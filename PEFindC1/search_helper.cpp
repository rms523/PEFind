// PEFind search helpers — Windows-dependent production implementation.
// Core algorithms (HexPattern, parse_hex_pattern, BMH search, wildcard matching)
// are defined in algo.h and reused here to avoid duplication.

#include <vector>
#include <iostream>
#include <iomanip>
#include <algorithm>
#include "file_info.h"
#include "search_helper.h"
#include "pe_hdrs_helper.h"
#include "algo.h"
#include "Shlwapi.h"

#pragma comment(lib, "Shlwapi.lib")

// RAII wrapper for HANDLE to prevent leaks on early returns
struct HandleGuard {
    HANDLE h;
    explicit HandleGuard(HANDLE handle) : h(handle) {}
    ~HandleGuard() { if (h != INVALID_HANDLE_VALUE && h != nullptr) CloseHandle(h); }
    HandleGuard(const HandleGuard&) = delete;
    HandleGuard& operator=(const HandleGuard&) = delete;
};

// Case-insensitive byte comparison helper for ASCII mode
static bool bytesEqualCI(BYTE a, BYTE b) { return tolower(a) == tolower(b); }

static void print_row_stream(const file_info& fi)
{
    std::ios_base::fmtflags f(std::cout.flags());
    size_t maxlen = 90;
    std::cout << std::setw(maxlen + 5) << std::left << fi.filepath;
    std::cout << std::setw(12) << std::uppercase << std::hex << fi.fileoffset;
    std::cout << std::setw(12) << fi.sectionindex;
    std::cout << std::setw(12) << fi.sectionoffset;
    std::cout << std::setw(18) << fi.sectionName;
    std::cout << std::setw(38) << fi.isPE;
    std::cout << std::endl;
    std::cout.flags(f);
}

static void status_update(const std::string& text)
{
    static size_t last_len = 0;
    std::string msg = std::string("Processing: ") + text;
    const size_t max_show = 160;
    if (msg.size() > max_show) { msg = msg.substr(0, max_show - 3) + "..."; }
    size_t pad = (last_len > msg.size()) ? (last_len - msg.size()) : 0;
    std::cout << '\r' << msg << std::string(pad, ' ') << std::flush;
    last_len = msg.size();
}

// Determine whether the PE buffer is 32-bit or 64-bit.
static bool peIs64bit(const BYTE* buf)
{
    const IMAGE_DOS_HEADER* idh = reinterpret_cast<const IMAGE_DOS_HEADER*>(buf);
    if (idh->e_magic != IMAGE_DOS_SIGNATURE) return false;

    LONG peOffset = idh->e_lfanew;
    if (peOffset < 0 || static_cast<DWORD>(peOffset + sizeof(DWORD)) > static_cast<DWORD>(sizeof(IMAGE_NT_HEADERS64))) {
        return false;
    }

    const DWORD* sig = reinterpret_cast<const DWORD*>(buf + peOffset);
    if (*sig != IMAGE_NT_SIGNATURE) return false;

    // Check machine type to determine 32 vs 64 bit
    const BYTE* ntPtr = buf + peOffset;
    const auto* fileHdr = reinterpret_cast<const IMAGE_FILE_HEADER*>(ntPtr + sizeof(DWORD));
    return fileHdr->Machine == IMAGE_FILE_MACHINE_AMD64;
}

static DWORD read_pe_header(HANDLE hFile, std::vector<BYTE>& outBuf)
{
    LARGE_INTEGER fileSize{};
    if (!GetFileSizeEx(hFile, &fileSize)) return 0;

    const DWORD MIN_HEADER = 1024;
    const DWORD MAX_PE_HEADER = 64 * 1024;
    DWORD readSize = static_cast<DWORD>(std::min<ULONGLONG>(fileSize.QuadPart, MIN_HEADER));
    if (readSize == 0) return 0;

    outBuf.resize(readSize);
    DWORD headerBytes = 0;
    LARGE_INTEGER zero{}; zero.QuadPart = 0;
    SetFilePointerEx(hFile, zero, NULL, FILE_BEGIN);
    if (!ReadFile(hFile, outBuf.data(), readSize, &headerBytes, NULL)) return 0;
    if (headerBytes < sizeof(IMAGE_DOS_HEADER)) return headerBytes;

    const IMAGE_DOS_HEADER* idh = reinterpret_cast<const IMAGE_DOS_HEADER*>(outBuf.data());
    if (idh->e_magic != IMAGE_DOS_SIGNATURE) return headerBytes;

    LONG peOffset = idh->e_lfanew;
    if (peOffset < 0) return headerBytes;

    // Ensure the NT signature and file header are available before reading fields from them.
    ULONGLONG ntHeaderMinimum = static_cast<ULONGLONG>(peOffset) + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER);
    if (ntHeaderMinimum > headerBytes) {
        readSize = static_cast<DWORD>(std::min<ULONGLONG>(
            fileSize.QuadPart,
            std::max<ULONGLONG>(ntHeaderMinimum, MIN_HEADER)));
        if (readSize > MAX_PE_HEADER) return headerBytes;

        outBuf.resize(readSize);
        SetFilePointerEx(hFile, zero, NULL, FILE_BEGIN);
        if (!ReadFile(hFile, outBuf.data(), readSize, &headerBytes, NULL)) return 0;
        if (ntHeaderMinimum > headerBytes) return headerBytes;
        idh = reinterpret_cast<const IMAGE_DOS_HEADER*>(outBuf.data());
        if (idh->e_magic != IMAGE_DOS_SIGNATURE) return headerBytes;
        peOffset = idh->e_lfanew;
        if (peOffset < 0) return headerBytes;
    }

    const BYTE* ntSigPtr = outBuf.data() + peOffset;
    if (reinterpret_cast<const DWORD*>(ntSigPtr)[0] != IMAGE_NT_SIGNATURE) return headerBytes;

    // Determine 32-bit vs 64-bit properly before accessing optional header
    bool is64b = false;
    const auto* fileHdr = reinterpret_cast<const IMAGE_FILE_HEADER*>(ntSigPtr + sizeof(DWORD));
    if (fileHdr->Machine == IMAGE_FILE_MACHINE_I386) {
        // 32-bit — nothing special needed
    } else if (fileHdr->Machine == IMAGE_FILE_MACHINE_AMD64) {
        is64b = true;
    }

    ULONGLONG ntHeaderSize = sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + fileHdr->SizeOfOptionalHeader;
    ULONGLONG sectionTableEnd = static_cast<ULONGLONG>(peOffset) + ntHeaderSize +
                                static_cast<ULONGLONG>(fileHdr->NumberOfSections) * IMAGE_SIZEOF_SECTION_HEADER;
    if (sectionTableEnd > headerBytes) {
        ULONGLONG neededSize = std::min<ULONGLONG>(fileSize.QuadPart, sectionTableEnd);
        if (neededSize > MAX_PE_HEADER) return headerBytes;
        outBuf.resize(static_cast<DWORD>(neededSize));
        SetFilePointerEx(hFile, zero, NULL, FILE_BEGIN);
        if (!ReadFile(hFile, outBuf.data(), static_cast<DWORD>(neededSize), &headerBytes, NULL)) return 0;
        if (sectionTableEnd > headerBytes) return headerBytes;
        ntSigPtr = outBuf.data() + peOffset;
        fileHdr = reinterpret_cast<const IMAGE_FILE_HEADER*>(ntSigPtr + sizeof(DWORD));
    }

    DWORD sizeOfHeaders = 0;
    if (is64b) {
        const auto* nthdr = reinterpret_cast<const IMAGE_NT_HEADERS64*>(ntSigPtr);
        sizeOfHeaders = nthdr->OptionalHeader.SizeOfHeaders;
    } else {
        const auto* nthdr = reinterpret_cast<const IMAGE_NT_HEADERS32*>(ntSigPtr);
        sizeOfHeaders = nthdr->OptionalHeader.SizeOfHeaders;
    }

    if (sizeOfHeaders > 0 && static_cast<DWORD>(sizeOfHeaders) > headerBytes) {
        DWORD needed = static_cast<DWORD>(std::min<ULONGLONG>(fileSize.QuadPart, 
                        std::max<ULONGLONG>(static_cast<ULONGLONG>(sizeOfHeaders), MIN_HEADER)));
        if (needed > MAX_PE_HEADER) return headerBytes;
        outBuf.resize(needed);
        SetFilePointerEx(hFile, zero, NULL, FILE_BEGIN);
        if (!ReadFile(hFile, outBuf.data(), needed, &headerBytes, NULL)) return 0;
    }

    // Ensure we have enough data for section headers.
    const BYTE* sig = outBuf.data() + peOffset;
    const auto* fh = reinterpret_cast<const IMAGE_FILE_HEADER*>(sig + sizeof(DWORD));
    ULONGLONG secNeeded = static_cast<ULONGLONG>(peOffset) + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) +
                          fh->SizeOfOptionalHeader +
                          static_cast<ULONGLONG>(fh->NumberOfSections) * IMAGE_SIZEOF_SECTION_HEADER;
    if (secNeeded > headerBytes && secNeeded <= static_cast<ULONGLONG>(fileSize.QuadPart)) {
        if (secNeeded > MAX_PE_HEADER) return headerBytes;
        outBuf.resize(static_cast<DWORD>(secNeeded));
        SetFilePointerEx(hFile, zero, NULL, FILE_BEGIN);
        if (!ReadFile(hFile, outBuf.data(), static_cast<DWORD>(secNeeded), &headerBytes, NULL)) return 0;
    }

    return headerBytes;
}

static void add_match(const string& pathTosearch, DWORD64 globalOffset, int sectionIndex,
                      PIMAGE_SECTION_HEADER sectionHeader, const string& searchStr,
                      BOOL isPE, vector<file_info>& all_file_info, BOOL stream)
{
    file_info fi;
    fi.filepath = pathTosearch;
    fi.fileoffset = globalOffset;
    fi.sectionindex = sectionIndex;

    if (sectionHeader != NULL) {
        fi.sectionoffset = globalOffset - sectionHeader->PointerToRawData;
        fi.sectionName = string(reinterpret_cast<char*>(sectionHeader->Name), 8);
        fi.isPE = "PE";
    } else {
        fi.sectionoffset = 0;
        fi.sectionName = "";
        if (isPE) fi.isPE = "Invalid PE or string not in sections(overlay?)";
        else fi.isPE = "Not a PE file.";
    }

    fi.stringTosearch = searchStr;
    all_file_info.push_back(fi);

    if (stream) { print_row_stream(fi); }
}

// Search a single chunk for the pattern.
// If hexPat is provided, use hex/wildcard matching instead of text-based search.
static void search_chunk(const BYTE* chunk, size_t chunkLen,
                          const BYTE* needle, int needleLen, BOOL isUnicode, BOOL caseInsensitive,
                          ULONGLONG baseOffset, vector<DWORD64>& allOffsets,
                          const HexPattern* hexPat = nullptr)
{
    if (hexPat != nullptr && !hexPat->bytes.empty()) {
        // Hex/wildcard pattern mode — delegate to algo.h implementations
        bool hasWildcards = false;
        for (bool isW : hexPat->isWildcard) { if (isW) { hasWildcards = true; break; } }

        if (!hasWildcards) {
            auto positions = find_all_bmh(
                chunk, chunkLen, hexPat->bytes.data(), static_cast<size_t>(hexPat->bytes.size()),
                [](uint8_t a, uint8_t b) { return a == b; });
            for (int pos : positions) allOffsets.push_back(baseOffset + static_cast<DWORD64>(pos));
        } else {
            auto positions = find_all_with_wildcards(chunk, chunkLen, *hexPat);
            for (int pos : positions) allOffsets.push_back(baseOffset + static_cast<DWORD64>(pos));
        }
    } else if (isUnicode && caseInsensitive) {
        // Unicode + case-insensitive: lowercase both pattern and chunk using CharLowerBuffW.
        size_t wLen = static_cast<size_t>(needleLen / sizeof(WCHAR));
        if (wLen == 0) return;

        std::vector<WCHAR> patLower(wLen);
        memcpy(patLower.data(), needle, needleLen);
        CharLowerBuffW(patLower.data(), static_cast<UINT>(wLen));

        // FIX: Allocate chunkLower in WCHARs and copy only the correct number of bytes.
        size_t chunkByteLen = chunkLen;  // total bytes to process from chunk
        size_t chunkWLenActual = chunkByteLen / sizeof(WCHAR);  // actual wide-char count
        std::vector<WCHAR> chunkLower(chunkWLenActual);

        // Copy only the bytes that fit into our WCHAR buffer — no overflow.
        size_t copyBytes = (chunkByteLen < chunkWLenActual * sizeof(WCHAR)) 
                           ? chunkByteLen : chunkWLenActual * sizeof(WCHAR);
        memcpy(chunkLower.data(), chunk, copyBytes);

        // Only lowercase the portion we actually copied.
        CharLowerBuffW(chunkLower.data(), static_cast<UINT>(chunkWLenActual));

        auto positions = find_all_bmh(
            reinterpret_cast<const uint8_t*>(chunkLower.data()), 
            chunkWLenActual * sizeof(WCHAR),
            reinterpret_cast<const uint8_t*>(patLower.data()), needleLen,
            [](uint8_t a, uint8_t b) { return a == b; });
        for (int pos : positions) allOffsets.push_back(baseOffset + static_cast<DWORD64>(pos));
    } else {
        // Standard BMH search with optional case-insensitive predicate
        ByteCompare cmp = caseInsensitive ? bytesEqualCI : 
                          [](BYTE a, BYTE b) { return a == b; };

        auto positions = find_all_bmh(
            chunk, chunkLen, needle, static_cast<size_t>(needleLen), cmp);
        for (int pos : positions) allOffsets.push_back(baseOffset + static_cast<DWORD64>(pos));
    }
}

void searchStringinFile(const string pathTosearch, const string stringTosearch, BOOL isUnicode, 
                        vector<file_info>& all_file_info, BOOL stream, BOOL caseInsensitive,
                        BOOL countMode, const HexPattern* hexPat)
{
    HANDLE hHandle = CreateFile(pathTosearch.c_str(), GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);

    if (hHandle == INVALID_HANDLE_VALUE) {
        std::cout << "Failed to Open file: " << pathTosearch.c_str() << std::endl;
        return;
    }

    HandleGuard guard(hHandle);

    LARGE_INTEGER size;
    if (!GetFileSizeEx(hHandle, &size)) {
        std::cout << "Unable to get file size" << std::endl;
        return;
    }

    std::vector<BYTE> header_buf;
    DWORD header_bytes = read_pe_header(hHandle, header_buf);

    if (header_bytes == 0) {
        std::cout << "File header read failed!" << std::endl;
        return;
    }

    int isPE = checkPE(header_buf.data()) ? 1 : 0;

    bool useHexPattern = (hexPat != nullptr && !hexPat->bytes.empty());

    const BYTE* pattern = nullptr;
    int pattern_len = 0;

    if (!useHexPattern) {
        string::size_type stringsize = stringTosearch.size();
        if (stringsize == 0) return;

        std::vector<BYTE> ascii_pat;
        std::vector<WCHAR> wpat;

        if (isUnicode) {
            wpat.resize(stringsize + 1);
            int k = MultiByteToWideChar(CP_UTF8, 0, stringTosearch.c_str(), -1, wpat.data(), static_cast<int>(wpat.size()));
            if (!k) { std::cout << "Unicode conversion failed" << std::endl; return; }
            wpat[static_cast<size_t>(k - 1)] = L'\0';
            pattern = reinterpret_cast<BYTE*>(wpat.data());
            pattern_len = (k - 1) * sizeof(WCHAR);
        } else {
            ascii_pat.assign(stringTosearch.begin(), stringTosearch.end());
            if (caseInsensitive) {
                std::transform(ascii_pat.begin(), ascii_pat.end(), ascii_pat.begin(),
                              [](BYTE b) { return static_cast<BYTE>(tolower(b)); });
            }
            pattern = ascii_pat.data();
            pattern_len = static_cast<int>(ascii_pat.size());
        }
    } else {
        pattern = hexPat->bytes.data();
        pattern_len = static_cast<int>(hexPat->bytes.size());
    }

    const DWORD CHUNK_SIZE = 8 * 1024 * 1024; // 8 MiB
    const DWORD OVERLAP = (pattern_len > 0) ? static_cast<DWORD>(pattern_len - 1) : 0;
    std::vector<BYTE> buf(CHUNK_SIZE + OVERLAP);
    DWORD overlap_len = 0;
    ULONGLONG base_offset = 0;

    LARGE_INTEGER zero{}; zero.QuadPart = 0;
    SetFilePointerEx(hHandle, zero, NULL, FILE_BEGIN);

    vector<DWORD64> allOffsets;

    for (;;) {
        DWORD bytesRead = 0;
        if (!ReadFile(hHandle, buf.data() + overlap_len, CHUNK_SIZE, &bytesRead, NULL)) {
            std::cout << "File reading failed!" << std::endl;
            return;
        }
        if (bytesRead == 0) break;

        DWORD search_size = overlap_len + bytesRead;
        size_t offsetsBeforeSearch = allOffsets.size();

        search_chunk(buf.data(), static_cast<size_t>(search_size),
                      pattern, pattern_len, isUnicode, caseInsensitive,
                      base_offset, allOffsets, hexPat);

        if (allOffsets.size() > offsetsBeforeSearch) {
            DWORD64 lastGlobal = allOffsets.back();
            int lastChunkPos = static_cast<int>(lastGlobal - base_offset);
            DWORD consumed = static_cast<DWORD>(lastChunkPos + pattern_len);

            if (consumed >= search_size) {
                DWORD new_overlap = std::min<DWORD>(OVERLAP, search_size);
                if (new_overlap > 0) memmove(buf.data(), buf.data() + (search_size - new_overlap), new_overlap);
                overlap_len = new_overlap;
            } else {
                DWORD remaining = search_size - consumed;
                if (remaining > 0 && remaining <= OVERLAP) {
                    memmove(buf.data(), buf.data() + consumed, remaining);
                    overlap_len = remaining;
                } else { overlap_len = 0; }
            }
        } else {
            DWORD new_overlap = std::min<DWORD>(OVERLAP, search_size);
            if (new_overlap > 0) memmove(buf.data(), buf.data() + (search_size - new_overlap), new_overlap);
            overlap_len = new_overlap;
        }
        base_offset += (search_size - overlap_len);
    }

    // Emit results based on mode
    if (countMode && !allOffsets.empty()) {
        // Count mode: one entry per file with total match count
        DWORD64 firstOffset = allOffsets[0];
        int sectionIndex = 0;
        // FIX: Pass DWORD64 directly — no truncation to int.
        PIMAGE_SECTION_HEADER sectionHeader = get_section_hdr(header_buf.data(), header_bytes, 
                                                             firstOffset, sectionIndex);

        file_info fi;
        fi.filepath = pathTosearch;
        char countStr[32];
#ifdef _MSC_VER
        sprintf_s(countStr, "%d", static_cast<int>(allOffsets.size()));
#else
        snprintf(countStr, sizeof(countStr), "%d", static_cast<int>(allOffsets.size()));
#endif
        fi.stringTosearch = countStr;  // store match count for display

        if (sectionHeader != NULL) {
            fi.sectionindex = sectionIndex;
            fi.sectionoffset = firstOffset - sectionHeader->PointerToRawData;
            fi.sectionName = string(reinterpret_cast<char*>(sectionHeader->Name), 8);
            fi.isPE = "PE";
        } else {
            fi.sectionindex = 0;
            fi.sectionoffset = 0;
            fi.sectionName = "";
            if (isPE) fi.isPE = "Overlay";
            else fi.isPE = "Not PE";
        }

        all_file_info.push_back(fi);
    } else {
        // Normal mode: one entry per match (existing behavior)
        for (DWORD64 globalOffset : allOffsets) {
            int sectionIndex = 0;
            // FIX: Pass DWORD64 directly — no truncation to int.
            PIMAGE_SECTION_HEADER sectionHeader = get_section_hdr(header_buf.data(), header_bytes, 
                                                                 globalOffset, sectionIndex);

            add_match(pathTosearch, globalOffset, sectionIndex, sectionHeader,
                      stringTosearch, isPE, all_file_info, stream);
        }
    }
}

void searchStringInDir(const std::string& directory, const string stringTosearch, BOOL isUnicode, 
                        vector<file_info>& all_file_info, BOOL stream, BOOL caseInsensitive,
                        BOOL countMode, const HexPattern* hexPat)
{
    WIN32_FIND_DATA findData;
    HANDLE hFind = INVALID_HANDLE_VALUE;
    std::string full_path = directory + "\\*";

    hFind = FindFirstFileA(full_path.c_str(), &findData);

    if (hFind == INVALID_HANDLE_VALUE) {
        throw std::runtime_error("Invalid handle value! Please check your path...");
    }

    HandleGuard findGuard(hFind);

    while (FindNextFileA(hFind, &findData) != 0) {
        if (strcmp(findData.cFileName, ".") == 0 || strcmp(findData.cFileName, "..") == 0) continue;

        char combined_path[MAX_PATH];
        strcpy_s(combined_path, directory.c_str());
        PathAppend(combined_path, findData.cFileName);

        if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            searchStringInDir(combined_path, stringTosearch, isUnicode, all_file_info, stream, 
                              caseInsensitive, countMode, hexPat);
        } else {
            if (!stream) status_update(combined_path);
            searchStringinFile(combined_path, stringTosearch, isUnicode, all_file_info, stream, 
                               caseInsensitive, countMode, hexPat);
        }
    }
}
