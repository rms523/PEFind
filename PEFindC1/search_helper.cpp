#include <vector>
#include <iostream>
#include <iomanip>
#include <algorithm>
#include "file_info.h"
#include "search_helper.h"
#include "pe_hdrs_helper.h"
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

// Boyer-Moore-Horspool search — O(n/m) average case.
// Supports optional case-insensitive matching via the compare predicate.
using ByteCompare = bool(*)(BYTE, BYTE);

static int searchBytesBoyerMooreHorspool(const BYTE* haystack, size_t haystackLen,
                                          const BYTE* needle, size_t needleLen,
                                          ByteCompare cmp)
{
    if (needleLen == 0 || needleLen > haystackLen) return -1;

    // Build bad-character skip table using the last byte of the needle
    constexpr size_t ALPHABET_SIZE = 256;
    int skip[ALPHABET_SIZE];
    for (size_t c = 0; c < ALPHABET_SIZE; ++c) skip[c] = static_cast<int>(needleLen);
    for (size_t i = 0; i < needleLen - 1; ++i) {
        skip[static_cast<unsigned char>(needle[i])] = static_cast<int>(needleLen - 1 - i);
    }

    size_t i = 0;
    while (i <= haystackLen - needleLen) {
        size_t j = needleLen;
        // Compare from right to left using the provided predicate
        while (j > 0 && cmp(haystack[i + j - 1], needle[j - 1])) {
            --j;
        }
        if (j == 0) return static_cast<int>(i); // match found
        i += skip[static_cast<unsigned char>(haystack[i + needleLen - 1])];
    }
    return -1;
}

// Find ALL occurrences of needle in haystack using Boyer-Moore-Horspool.
// Returns a vector of byte offsets (within the haystack) for each match.
static std::vector<int> findAllBytesBoyerMooreHorspool(const BYTE* haystack, size_t haystackLen,
                                                         const BYTE* needle, size_t needleLen,
                                                         ByteCompare cmp)
{
    std::vector<int> positions;

    if (needleLen == 0 || needleLen > haystackLen) return positions;

    // Build bad-character skip table using the last byte of the needle
    constexpr size_t ALPHABET_SIZE = 256;
    int skip[ALPHABET_SIZE];
    for (size_t c = 0; c < ALPHABET_SIZE; ++c) skip[c] = static_cast<int>(needleLen);
    for (size_t i = 0; i < needleLen - 1; ++i) {
        skip[static_cast<unsigned char>(needle[i])] = static_cast<int>(needleLen - 1 - i);
    }

    size_t i = 0;
    while (i <= haystackLen - needleLen) {
        size_t j = needleLen;
        while (j > 0 && cmp(haystack[i + j - 1], needle[j - 1])) {
            --j;
        }
        if (j == 0) {
            positions.push_back(static_cast<int>(i));
            i += needleLen; // non-overlapping: skip past this match
        } else {
            i += skip[static_cast<unsigned char>(haystack[i + needleLen - 1])];
        }
    }
    return positions;
}

// Legacy naive search kept for API compatibility. New code should use BMH above.
int searchHexBytes(const BYTE* bufTosearch, const BYTE * stringTosearch, int stringsize, DWORD bufSize)
{
    size_t i = 0, j = 0;

    for (i = 0; i < static_cast<size_t>(bufSize); ++i) {
        if (j == static_cast<size_t>(stringsize)) break;
        if (j == 0 && static_cast<DWORD>(stringsize) > (bufSize - static_cast<int>(i))) break;

        if (bufTosearch[i] == static_cast<BYTE>(stringTosearch[j])) {
            ++j;
            continue;
        } else {
            j = 0;
            if (static_cast<DWORD>(stringsize) > 0 && bufTosearch[i] == static_cast<BYTE>(stringTosearch[0])) {
                ++j;
            }
        }
    }

    if (j == static_cast<size_t>(stringsize)) {
        return static_cast<int>(i - j);
    }
    return -1;
}


static void print_row_stream(const file_info& fi)
{
    std::ios_base::fmtflags f(std::cout.flags());
    size_t maxlen = 90; // fixed width for streaming mode

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
    // Trim overly long messages to avoid wrapping
    const size_t max_show = 160;
    if (msg.size() > max_show) {
        msg = msg.substr(0, max_show - 3) + "...";
    }
    // Pad with spaces to fully clear previous content
    size_t pad = (last_len > msg.size()) ? (last_len - msg.size()) : 0;
    std::cout << '\r' << msg << std::string(pad, ' ') << std::flush;
    last_len = msg.size();
}

// Helper: read enough of the file header to map sections.
// Returns the number of bytes actually available in *outBuf.
static DWORD read_pe_header(HANDLE hFile, std::vector<BYTE>& outBuf)
{
    LARGE_INTEGER fileSize{};
    if (!GetFileSizeEx(hFile, &fileSize)) return 0;

    // First pass: read just the DOS header to get e_lfanew and check PE signature
    const DWORD MIN_HEADER = 1024; // at least one page for initial analysis
    DWORD readSize = static_cast<DWORD>(std::min<ULONGLONG>(fileSize.QuadPart, MIN_HEADER));

    outBuf.resize(readSize);
    DWORD headerBytes = 0;
    LARGE_INTEGER zero{}; zero.QuadPart = 0;
    SetFilePointerEx(hFile, zero, NULL, FILE_BEGIN);
    if (!ReadFile(hFile, outBuf.data(), readSize, &headerBytes, NULL)) return 0;

    // Check for MZ signature
    IMAGE_DOS_HEADER* idh = reinterpret_cast<IMAGE_DOS_HEADER*>(outBuf.data());
    if (idh->e_magic != IMAGE_DOS_SIGNATURE) {
        // Not a PE — we still have the bytes, caller will handle it
        return headerBytes;
    }

    LONG peOffset = idh->e_lfanew;
    if (peOffset < 0 || static_cast<DWORD>(peOffset + sizeof(DWORD)) > headerBytes) {
        // NT headers not in what we read — expand buffer
        const DWORD MAX_PE_HEADER = 64 * 1024; // generous upper bound for NT+sections
        readSize = static_cast<DWORD>(std::min<ULONGLONG>(fileSize.QuadPart, 
                          std::max<ULONGLONG>(static_cast<ULONGLONG>(peOffset + MAX_PE_HEADER), MIN_HEADER)));
        outBuf.resize(readSize);
        SetFilePointerEx(hFile, zero, NULL, FILE_BEGIN);
        if (!ReadFile(hFile, outBuf.data(), readSize, &headerBytes, NULL)) return 0;

        // Re-check PE signature after re-read
        idh = reinterpret_cast<IMAGE_DOS_HEADER*>(outBuf.data());
        if (idh->e_magic != IMAGE_DOS_SIGNATURE) return headerBytes;
        peOffset = idh->e_lfanew;
    }

    // Check NT signature
    BYTE* ntSig = outBuf.data() + peOffset;
    if (reinterpret_cast<DWORD*>(ntSig)[0] != IMAGE_NT_SIGNATURE) {
        return headerBytes;
    }

    // Determine SizeOfHeaders from optional header to ensure we have enough for section mapping
    bool is64bit = false;
    BYTE* ntHdr = outBuf.data() + peOffset;
    DWORD optOff = 0;
    if (reinterpret_cast<IMAGE_NT_HEADERS32*>(ntHdr)->FileHeader.Machine == IMAGE_FILE_MACHINE_I386) {
        is64bit = false;
        optOff = sizeof(IMAGE_NT_HEADERS32) - 24; // 24 = size diff between 32/64 optional headers at start
    } else if (reinterpret_cast<IMAGE_NT_HEADERS64*>(ntHdr)->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64) {
        is64bit = true;
        optOff = sizeof(IMAGE_NT_HEADERS64) - 24;
    }

    DWORD sizeOfHeaders = 0;
    if (is64bit) {
        auto* nthdr = reinterpret_cast<IMAGE_NT_HEADERS64*>(ntHdr);
        sizeOfHeaders = nthdr->OptionalHeader.SizeOfHeaders;
    } else {
        auto* nthdr = reinterpret_cast<IMAGE_NT_HEADERS32*>(ntHdr);
        sizeOfHeaders = nthdr->OptionalHeader.SizeOfHeaders;
    }

    // If SizeOfHeaders > what we have, re-read to cover it
    if (sizeOfHeaders > 0 && static_cast<DWORD>(sizeOfHeaders) > headerBytes) {
        DWORD needed = static_cast<DWORD>(std::min<ULONGLONG>(fileSize.QuadPart, 
                        std::max<ULONGLONG>(static_cast<ULONGLONG>(sizeOfHeaders), MIN_HEADER)));
        outBuf.resize(needed);
        SetFilePointerEx(hFile, zero, NULL, FILE_BEGIN);
        if (!ReadFile(hFile, outBuf.data(), needed, &headerBytes, NULL)) return 0;
    }

    // Also ensure we have enough for section headers
    BYTE* sig = outBuf.data() + peOffset;
    auto* fileHdr = is64bit 
        ? &(reinterpret_cast<IMAGE_NT_HEADERS64*>(sig)->FileHeader)
        : &(reinterpret_cast<IMAGE_NT_HEADERS32*>(sig)->FileHeader);

    DWORD secNeeded = static_cast<DWORD>(peOffset + sizeof(IMAGE_NT_HEADERS64) + 
                          fileHdr->NumberOfSections * IMAGE_SIZEOF_SECTION_HEADER);
    if (secNeeded > headerBytes && secNeeded <= static_cast<DWORD>(fileSize.QuadPart)) {
        outBuf.resize(secNeeded);
        SetFilePointerEx(hFile, zero, NULL, FILE_BEGIN);
        if (!ReadFile(hFile, outBuf.data(), secNeeded, &headerBytes, NULL)) return 0;
    }

    return headerBytes;
}

// Helper: create a file_info entry for a single match at the given global offset.
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

    if (stream) {
        print_row_stream(fi);
    }
}

// Search a single chunk for the pattern, handling case-insensitivity.
// For ASCII: uses tolower() comparison directly in BMH.
// For Unicode + CI: lowercases both pattern and haystack bytes using CharLowerBuffW before searching.
static void search_chunk(const BYTE* chunk, size_t chunkLen,
                          const BYTE* needle, int needleLen, BOOL isUnicode, BOOL caseInsensitive,
                          ULONGLONG baseOffset, vector<DWORD64>& allOffsets)
{
    if (isUnicode && caseInsensitive) {
        // For Unicode + case-insensitive: lowercase both pattern and chunk using CharLowerBuffW.
        size_t wLen = static_cast<size_t>(needleLen / sizeof(WCHAR));
        if (wLen == 0) return;

        std::vector<WCHAR> patLower(wLen);
        memcpy(patLower.data(), needle, needleLen);
        CharLowerBuffW(patLower.data(), static_cast<UINT>(wLen));

        // Lowercase the chunk too
        size_t chunkWLen = chunkLen / sizeof(WCHAR);
        std::vector<WCHAR> chunkLower(chunkWLen);
        memcpy(chunkLower.data(), chunk, 
               (chunkLen < chunkWLen * sizeof(WCHAR)) ? chunkLen : chunkWLen * sizeof(WCHAR));
        CharLowerBuffW(chunkLower.data(), static_cast<UINT>(chunkWLen));

        // Now search the lowercased versions with case-sensitive comparison
        auto positions = findAllBytesBoyerMooreHorspool(
            reinterpret_cast<const BYTE*>(chunkLower.data()), chunkLen,
            reinterpret_cast<const BYTE*>(patLower.data()), needleLen,
            [](BYTE a, BYTE b) { return a == b; });

        for (int pos : positions) {
            allOffsets.push_back(baseOffset + static_cast<DWORD64>(pos));
        }
    } else {
        // Standard BMH search with optional case-insensitive predicate
        ByteCompare cmp = caseInsensitive ? bytesEqualCI : 
                          [](BYTE a, BYTE b) { return a == b; };

        auto positions = findAllBytesBoyerMooreHorspool(
            chunk, chunkLen, needle, static_cast<size_t>(needleLen), cmp);

        for (int pos : positions) {
            allOffsets.push_back(baseOffset + static_cast<DWORD64>(pos));
        }
    }
}

void searchStringinFile(const string pathTosearch, const string stringTosearch, BOOL isUnicode, vector<file_info>& all_file_info, BOOL stream, BOOL caseInsensitive)
{
    HANDLE hHandle = CreateFile(pathTosearch.c_str(), GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);

    if (hHandle == INVALID_HANDLE_VALUE) {
        std::cout << "Failed to Open file: " << pathTosearch.c_str() << std::endl;
        return;
    }

    HandleGuard guard(hHandle); // RAII — ensures CloseHandle on any exit path

    LARGE_INTEGER size;
    if (!GetFileSizeEx(hHandle, &size)) {
        std::cout << "Unable to get file size" << std::endl;
        return;
    }

    // Read PE header region for section mapping (dynamically sized)
    std::vector<BYTE> header_buf;
    DWORD header_bytes = read_pe_header(hHandle, header_buf);

    if (header_bytes == 0) {
        std::cout << "File header read failed!" << std::endl;
        return;
    }

    // Determine if it looks like a PE (MZ)
    int isPE = checkPE(header_buf.data()) ? 1 : 0;

    // Build pattern bytes
    string::size_type stringsize = stringTosearch.size();
    if (stringsize == 0) {
        return;
    }

    BYTE* pattern = nullptr;
    int pattern_len = 0;
    std::vector<BYTE> ascii_pat;
    std::vector<WCHAR> wpat;

    if (isUnicode) {
        wpat.resize(stringsize + 1);
        int k = MultiByteToWideChar(CP_UTF8, 0, stringTosearch.c_str(), -1, wpat.data(), static_cast<int>(wpat.size()));
        if (!k) {
            std::cout << "Unicode conversion failed" << std::endl;
            return;
        }
        wpat[static_cast<size_t>(k - 1)] = L'\0';
        pattern = reinterpret_cast<BYTE*>(wpat.data());
        pattern_len = (k - 1) * sizeof(WCHAR); // ignore last null for substring search
    } else {
        ascii_pat.assign(stringTosearch.begin(), stringTosearch.end());
        if (caseInsensitive) {
            // Lowercase the ASCII pattern once upfront
            std::transform(ascii_pat.begin(), ascii_pat.end(), ascii_pat.begin(),
                          [](BYTE b) { return static_cast<BYTE>(tolower(b)); });
        }
        pattern = ascii_pat.data();
        pattern_len = static_cast<int>(ascii_pat.size());
    }

    // Stream through file in chunks with overlap to catch boundary matches.
    const DWORD CHUNK_SIZE = 8 * 1024 * 1024; // 8 MiB
    const DWORD OVERLAP = (pattern_len > 0) ? static_cast<DWORD>(pattern_len - 1) : 0;
    std::vector<BYTE> buf(CHUNK_SIZE + OVERLAP);
    DWORD overlap_len = 0;
    ULONGLONG base_offset = 0;

    LARGE_INTEGER zero{}; zero.QuadPart = 0;
    SetFilePointerEx(hHandle, zero, NULL, FILE_BEGIN);

    // Collect all match offsets first (needed for section lookup per offset)
    vector<DWORD64> allOffsets;

    for (;;) {
        DWORD bytesRead = 0;
        if (!ReadFile(hHandle, buf.data() + overlap_len, CHUNK_SIZE, &bytesRead, NULL)) {
            std::cout << "File reading failed!" << std::endl;
            return;
        }
        if (bytesRead == 0) break; // EOF

        DWORD search_size = overlap_len + bytesRead;
        size_t offsetsBeforeSearch = allOffsets.size();

        // Search this chunk for all pattern occurrences
        search_chunk(buf.data(), static_cast<size_t>(search_size),
                      pattern, pattern_len, isUnicode, caseInsensitive,
                      base_offset, allOffsets);

        // Advance past the last match in this chunk (if any found)
        if (allOffsets.size() > offsetsBeforeSearch) {
            DWORD64 lastGlobal = allOffsets.back();
            int lastChunkPos = static_cast<int>(lastGlobal - base_offset);
            DWORD consumed = static_cast<DWORD>(lastChunkPos + pattern_len);

            if (consumed >= search_size) {
                // Match extends beyond chunk boundary — use standard overlap
                DWORD new_overlap = std::min<DWORD>(OVERLAP, search_size);
                if (new_overlap > 0) {
                    memmove(buf.data(), buf.data() + (search_size - new_overlap), new_overlap);
                }
                overlap_len = new_overlap;
            } else {
                DWORD remaining = search_size - consumed;
                if (remaining > 0 && remaining <= OVERLAP) {
                    memmove(buf.data(), buf.data() + consumed, remaining);
                    overlap_len = remaining;
                } else {
                    overlap_len = 0;
                }
            }
        } else {
            // No matches — standard overlap logic
            DWORD new_overlap = std::min<DWORD>(OVERLAP, search_size);
            if (new_overlap > 0) {
                memmove(buf.data(), buf.data() + (search_size - new_overlap), new_overlap);
            }
            overlap_len = new_overlap;
        }
        base_offset += (search_size - overlap_len);
    }

    // Now emit results — one entry per match, with section info looked up per offset
    for (DWORD64 globalOffset : allOffsets) {
        int sectionIndex = 0;
        PIMAGE_SECTION_HEADER sectionHeader = get_section_hdr(header_buf.data(), header_bytes, 
                                                             static_cast<int>(globalOffset), sectionIndex);

        add_match(pathTosearch, globalOffset, sectionIndex, sectionHeader,
                  stringTosearch, isPE, all_file_info, stream);
    }
}

// FIX: searchStringInDir now accepts and forwards caseInsensitive flag for recursive calls.
void searchStringInDir(const std::string& directory, const string stringTosearch, BOOL isUnicode, 
                        vector<file_info>& all_file_info, BOOL stream, BOOL caseInsensitive)
{
    WIN32_FIND_DATA findData;
    HANDLE hFind = INVALID_HANDLE_VALUE;
    std::string full_path = directory + "\\*";

    hFind = FindFirstFileA(full_path.c_str(), &findData);

    if (hFind == INVALID_HANDLE_VALUE) {
        throw std::runtime_error("Invalid handle value! Please check your path...");
    }

    // RAII guard for find handle — ensures cleanup even on exceptions
    HandleGuard findGuard(hFind);

    while (FindNextFileA(hFind, &findData) != 0) {
        // Skip . and ..
        if (strcmp(findData.cFileName, ".") == 0 || strcmp(findData.cFileName, "..") == 0) continue;

        char combined_path[MAX_PATH];
        strcpy_s(combined_path, directory.c_str());
        PathAppend(combined_path, findData.cFileName);

        if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            // Recurse into subdirectories, forwarding caseInsensitive flag
            searchStringInDir(combined_path, stringTosearch, isUnicode, all_file_info, stream, caseInsensitive);
        } else {
            if (!stream) status_update(combined_path);
            searchStringinFile(combined_path, stringTosearch, isUnicode, all_file_info, stream, caseInsensitive);
        }
    }

    // findGuard automatically closes hFind when it goes out of scope
}


void searchString(const string pathTosearch, const string stringTosearch, BOOL isUnicode, vector<file_info>& all_file_info, BOOL isDir, BOOL stream)
{
    if (isDir) {
        try {
            searchStringInDir(pathTosearch, stringTosearch, isUnicode, all_file_info, stream);
        } catch (std::exception const& e) {
            std::cout << "Exception: " << e.what() << std::endl;
        }
        return;
    }

    if (!stream) status_update(pathTosearch);
    searchStringinFile(pathTosearch, stringTosearch, isUnicode, all_file_info, stream);
}
