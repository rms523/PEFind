#include "search_helper.h"

#include <algorithm>
#include <cctype>
#include <cstring>
#include <iostream>
#include <limits>

#include "algo.h"
#include "elf_header_reader.h"
#include "elf_hdrs_helper.h"
#include "pe_header_reader.h"
#include "pe_hdrs_helper.h"
#include "platform.h"

enum class BinaryFormat { Unknown, PE, ELF };

struct SectionMatch {
    bool found = false;
    int index = 0;
    uint64_t section_offset = 0;
    std::string name;
};

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

static const char* format_label(BinaryFormat format)
{
    switch (format) {
    case BinaryFormat::PE: return "PE";
    case BinaryFormat::ELF: return "ELF";
    default: return "Unknown";
    }
}

static const char* outside_section_label(BinaryFormat format)
{
    switch (format) {
    case BinaryFormat::PE:
        return "Invalid PE or string not in sections(overlay?)";
    case BinaryFormat::ELF:
        return "Invalid ELF or string not in sections(overlay?)";
    default:
        return "Not a PE or ELF file.";
    }
}

static SectionMatch lookup_section(BinaryFormat format, const BYTE* header_buf, size_t header_bytes,
                                   uint64_t file_offset)
{
    SectionMatch match;
    if (format == BinaryFormat::PE) {
        int sectionIndex = 0;
        PIMAGE_SECTION_HEADER sectionHeader =
            get_section_hdr(header_buf, header_bytes, file_offset, sectionIndex);
        if (sectionHeader != nullptr) {
            match.found = true;
            match.index = sectionIndex;
            match.section_offset = file_offset - sectionHeader->PointerToRawData;
            match.name.assign(reinterpret_cast<const char*>(sectionHeader->Name), 8);
            // Trim trailing NULs from the 8-byte PE section name.
            while (!match.name.empty() && match.name.back() == '\0') {
                match.name.pop_back();
            }
        }
        return match;
    }

    if (format == BinaryFormat::ELF) {
        const ElfSectionHit hit =
            get_elf_section_by_file_offset(header_buf, header_bytes, file_offset);
        if (hit.found) {
            match.found = true;
            match.index = hit.index;
            match.section_offset = hit.section_offset;
            match.name = hit.name;
        }
    }
    return match;
}

static void add_match(const string& pathTosearch, uint64_t globalOffset, const SectionMatch& section,
                      const string& searchStr, BinaryFormat format,
                      vector<file_info>& all_file_info, const ResultCallback& onResult)
{
    file_info fi;
    fi.filepath = pathTosearch;
    fi.fileoffset = globalOffset;
    fi.stringTosearch = searchStr;

    if (section.found) {
        fi.sectionindex = section.index;
        fi.sectionoffset = section.section_offset;
        fi.sectionName = section.name;
        fi.isPE = format_label(format);
    } else {
        fi.sectionindex = 0;
        fi.sectionoffset = 0;
        fi.sectionName = "";
        fi.isPE = outside_section_label(format);
    }

    all_file_info.push_back(fi);
    if (onResult) {
        onResult(all_file_info.back());
    }
}

static bool bytesEqualCI(BYTE a, BYTE b)
{
    return std::tolower(static_cast<unsigned char>(a)) ==
           std::tolower(static_cast<unsigned char>(b));
}

static void search_chunk(const BYTE* chunk, size_t chunkLen,
                         const BYTE* needle, int needleLen, BOOL isUnicode, BOOL caseInsensitive,
                         uint64_t baseOffset, vector<uint64_t>& allOffsets,
                         const HexPattern* hexPat = nullptr)
{
    if (hexPat != nullptr && !hexPat->bytes.empty()) {
        bool hasWildcards = false;
        for (bool isW : hexPat->isWildcard) { if (isW) { hasWildcards = true; break; } }

        if (!hasWildcards) {
            auto positions = find_all_bmh(
                chunk, chunkLen, hexPat->bytes.data(), static_cast<size_t>(hexPat->bytes.size()),
                [](uint8_t a, uint8_t b) { return a == b; });
            for (int pos : positions) allOffsets.push_back(baseOffset + static_cast<uint64_t>(pos));
        } else {
            auto positions = find_all_with_wildcards(chunk, chunkLen, *hexPat);
            for (int pos : positions) allOffsets.push_back(baseOffset + static_cast<uint64_t>(pos));
        }
    } else if (isUnicode && caseInsensitive) {
        size_t wLen = static_cast<size_t>(needleLen / static_cast<int>(sizeof(char16_t)));
        if (wLen == 0) return;

        std::vector<char16_t> patLower(wLen);
        memcpy(patLower.data(), needle, static_cast<size_t>(needleLen));
        platform_lowercase_utf16(patLower.data(), wLen);

        for (size_t alignment = 0; alignment < sizeof(char16_t) && alignment < chunkLen; ++alignment) {
            size_t alignedBytes = chunkLen - alignment;
            size_t chunkWLenActual = alignedBytes / sizeof(char16_t);
            if (chunkWLenActual == 0) continue;

            std::vector<char16_t> chunkLower(chunkWLenActual);
            memcpy(chunkLower.data(), chunk + alignment, chunkWLenActual * sizeof(char16_t));
            platform_lowercase_utf16(chunkLower.data(), chunkWLenActual);

            auto positions = find_all_bmh(
                reinterpret_cast<const uint8_t*>(chunkLower.data()),
                chunkWLenActual * sizeof(char16_t),
                reinterpret_cast<const uint8_t*>(patLower.data()), needleLen,
                [](uint8_t a, uint8_t b) { return a == b; });
            for (int pos : positions) {
                allOffsets.push_back(baseOffset + alignment + static_cast<uint64_t>(pos));
            }
        }
    } else {
        ByteCompare cmp = caseInsensitive ? bytesEqualCI :
                          [](BYTE a, BYTE b) { return a == b; };

        auto positions = find_all_bmh(
            chunk, chunkLen, needle, static_cast<size_t>(needleLen), cmp);
        for (int pos : positions) allOffsets.push_back(baseOffset + static_cast<uint64_t>(pos));
    }
}

void searchStringinFile(const string pathTosearch, const string stringTosearch, BOOL isUnicode,
                        vector<file_info>& all_file_info, BOOL caseInsensitive,
                        BOOL countMode, const HexPattern* hexPat, const ResultCallback& onResult,
                        ScanStats* stats)
{
    PlatformFile* file = nullptr;
    if (!platform_file_open(pathTosearch, file)) {
        std::cout << "Failed to Open file: " << pathTosearch.c_str() << std::endl;
        if (stats) stats->recordFailure(pathTosearch);
        return;
    }

    const uint64_t file_size = platform_file_size(file);
    if (file_size == 0) {
        std::cout << "Unable to get file size" << std::endl;
        if (stats) stats->recordFailure(pathTosearch);
        platform_file_close(file);
        return;
    }

    std::vector<BYTE> header_buf;
    BinaryFormat format = BinaryFormat::Unknown;

    // Probe the first bytes to choose PE vs ELF header loading.
    {
        std::vector<BYTE> probe;
        const size_t probe_len =
            static_cast<size_t>((std::min)(platform_file_size(file), static_cast<uint64_t>(64)));
        if (probe_len == 0 || !platform_file_seek(file, 0)) {
            std::cout << "File header read failed!" << std::endl;
            if (stats) stats->recordFailure(pathTosearch);
            platform_file_close(file);
            return;
        }
        size_t probe_read = 0;
        probe.resize(probe_len);
        if (!platform_file_read(file, probe.data(), probe_len, probe_read) || probe_read == 0) {
            std::cout << "File header read failed!" << std::endl;
            if (stats) stats->recordFailure(pathTosearch);
            platform_file_close(file);
            return;
        }
        probe.resize(probe_read);

        if (checkPE(probe.data(), probe.size())) {
            format = BinaryFormat::PE;
            const uint32_t header_bytes = read_pe_header(file, header_buf);
            if (header_bytes == 0) {
                std::cout << "File header read failed!" << std::endl;
                if (stats) stats->recordFailure(pathTosearch);
                platform_file_close(file);
                return;
            }
        } else if (checkELF(probe.data(), probe.size())) {
            format = BinaryFormat::ELF;
            const uint32_t header_bytes = read_elf_header(file, header_buf);
            if (header_bytes == 0) {
                std::cout << "File header read failed!" << std::endl;
                if (stats) stats->recordFailure(pathTosearch);
                platform_file_close(file);
                return;
            }
        } else {
            // Non-PE/ELF: keep the probe so section lookup simply reports unknown.
            header_buf.swap(probe);
        }
    }

    const bool useHexPattern = (hexPat != nullptr && !hexPat->bytes.empty());

    const BYTE* pattern = nullptr;
    int pattern_len = 0;
    std::vector<BYTE> ascii_pat;
    std::vector<char16_t> utf16_pat;

    if (!useHexPattern) {
        const string::size_type stringsize = stringTosearch.size();
        if (stringsize == 0) {
            platform_file_close(file);
            return;
        }

        if (isUnicode) {
            const std::u16string widePattern = platform_utf8_to_utf16le(stringTosearch);
            if (widePattern.empty()) {
                std::cout << "Unicode conversion failed" << std::endl;
                if (stats) stats->recordFailure(pathTosearch);
                platform_file_close(file);
                return;
            }
            utf16_pat.assign(widePattern.begin(), widePattern.end());
            pattern = reinterpret_cast<const BYTE*>(utf16_pat.data());
            pattern_len = static_cast<int>(utf16_pat.size() * sizeof(char16_t));
        } else {
            ascii_pat.assign(stringTosearch.begin(), stringTosearch.end());
            if (caseInsensitive) {
                std::transform(ascii_pat.begin(), ascii_pat.end(), ascii_pat.begin(),
                               [](BYTE b) {
                                   return static_cast<BYTE>(std::tolower(static_cast<unsigned char>(b)));
                               });
            }
            pattern = ascii_pat.data();
            pattern_len = static_cast<int>(ascii_pat.size());
        }
    } else {
        pattern = hexPat->bytes.data();
        pattern_len = static_cast<int>(hexPat->bytes.size());
    }

    const size_t CHUNK_SIZE = 8 * 1024 * 1024;
    const size_t overlap = (pattern_len > 0) ? static_cast<size_t>(pattern_len - 1) : 0;
    std::vector<BYTE> buf(CHUNK_SIZE + overlap);
    size_t overlap_len = 0;
    uint64_t base_offset = 0;

    if (!platform_file_seek(file, 0)) {
        std::cout << "File reading failed!" << std::endl;
        if (stats) stats->recordFailure(pathTosearch);
        platform_file_close(file);
        return;
    }

    vector<uint64_t> allOffsets;

    for (;;) {
        size_t bytes_read = 0;
        if (!platform_file_read(file, buf.data() + overlap_len, CHUNK_SIZE, bytes_read)) {
            std::cout << "File reading failed!" << std::endl;
            if (stats) stats->recordFailure(pathTosearch);
            platform_file_close(file);
            return;
        }
        if (bytes_read == 0) break;

        const size_t search_size = overlap_len + bytes_read;

        search_chunk(buf.data(), search_size,
                     pattern, pattern_len, isUnicode, caseInsensitive,
                     base_offset, allOffsets, hexPat);

        const size_t new_overlap = (std::min)(overlap, search_size);
        if (new_overlap > 0) {
            memmove(buf.data(), buf.data() + (search_size - new_overlap), new_overlap);
        }
        overlap_len = new_overlap;
        base_offset += (search_size - overlap_len);
    }

    platform_file_close(file);

    std::sort(allOffsets.begin(), allOffsets.end());
    allOffsets.erase(std::unique(allOffsets.begin(), allOffsets.end()), allOffsets.end());
    if (stats) {
        stats->recordFile(pathTosearch, allOffsets.size());
    }

    if (countMode && !allOffsets.empty()) {
        const uint64_t firstOffset = allOffsets[0];
        const SectionMatch section =
            lookup_section(format, header_buf.data(), header_buf.size(), firstOffset);

        file_info fi;
        fi.filepath = pathTosearch;
        fi.fileoffset = firstOffset;
        fi.stringTosearch = std::to_string(allOffsets.size());

        if (section.found) {
            fi.sectionindex = section.index;
            fi.sectionoffset = section.section_offset;
            fi.sectionName = section.name;
            fi.isPE = format_label(format);
        } else {
            fi.sectionindex = 0;
            fi.sectionoffset = 0;
            fi.sectionName = "";
            fi.isPE = outside_section_label(format);
        }

        all_file_info.push_back(fi);
        if (onResult) {
            onResult(all_file_info.back());
        }
    } else {
        for (uint64_t globalOffset : allOffsets) {
            const SectionMatch section =
                lookup_section(format, header_buf.data(), header_buf.size(), globalOffset);
            add_match(pathTosearch, globalOffset, section, stringTosearch, format,
                      all_file_info, onResult);
        }
    }
}

void searchStringInDir(const std::string& directory, const string stringTosearch, BOOL isUnicode,
                       vector<file_info>& all_file_info, BOOL caseInsensitive,
                       BOOL countMode, const HexPattern* hexPat, const ResultCallback& onResult,
                       ScanStats* stats)
{
    platform_walk_directory(directory,
        [&](const std::string& combined_path, bool is_directory, bool is_symlink) {
            if (is_directory) {
                if (is_symlink) {
                    return;
                }
                searchStringInDir(combined_path, stringTosearch, isUnicode, all_file_info,
                                  caseInsensitive, countMode, hexPat, onResult, stats);
                return;
            }

            if (!onResult) {
                status_update(combined_path);
            }
            searchStringinFile(combined_path, stringTosearch, isUnicode, all_file_info,
                               caseInsensitive, countMode, hexPat, onResult, stats);
        });
}
