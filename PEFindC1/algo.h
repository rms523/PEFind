#pragma once

#include <vector>
#include <string>
#include <cctype>
#include <cstring>
#include <cstdint>
#include <cassert>

#ifndef IMAGE_NT_OPTIONAL_HDR_MAGIC64
#define IMAGE_NT_OPTIONAL_HDR_MAGIC64 IMAGE_NT_OPTIONAL_HDR64_MAGIC
#endif

// Hex/wildcard pattern structure for --hex/--wildcard mode
struct HexPattern {
    std::vector<uint8_t> bytes;      // byte values (valid only if !isWildcard[i])
    std::vector<bool> isWildcard;    // true if this position matches any byte
    
    size_t size() const { return bytes.size(); }
};

// Parse hex string into HexPattern. Supports:
//   "4D5A9000" → exact bytes [0x4D, 0x5A, 0x90, 0x00]
//   "4D 5A 90 00" → same (spaces ignored)
//   "xx xx 90 00" → wildcard + wildcard + exact + exact
inline HexPattern parse_hex_pattern(const std::string& hexStr) {
    HexPattern pattern;
    
    // Remove spaces first
    std::string cleaned;
    for (char c : hexStr) {
        if (c != ' ') cleaned += c;
    }
    
    size_t i = 0;
    while (i < cleaned.size()) {
        char c1 = tolower(static_cast<unsigned char>(cleaned[i]));
        
        // Check for wildcard "xx" or "XX"
        if (c1 == 'x' && i + 1 < cleaned.size() && 
            tolower(static_cast<unsigned char>(cleaned[i+1])) == 'x') {
            pattern.bytes.push_back(0);
            pattern.isWildcard.push_back(true);
            i += 2;
        } else if (i + 1 < cleaned.size()) {
            char h = toupper(static_cast<unsigned char>(cleaned[i]));
            char l = toupper(static_cast<unsigned char>(cleaned[i+1]));
            
            uint8_t high, low;
            if (h >= '0' && h <= '9') high = static_cast<uint8_t>(h - '0');
            else if (h >= 'A' && h <= 'F') high = static_cast<uint8_t>(h - 'A' + 10);
            else { ++i; continue; }
            
            if (l >= '0' && l <= '9') low = static_cast<uint8_t>(l - '0');
            else if (l >= 'A' && l <= 'F') low = static_cast<uint8_t>(l - 'A' + 10);
            else { ++i; continue; }
            
            pattern.bytes.push_back(static_cast<uint8_t>((high << 4) | low));
            pattern.isWildcard.push_back(false);
            i += 2;
        } else {
            // Single remaining character - skip it
            ++i;
        }
    }
    
    return pattern;
}

// Case-insensitive byte comparison helper for ASCII mode
inline bool bytes_equal_ci(uint8_t a, uint8_t b) { 
    return tolower(a) == tolower(b); 
}

// Boyer-Moore-Horspool search — O(n/m) average case.
using ByteCompare = bool(*)(uint8_t, uint8_t);

inline void build_bmh_skip_table(const uint8_t* needle, size_t needleLen, ByteCompare cmp,
                                 int (&skip)[256]) {
    for (size_t c = 0; c < 256; ++c) {
        skip[c] = static_cast<int>(needleLen);
        for (size_t i = 0; i + 1 < needleLen; ++i) {
            if (cmp(static_cast<uint8_t>(c), needle[i])) {
                skip[c] = static_cast<int>(needleLen - 1 - i);
            }
        }
    }
}

inline int search_bmh(const uint8_t* haystack, size_t haystackLen,
                      const uint8_t* needle, size_t needleLen,
                      ByteCompare cmp) {
    if (needleLen == 0 || needleLen > haystackLen) return -1;

    constexpr size_t ALPHABET_SIZE = 256;
    int skip[ALPHABET_SIZE];
    build_bmh_skip_table(needle, needleLen, cmp, skip);

    size_t i = 0;
    while (i <= haystackLen - needleLen) {
        size_t j = needleLen;
        while (j > 0 && cmp(haystack[i + j - 1], needle[j - 1])) { --j; }
        if (j == 0) return static_cast<int>(i);
        i += skip[static_cast<uint8_t>(haystack[i + needleLen - 1])];
    }
    return -1;
}

// Find ALL occurrences of needle in haystack using Boyer-Moore-Horspool.
inline std::vector<int> find_all_bmh(const uint8_t* haystack, size_t haystackLen,
                                      const uint8_t* needle, size_t needleLen,
                                      ByteCompare cmp) {
    std::vector<int> positions;
    if (needleLen == 0 || needleLen > haystackLen) return positions;

    constexpr size_t ALPHABET_SIZE = 256;
    int skip[ALPHABET_SIZE];
    build_bmh_skip_table(needle, needleLen, cmp, skip);

    size_t i = 0;
    while (i <= haystackLen - needleLen) {
        size_t j = needleLen;
        while (j > 0 && cmp(haystack[i + j - 1], needle[j - 1])) { --j; }
        if (j == 0) { positions.push_back(static_cast<int>(i)); i += needleLen; }
        else { i += skip[static_cast<uint8_t>(haystack[i + needleLen - 1])]; }
    }
    return positions;
}

// Find all occurrences of a hex pattern (with optional wildcards) using sliding window.
inline std::vector<int> find_all_with_wildcards(const uint8_t* haystack, size_t haystackLen, 
                                                 const HexPattern& pattern) {
    std::vector<int> positions;
    if (pattern.bytes.empty() || pattern.isWildcard.size() != pattern.bytes.size()) return positions;

    int needleLen = static_cast<int>(pattern.bytes.size());
    if (needleLen > static_cast<int>(haystackLen)) return positions;

    // Check for at least one non-wildcard byte
    bool hasNonWildcard = false;
    for (bool isW : pattern.isWildcard) { if (!isW) { hasNonWildcard = true; break; } }
    if (!hasNonWildcard) return positions;

    for (size_t i = 0; i <= haystackLen - static_cast<size_t>(needleLen); ++i) {
        bool match = true;
        for (int j = 0; j < needleLen && match; ++j) {
            if (!pattern.isWildcard[j] && haystack[i + j] != pattern.bytes[j]) {
                match = false;
            }
        }
        if (match) { positions.push_back(static_cast<int>(i)); i += static_cast<size_t>(needleLen - 1); }
    }
    return positions;
}

// ============================================================
// PE header parsing helpers — pure C++ implementations for testing.
// These mirror the logic in pe_hdrs_helper.cpp but work on raw byte buffers.
// Requires winnt_mock.h to be included first (or real Windows headers).
// ============================================================

struct PeInfo {
    bool is_valid = false;
    bool is_64bit = false;
    DWORD e_lfanew = 0;
    WORD machine = 0;
    WORD num_sections = 0;
    DWORD size_of_headers = 0;
};

inline PeInfo parse_pe_header(const uint8_t* buf, size_t buf_size) {
    PeInfo info;
    
    if (buf_size < sizeof(IMAGE_DOS_HEADER)) return info;
    
    const auto* idh = reinterpret_cast<const IMAGE_DOS_HEADER*>(buf);
    if (idh->e_magic != IMAGE_DOS_SIGNATURE) return info;
    
    LONG pe_offset = static_cast<LONG>(idh->e_lfanew);
    if (pe_offset < 0 || pe_offset > static_cast<LONG>(buf_size - sizeof(DWORD))) return info;
    
    const auto* sig = reinterpret_cast<const DWORD*>(buf + pe_offset);
    if (*sig != IMAGE_NT_SIGNATURE) return info;

    if (static_cast<size_t>(pe_offset) + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) > buf_size) {
        return info;
    }

    info.e_lfanew = static_cast<DWORD>(pe_offset);
    
    // Check machine type to determine 32 vs 64 bit
    const auto* file_hdr = reinterpret_cast<const IMAGE_FILE_HEADER*>(buf + pe_offset + sizeof(DWORD));
    info.machine = file_hdr->Machine;
    info.num_sections = file_hdr->NumberOfSections;
    
    const uint8_t* optional_header = reinterpret_cast<const uint8_t*>(file_hdr) + sizeof(IMAGE_FILE_HEADER);
    if (optional_header + file_hdr->SizeOfOptionalHeader > buf + buf_size) return info;

    if (file_hdr->Machine == IMAGE_FILE_MACHINE_I386) {
        if (file_hdr->SizeOfOptionalHeader < sizeof(IMAGE_OPTIONAL_HEADER32)) return info;
        info.is_64bit = false;
        const auto* opt_hdr32 = reinterpret_cast<const IMAGE_OPTIONAL_HEADER32*>(optional_header);
        info.size_of_headers = opt_hdr32->SizeOfHeaders;
        info.is_valid = true;
    } else if (file_hdr->Machine == IMAGE_FILE_MACHINE_AMD64) {
        if (file_hdr->SizeOfOptionalHeader < sizeof(IMAGE_OPTIONAL_HEADER64)) return info;
        info.is_64bit = true;
        const auto* opt_hdr64 = reinterpret_cast<const IMAGE_OPTIONAL_HEADER64*>(optional_header);
        info.size_of_headers = opt_hdr64->SizeOfHeaders;
        info.is_valid = true;
    }
    
    return info;
}

// Get section header at a given index from the PE buffer.
inline const IMAGE_SECTION_HEADER* get_section_at(const uint8_t* buf, size_t buf_size, 
                                                   DWORD pe_offset, int index) {
    if (index < 0) return nullptr;
    if (static_cast<size_t>(pe_offset) + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) > buf_size) return nullptr;
    
    const auto* file_hdr = reinterpret_cast<const IMAGE_FILE_HEADER*>(buf + pe_offset + sizeof(DWORD));
    const uint8_t* sec_ptr = reinterpret_cast<const uint8_t*>(file_hdr) +
                             sizeof(IMAGE_FILE_HEADER) + file_hdr->SizeOfOptionalHeader;
    if (sec_ptr > buf + buf_size) return nullptr;
    
    for (int i = 0; i < file_hdr->NumberOfSections && i <= index; ++i, 
         sec_ptr += IMAGE_SIZEOF_SECTION_HEADER) {
        if (i == index) {
            // Validate bounds
            size_t offset = static_cast<size_t>(sec_ptr - buf);
            if (offset + sizeof(IMAGE_SECTION_HEADER) > buf_size) return nullptr;
            return reinterpret_cast<const IMAGE_SECTION_HEADER*>(sec_ptr);
        }
    }
    return nullptr;
}

// Find which section contains a given file offset.
inline int find_section_for_offset(const uint8_t* buf, size_t buf_size, 
                                    DWORD pe_offset, DWORD file_offset) {
    if (static_cast<size_t>(pe_offset) + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) > buf_size) return -1;

    const auto* file_hdr = reinterpret_cast<const IMAGE_FILE_HEADER*>(buf + pe_offset + sizeof(DWORD));
    const uint8_t* sec_ptr = reinterpret_cast<const uint8_t*>(file_hdr) +
                             sizeof(IMAGE_FILE_HEADER) + file_hdr->SizeOfOptionalHeader;
    if (sec_ptr > buf + buf_size) return -1;
    
    for (int i = 0; i < file_hdr->NumberOfSections; ++i, 
         sec_ptr += IMAGE_SIZEOF_SECTION_HEADER) {
        size_t offset = static_cast<size_t>(sec_ptr - buf);
        if (offset + sizeof(IMAGE_SECTION_HEADER) > buf_size) continue;
        
        const auto* section = reinterpret_cast<const IMAGE_SECTION_HEADER*>(sec_ptr);
        DWORD raw_addr = section->PointerToRawData;
        DWORD raw_size = section->SizeOfRawData;
        
        if (raw_addr <= file_offset && file_offset < raw_addr + raw_size) {
            return i;
        }
    }
    return -1;  // Not in any section
}

// Create a minimal test PE buffer for testing section header logic.
inline std::vector<uint8_t> create_test_pe(size_t file_size, 
                                            const std::vector<std::pair<DWORD, DWORD>>& sections) {
    size_t section_count = sections.size();
    
    // Calculate sizes: DOS header + NT headers (sig + file_hdr + opt_hdr64) + section table
    size_t dos_header_size = sizeof(IMAGE_DOS_HEADER);
    size_t nt_sig_size = sizeof(DWORD);
    size_t file_hdr_size = sizeof(IMAGE_FILE_HEADER);
    size_t opt_hdr_size = sizeof(IMAGE_OPTIONAL_HEADER64);
    size_t section_table_size = section_count * IMAGE_SIZEOF_SECTION_HEADER;
    
    // Align headers to 512 bytes for simplicity (matching real PE alignment)
    size_t header_total = dos_header_size + nt_sig_size + file_hdr_size + opt_hdr_size + section_table_size;
    size_t aligned_headers = ((header_total + 511) / 512) * 512;
    
    size_t total_size = (std::max)(aligned_headers, file_size);
    
    std::vector<uint8_t> buf(total_size, 0);
    
    // Write DOS header
    auto* idh = reinterpret_cast<IMAGE_DOS_HEADER*>(buf.data());
    idh->e_magic = IMAGE_DOS_SIGNATURE;
    DWORD pe_offset = static_cast<DWORD>(aligned_headers - (nt_sig_size + file_hdr_size + opt_hdr_size));
    if (pe_offset >= total_size) pe_offset = 0;
    idh->e_lfanew = pe_offset;
    
    // Write NT signature
    auto* sig = reinterpret_cast<DWORD*>(buf.data() + pe_offset);
    *sig = IMAGE_NT_SIGNATURE;
    
    // Write FILE header (64-bit)
    auto* file_hdr = reinterpret_cast<IMAGE_FILE_HEADER*>(buf.data() + pe_offset + sizeof(DWORD));
    file_hdr->Machine = IMAGE_FILE_MACHINE_AMD64;
    file_hdr->NumberOfSections = static_cast<WORD>(section_count);
    file_hdr->SizeOfOptionalHeader = static_cast<WORD>(sizeof(IMAGE_OPTIONAL_HEADER64));
    file_hdr->Characteristics = 0x0022; // EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE
    
    // Write OPTIONAL header (64-bit)
    auto* opt_hdr = reinterpret_cast<IMAGE_OPTIONAL_HEADER64*>(
        reinterpret_cast<uint8_t*>(file_hdr) + sizeof(IMAGE_FILE_HEADER));
    opt_hdr->Magic = IMAGE_NT_OPTIONAL_HDR_MAGIC64;
    opt_hdr->SizeOfHeaders = static_cast<DWORD>(aligned_headers);
    
    // Write section headers
    uint8_t* sec_ptr = reinterpret_cast<uint8_t*>(opt_hdr) + file_hdr->SizeOfOptionalHeader;
    for (size_t i = 0; i < sections.size(); ++i, 
         sec_ptr += IMAGE_SIZEOF_SECTION_HEADER) {
        auto* section = reinterpret_cast<IMAGE_SECTION_HEADER*>(sec_ptr);
        // Section name: ".text", ".rdata", etc. — copy up to 7 chars (8th byte zeroed by memset above)
        const char* names[] = {".text", ".rdata", ".data", ".rsrc", ".reloc"};
        size_t name_len = (std::min)(strlen(names[i < 5 ? i : 4]), static_cast<size_t>(7));
        memcpy(section->Name, names[i < 5 ? i : 4], name_len);
        
        section->VirtualAddress = static_cast<DWORD>(i * 0x1000);
        section->Misc.VirtualSize = sections[i].second;
        section->PointerToRawData = sections[i].first;
        section->SizeOfRawData = sections[i].second;
    }
    
    return buf;
}
