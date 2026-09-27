#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

#include "elf_defs.h"
#include "pe_winnt.h"

struct ElfSectionHit {
    bool found = false;
    int index = 0;
    uint64_t section_offset = 0;
    std::string name;
};

// One file-backed section from the section header table.
struct ElfSection {
    int index = 0;
    uint32_t type = SHT_NULL;
    uint64_t offset = 0;
    uint64_t size = 0;
    std::string name;
};

// Reads `length` bytes at `offset` into `dest`; returns false if the range is unavailable.
using ElfReader = std::function<bool(uint64_t offset, size_t length, std::vector<BYTE>& dest)>;

bool checkELF(const BYTE* buf, size_t buffer_size);
bool is_elf64(const BYTE* buf, size_t buffer_size);

// Parse the section header table (little- or big-endian, ELF32 or ELF64) through `read`.
// `object_size` bounds every table read. Returns false when the object has no usable table.
bool parse_elf_sections(const ElfReader& read, uint64_t object_size, std::vector<ElfSection>& out);

// Convenience wrapper for an ELF image that is fully in memory.
bool parse_elf_sections(const BYTE* buf, size_t buffer_size, std::vector<ElfSection>& out);

ElfSectionHit find_elf_section(const std::vector<ElfSection>& sections, uint64_t file_offset);
ElfSectionHit get_elf_section_by_file_offset(const BYTE* buf, size_t buffer_size, uint64_t file_offset);
