#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

#include "elf_defs.h"
#include "pe_winnt.h"

struct ElfSectionHit {
    bool found = false;
    int index = 0;
    uint64_t section_offset = 0;
    std::string name;
};

bool checkELF(const BYTE* buf, size_t buffer_size);
bool is_elf64(const BYTE* buf, size_t buffer_size);
ElfSectionHit get_elf_section_by_file_offset(const BYTE* buf, size_t buffer_size, uint64_t file_offset);
