#pragma once

#include <cstdint>
#include <vector>

#include "pe_winnt.h"

struct PlatformFile;

// Read ELF header, section header table, and section-name string table into out_buf.
// Returns bytes available in out_buf (0 on hard failure).
uint32_t read_elf_header(PlatformFile* file, std::vector<BYTE>& out_buf);
