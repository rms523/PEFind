#pragma once

#include <vector>

#include "elf_hdrs_helper.h"

struct PlatformFile;

// Load the section table and section names straight from the file, wherever they are stored.
// Returns false when the file has no usable section table (matches then report as outside sections).
bool read_elf_sections(PlatformFile* file, std::vector<ElfSection>& out);
