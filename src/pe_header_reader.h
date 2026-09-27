#pragma once

#include <cstdint>
#include <vector>

#include "pe_winnt.h"

struct PlatformFile;

uint32_t read_pe_header(PlatformFile* file, std::vector<BYTE>& out_buf);
