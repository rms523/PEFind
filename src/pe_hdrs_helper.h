#pragma once
#include <cstddef>

#include "pe_winnt.h"

BYTE* get_nt_hrds(const BYTE* pe_buffer, size_t buffer_size);
IMAGE_NT_HEADERS32* get_nt_hrds32(BYTE* pe_buffer, size_t buffer_size);
IMAGE_NT_HEADERS64* get_nt_hrds64(const BYTE* pe_buffer, size_t buffer_size);
bool is64bit(const BYTE* pe_buffer, size_t buffer_size);
IMAGE_DATA_DIRECTORY* get_pe_directory(const BYTE* pe_buffer, size_t buffer_size, DWORD dir_id);
ULONGLONG get_module_base(const BYTE* pe_buffer, size_t buffer_size);
PIMAGE_SECTION_HEADER get_section_hdr(const BYTE* payload, size_t buffer_size, DWORD64 globalOffset, int& sectionIndex);
BOOL checkPE(const BYTE* buf, size_t buffer_size);
