#pragma once
#include <windows.h>

BYTE* get_nt_hrds(const BYTE* pe_buffer);
IMAGE_NT_HEADERS32* get_nt_hrds32(BYTE* pe_buffer);
IMAGE_NT_HEADERS64* get_nt_hrds64(const BYTE* pe_buffer);
bool is64bit(const BYTE* pe_buffer);
IMAGE_DATA_DIRECTORY* get_pe_directory(const BYTE* pe_buffer, DWORD dir_id);
ULONGLONG get_module_base(const BYTE* pe_buffer);
PIMAGE_SECTION_HEADER get_section_hdr(const BYTE* payload, const size_t buffer_size, DWORD64 globalOffset, int &sectionIndex);
BOOL checkPE(const BYTE* buf);
