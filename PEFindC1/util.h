#pragma once

#include <windows.h>
#include <TlHelp32.h>
#include <stdio.h>
#include <string>

bool validate_ptr(const void* buffer_bgn, SIZE_T buffer_size, const void* field_bgn, SIZE_T field_size);
std::wstring utf8_to_utf16(const std::string& text);
std::string utf16_to_utf8(const std::wstring& text);
