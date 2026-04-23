#pragma once

#include <windows.h>
#include <TlHelp32.h>
#include <stdio.h>

bool validate_ptr(const void* buffer_bgn, SIZE_T buffer_size, const void* field_bgn, SIZE_T field_size);
