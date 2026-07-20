#pragma once

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

struct PlatformFile;

// Returns -1 if missing/inaccessible, 0 for file, 1 for directory.
int platform_path_kind(const std::string& path);

bool platform_file_open(const std::string& path, PlatformFile*& out);
uint64_t platform_file_size(const PlatformFile* file);
bool platform_file_read(PlatformFile* file, void* buffer, size_t length, size_t& bytes_read);
bool platform_file_seek(PlatformFile* file, uint64_t offset);
void platform_file_close(PlatformFile* file);

void platform_console_flush_input();
void platform_console_set_color(int color); // 0 = default, 1 = green
const char* platform_exe_name();

std::string platform_wide_to_utf8(const wchar_t* data, size_t count);

void platform_lowercase_utf16(char16_t* data, size_t count);

std::u16string platform_utf8_to_utf16le(const std::string& text);
std::string platform_utf16le_to_utf8(const char16_t* data, size_t count);

void platform_walk_directory(
    const std::string& directory,
    const std::function<void(const std::string& full_path, bool is_directory, bool is_symlink)>& visitor);
