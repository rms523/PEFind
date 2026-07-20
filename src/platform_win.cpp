#include "platform.h"

#ifdef _WIN32

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>

#include <cstring>
#include <functional>
#include <string>

struct PlatformFile {
    HANDLE handle = INVALID_HANDLE_VALUE;
    uint64_t size = 0;
};

static std::wstring utf8_to_wide(const std::string& text)
{
    if (text.empty()) return {};

    int length = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.c_str(),
                                     static_cast<int>(text.size()), nullptr, 0);
    if (length <= 0) {
        length = MultiByteToWideChar(CP_ACP, 0, text.c_str(), static_cast<int>(text.size()), nullptr, 0);
        if (length <= 0) return {};
        std::wstring wide(static_cast<size_t>(length), L'\0');
        if (MultiByteToWideChar(CP_ACP, 0, text.c_str(), static_cast<int>(text.size()),
                                &wide[0], length) != length) {
            return {};
        }
        return wide;
    }

    std::wstring wide(static_cast<size_t>(length), L'\0');
    if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.c_str(), static_cast<int>(text.size()),
                            &wide[0], length) != length) {
        return {};
    }
    return wide;
}

static std::string wide_to_utf8(const std::wstring& text)
{
    if (text.empty()) return {};

    int length = WideCharToMultiByte(CP_UTF8, 0, text.c_str(), static_cast<int>(text.size()),
                                     nullptr, 0, nullptr, nullptr);
    if (length <= 0) return {};

    std::string utf8(static_cast<size_t>(length), '\0');
    if (WideCharToMultiByte(CP_UTF8, 0, text.c_str(), static_cast<int>(text.size()),
                            &utf8[0], length, nullptr, nullptr) != length) {
        return {};
    }
    return utf8;
}

const char* platform_exe_name()
{
    return "PEFind.exe";
}

int platform_path_kind(const std::string& path)
{
    const std::wstring wide_path = utf8_to_wide(path);
    if (wide_path.empty() && !path.empty()) {
        return -1;
    }

    const DWORD attrs = GetFileAttributesW(wide_path.c_str());
    if (attrs == INVALID_FILE_ATTRIBUTES) {
        return -1;
    }
    if (attrs & FILE_ATTRIBUTE_DIRECTORY) {
        return 1;
    }
    return 0;
}

bool platform_file_open(const std::string& path, PlatformFile*& out)
{
    out = nullptr;
    const std::wstring wide_path = utf8_to_wide(path);
    if (wide_path.empty() && !path.empty()) {
        return false;
    }

    HANDLE handle = CreateFileW(wide_path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                                OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (handle == INVALID_HANDLE_VALUE) {
        return false;
    }

    LARGE_INTEGER file_size {};
    if (!GetFileSizeEx(handle, &file_size)) {
        CloseHandle(handle);
        return false;
    }

    auto* file = new PlatformFile();
    file->handle = handle;
    file->size = static_cast<uint64_t>(file_size.QuadPart);
    out = file;
    return true;
}

uint64_t platform_file_size(const PlatformFile* file)
{
    return file ? file->size : 0;
}

bool platform_file_read(PlatformFile* file, void* buffer, size_t length, size_t& bytes_read)
{
    bytes_read = 0;
    if (file == nullptr || file->handle == INVALID_HANDLE_VALUE || buffer == nullptr) {
        return false;
    }

    DWORD chunk = 0;
    if (!ReadFile(file->handle, buffer, static_cast<DWORD>(length), &chunk, nullptr)) {
        return false;
    }
    bytes_read = chunk;
    return true;
}

bool platform_file_seek(PlatformFile* file, uint64_t offset)
{
    if (file == nullptr || file->handle == INVALID_HANDLE_VALUE) {
        return false;
    }
    LARGE_INTEGER pos {};
    pos.QuadPart = static_cast<LONGLONG>(offset);
    return SetFilePointerEx(file->handle, pos, nullptr, FILE_BEGIN) != FALSE;
}

void platform_file_close(PlatformFile* file)
{
    if (file == nullptr) {
        return;
    }
    if (file->handle != INVALID_HANDLE_VALUE) {
        CloseHandle(file->handle);
    }
    delete file;
}

void platform_console_flush_input()
{
    // No-op: FlushConsoleInputBuffer is optional and not always exposed with WIN32_LEAN_AND_MEAN.
}

void platform_console_set_color(int color)
{
    HANDLE console = GetStdHandle(STD_OUTPUT_HANDLE);
    if (console == INVALID_HANDLE_VALUE) {
        return;
    }
    SetConsoleTextAttribute(console, color == 1 ? 10 : 15);
}

std::u16string platform_utf8_to_utf16le(const std::string& text)
{
    const std::wstring wide = utf8_to_wide(text);
    return std::u16string(wide.begin(), wide.end());
}

std::string platform_utf16le_to_utf8(const char16_t* data, size_t count)
{
    std::wstring wide(reinterpret_cast<const wchar_t*>(data), count);
    return wide_to_utf8(wide);
}

void platform_lowercase_utf16(char16_t* data, size_t count)
{
    if (data == nullptr || count == 0) {
        return;
    }
    CharLowerBuffW(reinterpret_cast<PWSTR>(data), static_cast<DWORD>(count));
}

void platform_walk_directory(
    const std::string& directory,
    const std::function<void(const std::string& full_path, bool is_directory, bool is_symlink)>& visitor)
{
    const std::wstring wide_directory = utf8_to_wide(directory);
    if (wide_directory.empty() && !directory.empty()) {
        return;
    }

    const std::wstring pattern = wide_directory + L"\\*";
    WIN32_FIND_DATAW find_data {};
    HANDLE find_handle = FindFirstFileW(pattern.c_str(), &find_data);
    if (find_handle == INVALID_HANDLE_VALUE) {
        return;
    }

    do {
        if (wcscmp(find_data.cFileName, L".") == 0 || wcscmp(find_data.cFileName, L"..") == 0) {
            continue;
        }

        std::string combined = directory;
        if (!combined.empty() && combined.back() != '\\' && combined.back() != '/') {
            combined += "\\";
        }
        combined += wide_to_utf8(find_data.cFileName);

        const bool is_directory = (find_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
        const bool is_symlink = (find_data.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0;
        visitor(combined, is_directory, is_symlink);
    } while (FindNextFileW(find_handle, &find_data) != 0);

    FindClose(find_handle);
}

#endif
