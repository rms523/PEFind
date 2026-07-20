#include "platform.h"

#ifndef _WIN32

#include <cstdio>
#include <cctype>
#include <cerrno>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <string>
#include <system_error>
#include <vector>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

struct PlatformFile {
    int fd = -1;
    uint64_t size = 0;
};

const char* platform_exe_name()
{
    return "PEFind";
}

int platform_path_kind(const std::string& path)
{
    struct stat st {};
    if (stat(path.c_str(), &st) != 0) {
        return -1;
    }
    if (S_ISDIR(st.st_mode)) {
        return 1;
    }
    if (S_ISREG(st.st_mode)) {
        return 0;
    }
    return -1;
}

bool platform_file_open(const std::string& path, PlatformFile*& out)
{
    out = nullptr;
    int fd = open(path.c_str(), O_RDONLY);
    if (fd < 0) {
        return false;
    }

    struct stat st {};
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
        close(fd);
        return false;
    }

    auto* file = new PlatformFile();
    file->fd = fd;
    file->size = static_cast<uint64_t>(st.st_size);
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
    if (file == nullptr || file->fd < 0 || buffer == nullptr) {
        return false;
    }

    while (bytes_read < length) {
        ssize_t chunk = read(file->fd, static_cast<char*>(buffer) + bytes_read, length - bytes_read);
        if (chunk < 0) {
            if (errno == EINTR) {
                continue;
            }
            return false;
        }
        if (chunk == 0) {
            break;
        }
        bytes_read += static_cast<size_t>(chunk);
    }
    return true;
}

bool platform_file_seek(PlatformFile* file, uint64_t offset)
{
    if (file == nullptr || file->fd < 0) {
        return false;
    }
    return lseek(file->fd, static_cast<off_t>(offset), SEEK_SET) >= 0;
}

void platform_file_close(PlatformFile* file)
{
    if (file == nullptr) {
        return;
    }
    if (file->fd >= 0) {
        close(file->fd);
    }
    delete file;
}

void platform_console_flush_input()
{
}

void platform_console_set_color(int color)
{
    if (color == 1) {
        std::fputs("\033[32m", stdout);
    } else {
        std::fputs("\033[0m", stdout);
    }
}

static bool append_utf16_codepoint(std::u16string& out, uint32_t codepoint)
{
    if (codepoint <= 0xFFFF) {
        out.push_back(static_cast<char16_t>(codepoint));
        return true;
    }
    if (codepoint > 0x10FFFF) {
        return false;
    }
    codepoint -= 0x10000;
    out.push_back(static_cast<char16_t>(0xD800 + (codepoint >> 10)));
    out.push_back(static_cast<char16_t>(0xDC00 + (codepoint & 0x3FF)));
    return true;
}

std::u16string platform_utf8_to_utf16le(const std::string& text)
{
    std::u16string out;
    for (size_t i = 0; i < text.size();) {
        unsigned char c = static_cast<unsigned char>(text[i]);
        if (c < 0x80) {
            out.push_back(static_cast<char16_t>(c));
            ++i;
            continue;
        }

        size_t extra = 0;
        uint32_t codepoint = 0;
        if ((c & 0xE0) == 0xC0) {
            extra = 1;
            codepoint = c & 0x1F;
        } else if ((c & 0xF0) == 0xE0) {
            extra = 2;
            codepoint = c & 0x0F;
        } else if ((c & 0xF8) == 0xF0) {
            extra = 3;
            codepoint = c & 0x07;
        } else {
            return {};
        }

        if (i + extra >= text.size()) {
            return {};
        }

        for (size_t j = 1; j <= extra; ++j) {
            unsigned char next = static_cast<unsigned char>(text[i + j]);
            if ((next & 0xC0) != 0x80) {
                return {};
            }
            codepoint = (codepoint << 6) | (next & 0x3F);
        }

        if (!append_utf16_codepoint(out, codepoint)) {
            return {};
        }
        i += extra + 1;
    }
    return out;
}

std::string platform_utf16le_to_utf8(const char16_t* data, size_t count)
{
    std::string out;
    for (size_t i = 0; i < count; ++i) {
        uint32_t codepoint = static_cast<uint16_t>(data[i]);
        if (codepoint >= 0xD800 && codepoint <= 0xDBFF) {
            if (i + 1 >= count) {
                return {};
            }
            uint32_t low = static_cast<uint16_t>(data[i + 1]);
            if (low < 0xDC00 || low > 0xDFFF) {
                return {};
            }
            codepoint = 0x10000 + ((codepoint - 0xD800) << 10) + (low - 0xDC00);
            ++i;
        }

        if (codepoint <= 0x7F) {
            out.push_back(static_cast<char>(codepoint));
        } else if (codepoint <= 0x7FF) {
            out.push_back(static_cast<char>(0xC0 | (codepoint >> 6)));
            out.push_back(static_cast<char>(0x80 | (codepoint & 0x3F)));
        } else if (codepoint <= 0xFFFF) {
            out.push_back(static_cast<char>(0xE0 | (codepoint >> 12)));
            out.push_back(static_cast<char>(0x80 | ((codepoint >> 6) & 0x3F)));
            out.push_back(static_cast<char>(0x80 | (codepoint & 0x3F)));
        } else {
            out.push_back(static_cast<char>(0xF0 | (codepoint >> 18)));
            out.push_back(static_cast<char>(0x80 | ((codepoint >> 12) & 0x3F)));
            out.push_back(static_cast<char>(0x80 | ((codepoint >> 6) & 0x3F)));
            out.push_back(static_cast<char>(0x80 | (codepoint & 0x3F)));
        }
    }
    return out;
}

void platform_lowercase_utf16(char16_t* data, size_t count)
{
    for (size_t i = 0; i < count; ++i) {
        if (data[i] < 128) {
            data[i] = static_cast<char16_t>(std::tolower(static_cast<unsigned char>(data[i])));
        }
    }
}

void platform_walk_directory(
    const std::string& directory,
    const std::function<void(const std::string& full_path, bool is_directory, bool is_symlink)>& visitor)
{
    namespace fs = std::filesystem;
    std::error_code ec;
    fs::directory_iterator it(directory, fs::directory_options::skip_permission_denied, ec);
    if (ec) {
        return;
    }

    for (const auto& entry : it) {
        std::error_code entry_ec;
        if (entry.path().filename() == "." || entry.path().filename() == "..") {
            continue;
        }

        const std::string full_path = entry.path().string();
        const bool is_symlink = entry.is_symlink(entry_ec);
        const bool is_directory = entry.is_directory(entry_ec);
        visitor(full_path, is_directory, is_symlink);
    }
}

#endif
