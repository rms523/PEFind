#include "util.h"

bool validate_ptr(const void* buffer_bgn, SIZE_T buffer_size, const void* field_bgn, SIZE_T field_size)
{
    ULONGLONG start = (ULONGLONG)buffer_bgn;
    ULONGLONG end = start + buffer_size;

    ULONGLONG field_end = (ULONGLONG)field_bgn + field_size;

    if ((ULONGLONG)field_bgn < start) {
        return false;
    }
    if (field_end > end) {
        return false;
    }
    return true;
}

static std::wstring multibyte_to_utf16(const std::string& text, UINT codePage, DWORD flags)
{
    if (text.empty()) return {};

    int length = MultiByteToWideChar(codePage, flags, text.c_str(),
                                     static_cast<int>(text.size()), nullptr, 0);
    if (length <= 0) return {};

    std::wstring wide(static_cast<size_t>(length), L'\0');
    if (MultiByteToWideChar(codePage, flags, text.c_str(), static_cast<int>(text.size()),
                            wide.data(), length) != length) {
        return {};
    }

    return wide;
}

std::wstring utf8_to_utf16(const std::string& text)
{
    std::wstring wide = multibyte_to_utf16(text, CP_UTF8, MB_ERR_INVALID_CHARS);
    if (!wide.empty() || text.empty()) return wide;

    // Narrow argv can still arrive in the active ANSI code page on older shells.
    return multibyte_to_utf16(text, CP_ACP, 0);
}

std::string utf16_to_utf8(const std::wstring& text)
{
    if (text.empty()) return {};

    int length = WideCharToMultiByte(CP_UTF8, 0, text.c_str(), static_cast<int>(text.size()),
                                     nullptr, 0, nullptr, nullptr);
    if (length <= 0) return {};

    std::string utf8(static_cast<size_t>(length), '\0');
    if (WideCharToMultiByte(CP_UTF8, 0, text.c_str(), static_cast<int>(text.size()),
                            utf8.data(), length, nullptr, nullptr) != length) {
        return {};
    }

    return utf8;
}
