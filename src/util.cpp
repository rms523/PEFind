#include "util.h"

#include <cstdint>

bool validate_ptr(const void* buffer_bgn, std::size_t buffer_size, const void* field_bgn, std::size_t field_size)
{
    const auto start = reinterpret_cast<std::uintptr_t>(buffer_bgn);
    const auto end = start + buffer_size;
    const auto field_start = reinterpret_cast<std::uintptr_t>(field_bgn);
    const auto field_end = field_start + field_size;

    if (field_start < start) {
        return false;
    }
    if (field_end > end) {
        return false;
    }
    return true;
}
