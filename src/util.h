#pragma once

#include <cstddef>
#include <string>

bool validate_ptr(const void* buffer_bgn, std::size_t buffer_size, const void* field_bgn, std::size_t field_size);
