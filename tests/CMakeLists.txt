# Unit tests for PEFind — pure C++ algorithm testing.
# Tests include winnt_mock.h + algo.h and do NOT depend on Windows SDK.

include(GoogleTest)

add_executable(test_algorithms
    test_parse_hex.cpp
    test_bmh_search.cpp
    test_wildcard_search.cpp
    test_case_insensitive.cpp
    test_pe_parsing.cpp
)

target_include_directories(test_algorithms PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(test_algorithms PRIVATE gtest gtest_main)

# Register tests with CTest
gtest_discover_tests(test_algorithms)
