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

target_include_directories(test_algorithms PRIVATE ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/../PEFindC1)
target_link_libraries(test_algorithms PRIVATE gtest gtest_main)

# Register tests with CTest
gtest_discover_tests(test_algorithms)

if(WIN32)
    add_executable(test_scanner_windows
        test_scanner_windows.cpp
    )

    target_include_directories(test_scanner_windows PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}/../PEFindC1
    )
    target_link_libraries(test_scanner_windows PRIVATE pefind_core gtest gtest_main)
    gtest_discover_tests(test_scanner_windows)

    add_test(NAME cli_ascii_result_columns
        COMMAND $<TARGET_FILE:PEFindC1> -a "${CMAKE_CURRENT_SOURCE_DIR}/../README.md" "PEFind")
    set_tests_properties(cli_ascii_result_columns PROPERTIES
        PASS_REGULAR_EXPRESSION "FilePath.*FileOff.*SecIndex.*secOffset.*secName.*isPE")

    add_test(NAME cli_hex_result_columns
        COMMAND $<TARGET_FILE:PEFindC1> --hex "50 45 46 69 6E 64" "${CMAKE_CURRENT_SOURCE_DIR}/../README.md")
    set_tests_properties(cli_hex_result_columns PROPERTIES
        PASS_REGULAR_EXPRESSION "FilePath.*FileOff.*SecIndex.*secOffset.*secName.*isPE")

    add_test(NAME cli_hex_count_result_columns
        COMMAND $<TARGET_FILE:PEFindC1> --hex "50 45 46 69 6E 64" -c "${CMAKE_CURRENT_SOURCE_DIR}/../README.md")
    set_tests_properties(cli_hex_count_result_columns PROPERTIES
        PASS_REGULAR_EXPRESSION "FilePath.*FileOff.*SecIndex.*secOffset.*secName.*isPE.*Matches")

    add_test(NAME cli_ascii_count_result_columns
        COMMAND $<TARGET_FILE:PEFindC1> -a -c "${CMAKE_CURRENT_SOURCE_DIR}/../README.md" "PEFind")
    set_tests_properties(cli_ascii_count_result_columns PROPERTIES
        PASS_REGULAR_EXPRESSION "FilePath.*FileOff.*SecIndex.*secOffset.*secName.*isPE.*Matches")

    add_test(NAME cli_reject_count_with_nth
        COMMAND $<TARGET_FILE:PEFindC1> -c -n 1 "${CMAKE_CURRENT_SOURCE_DIR}/../README.md" "PEFind")
    set_tests_properties(cli_reject_count_with_nth PROPERTIES WILL_FAIL TRUE)
endif()
