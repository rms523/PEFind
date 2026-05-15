# PEFind library (core logic) — compiled with Windows headers for the main build.
# Note: algo.h is header-only and can be included by tests without Windows deps.

add_library(pefind_core STATIC
    file_info.cpp
    pe_hdrs_helper.cpp
    search_helper.cpp
    util.cpp
)

target_include_directories(pefind_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

# Main executable
add_executable(PEFindC1 PEFindC1.cpp)

target_include_directories(PEFindC1 PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(PEFindC1 PRIVATE pefind_core)

# Install targets (optional, for `make install`)
install(TARGETS PEFindC1 DESTINATION bin)
