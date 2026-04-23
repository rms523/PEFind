# PEFind library (core logic) — compiled with Windows headers for the main build.
# Note: algo.h is header-only and can be included by tests without Windows deps.

add_library(pefind_core STATIC
    file_info.cpp
    pe_hdrs_helper.cpp
    search_helper.cpp
    util.cpp
)

target_include_directories(pefind_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

# Link Shlwapi for the library (needed by search_helper.cpp)
if(MSVC OR MINGW)
    target_link_libraries(pefind_core PRIVATE shlwapi)
endif()

# Main executable
add_executable(PEFindC1 PEFindC1.cpp)

target_include_directories(PEFindC1 PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(PEFindC1 PRIVATE pefind_core)

if(MSVC OR MINGW)
    target_link_libraries(PEFindC1 PRIVATE shlwapi)
endif()

# Install targets (optional, for `make install`)
install(TARGETS PEFindC1 DESTINATION bin)
