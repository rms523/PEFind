# PEFind library (core logic).
# Shared scanner code plus a small platform layer for file I/O and console output.

add_library(pefind_core STATIC
    file_info.cpp
    pe_hdrs_helper.cpp
    pe_header_reader.cpp
    elf_hdrs_helper.cpp
    elf_header_reader.cpp
    search_helper.cpp
    util.cpp
)

if(WIN32)
    target_sources(pefind_core PRIVATE platform_win.cpp)
else()
    target_sources(pefind_core PRIVATE platform_posix.cpp)
endif()

target_include_directories(pefind_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

add_executable(PEFind PEFind.cpp)

target_include_directories(PEFind PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(PEFind PRIVATE pefind_core)

install(TARGETS PEFind DESTINATION bin)
