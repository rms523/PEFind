#pragma once

#include <cstdint>
#include <string>

struct file_info {
    std::string filepath;
    uint64_t fileoffset;
    int sectionindex;
    uint64_t sectionoffset;
    std::string sectionName, stringTosearch, isPE;
};

bool compare_filepath(const file_info&, const file_info&);
bool compare_fileoffset(const file_info&, const file_info&);
bool compare_secIndex(const file_info&, const file_info&);
bool compare_secOffset(const file_info&, const file_info&);
bool compare_secName(const file_info&, const file_info&);
bool compare_isPE(const file_info&, const file_info&);
int checkFile(const std::string&);
