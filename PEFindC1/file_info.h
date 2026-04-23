#pragma once
#include <string>
using std::string;

struct file_info {
    string filepath;
    DWORD64 fileoffset;       // FIX #2: was int, now DWORD64 to support files > 2 GiB
    int sectionindex, sectionoffset;
    string sectionName, stringTosearch, isPE;
};
bool compare_filepath(const file_info&, const file_info&);
bool compare_fileoffset(const file_info&, const file_info&);
bool compare_secIndex(const file_info&, const file_info&);
bool compare_secOffset(const file_info&, const file_info&);
bool compare_secName(const file_info&, const file_info&);
bool compare_isPE(const file_info&, const file_info&);
int checkFile(const string);
