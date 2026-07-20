#pragma once
#include <string>
#include <windows.h>
using std::string;

struct file_info {
    string filepath;
    DWORD64 fileoffset;
    int sectionindex;
    DWORD64 sectionoffset;
    string sectionName, stringTosearch, isPE;
};

bool compare_filepath(const file_info&, const file_info&);
bool compare_fileoffset(const file_info&, const file_info&);
bool compare_secIndex(const file_info&, const file_info&);
bool compare_secOffset(const file_info&, const file_info&);
bool compare_secName(const file_info&, const file_info&);
bool compare_isPE(const file_info&, const file_info&);
int checkFile(const string);
