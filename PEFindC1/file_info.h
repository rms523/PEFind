#pragma once
#include <string>
#define MAX_SIZE 0x10000000
using std::string;

struct file_info {
	string filepath;
	int fileoffset, sectionindex, sectionoffset;
	string sectionName, stringTosearch, isPE;
};
bool compare_filepath(const file_info&, const file_info&);
bool compare_fileoffset(const file_info&, const file_info&);
bool compare_secIndex(const file_info&, const file_info&);
bool compare_secOffset(const file_info&, const file_info&);
bool compare_secName(const file_info&, const file_info&);
bool compare_isPE(const file_info&, const file_info&);
int checkFile(const string);