#pragma once

#include<Windows.h>
#include "file_info.h"

using std::vector;

void searchString(const string , const string, BOOL, vector<file_info>&, BOOL isDir, BOOL stream, BOOL caseInsensitive = FALSE);
void searchStringInDir(const std::string& directory, const string stringTosearch, BOOL isUnicode, vector<file_info>& all_file_info, BOOL stream, BOOL caseInsensitive = FALSE);
