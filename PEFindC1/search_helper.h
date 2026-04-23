#pragma once

#include <windows.h>
#include "file_info.h"
#include "algo.h"

using std::vector;

void searchStringinFile(const string pathTosearch, const string stringTosearch, BOOL isUnicode, 
                        vector<file_info>& all_file_info, BOOL stream, BOOL caseInsensitive = FALSE,
                        BOOL countMode = FALSE, const HexPattern* hexPat = nullptr);

void searchStringInDir(const std::string& directory, const string stringTosearch, BOOL isUnicode, 
                       vector<file_info>& all_file_info, BOOL stream, BOOL caseInsensitive = FALSE,
                       BOOL countMode = FALSE, const HexPattern* hexPat = nullptr);
