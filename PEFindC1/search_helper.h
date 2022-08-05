#pragma once

#include<Windows.h>
#include "file_info.h"

using std::vector;

void searchString(const string , const string, BOOL, vector<file_info>&, BOOL isDir);
