#include <Windows.h>
#include "file_info.h"


bool compare_filepath(const file_info& x, const file_info& y) { return x.filepath < y.filepath; }

bool compare_fileoffset(const file_info& x, const file_info& y) { return x.fileoffset < y.fileoffset; }

bool compare_secIndex(const file_info& x, const file_info& y) { return x.sectionindex < y.sectionindex; }

bool compare_secOffset(const file_info& x, const file_info& y) { return x.sectionoffset < y.sectionoffset; }

bool compare_secName(const file_info& x, const file_info& y) { return x.sectionName < y.sectionName; }

bool compare_isPE(const file_info& x, const file_info& y) { return x.isPE < y.isPE; }


int checkFile(const string pathTosearch)
{
    DWORD fileInfo;
    fileInfo = GetFileAttributesA(pathTosearch.c_str());

    if (INVALID_FILE_ATTRIBUTES == fileInfo && GetLastError() == ERROR_FILE_NOT_FOUND)
    {
        //cout << "file or path: " << pathTosearch << " does not exist." << endl;
        return -1;
    }

    if (fileInfo & FILE_ATTRIBUTE_DIRECTORY) {
        //cout << "pathTosearch is directory." << endl;
        return 1;
    }

    return 0;
}
