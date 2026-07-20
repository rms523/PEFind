#include "file_info.h"
#include "platform.h"

bool compare_filepath(const file_info& x, const file_info& y) { return x.filepath < y.filepath; }

bool compare_fileoffset(const file_info& x, const file_info& y) { return x.fileoffset < y.fileoffset; }

bool compare_secIndex(const file_info& x, const file_info& y) { return x.sectionindex < y.sectionindex; }

bool compare_secOffset(const file_info& x, const file_info& y) { return x.sectionoffset < y.sectionoffset; }

bool compare_secName(const file_info& x, const file_info& y) { return x.sectionName < y.sectionName; }

bool compare_isPE(const file_info& x, const file_info& y) { return x.isPE < y.isPE; }

int checkFile(const std::string& pathTosearch)
{
    return platform_path_kind(pathTosearch);
}
