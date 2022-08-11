#include <vector>
#include <iostream>
#include <iomanip>
#include "file_info.h"
#include "search_helper.h"
#include "pe_hdrs_helper.h"
#include "Shlwapi.h"

#pragma comment(lib, "Shlwapi.lib")

int searchHexBytes(const BYTE* bufTosearch, const BYTE * stringTosearch, int stringsize,  DWORD bufSize)
{
    int i = 0, j = 0, k = 0;
    //string::size_type stringsize = stringTosearch.size();


    for (i = 0; i < bufSize; i++)
    {
        if (j == stringsize) break;

        if (j == 0 && (stringsize > (bufSize - i))) break;

        if (bufTosearch[i] == (BYTE)stringTosearch[j])
        {

            j++;
            continue;
        }
        else {
            j = 0;
            if (bufTosearch[i] == (BYTE)stringTosearch[j])
            {

                j++;
                
            }
        }
    }


    if (j == stringsize)
    {
        return i - j;

    }
    return -1;
}


void searchStringinFile(const string pathTosearch, const string stringTosearch, BOOL isUnicode, vector<file_info>& all_file_info)
{
    HANDLE hHandle = CreateFile(pathTosearch.c_str(), GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
    
    if (hHandle == INVALID_HANDLE_VALUE)
    {
        std::cout << "Failed to Open file: " << pathTosearch.c_str() << std::endl;
        return;
    }


    LARGE_INTEGER size;
    if (!GetFileSizeEx(hHandle, &size))
    {
        std::cout << "Unable to get file size" << std::endl;
        return;
    }

    if (size.QuadPart > MAX_SIZE)
    {
        // File to big to process
        std::cout << "File too big to process" << std::endl;
        return;
    }

    BYTE* buf = new BYTE[size.QuadPart+1];
    memset(buf, 0, sizeof(buf));

    DWORD bytesRead;
    if (ReadFile(hHandle, buf, size.QuadPart, &bytesRead, NULL)) {
        //printf("File successfully read!\n");
        //printf("%d bytes read.\n", bytesRead);
        //printf("%s\n", buf);
        CloseHandle(hHandle);
    }
    else
    {
        CloseHandle(hHandle);
        std::cout << "File reading failed!" << std::endl;
        return;
    }

    int isPE = 1;
    int sectionIndex = 0;

    if (!checkPE(buf))
    {
        //"Not a valid PE file"
        isPE = 0;
    }

    int k = 0, global_offset = 0;
    string::size_type stringsize = stringTosearch.size();

    if (isUnicode)
    {
        WCHAR* uniStringTosearch = new WCHAR[stringsize + 1];
        k = MultiByteToWideChar(CP_UTF8, 0, stringTosearch.c_str(), -1, uniStringTosearch, stringsize+1);
        if (!k)
        {
            std::cout << "Unicode conversion failed" << std::endl;
            return;
        }
        uniStringTosearch[k-1] = L'\0';
        int t = (sizeof(uniStringTosearch)-1) * sizeof(WCHAR);
        global_offset = searchHexBytes(buf, (BYTE *) uniStringTosearch, t, size.QuadPart);

    }

    else 
    {
        global_offset = searchHexBytes(buf, (BYTE *) stringTosearch.c_str(), stringsize, size.QuadPart);
    }

    
    // Not found in file
    if (global_offset == -1) return;

    else
    {
        PIMAGE_SECTION_HEADER sectionHeader = get_section_hdr(buf, size.QuadPart + 1, global_offset, sectionIndex);

        if (sectionHeader == NULL)
        {
            file_info temp_file_info;
            temp_file_info.filepath = pathTosearch;
            temp_file_info.fileoffset = global_offset;
            temp_file_info.sectionindex = 0;
            temp_file_info.sectionoffset = 0;
            temp_file_info.sectionName = "";
            temp_file_info.stringTosearch = stringTosearch;
            if (isPE) temp_file_info.isPE = "Invalid PE or string not in sections?)";
            else temp_file_info.isPE = "Not a PE file.";
            all_file_info.push_back(temp_file_info);
            return;
        }

        else {
            file_info temp_file_info;
            temp_file_info.filepath = pathTosearch;
            temp_file_info.fileoffset = global_offset;
            temp_file_info.sectionindex = sectionIndex;
            temp_file_info.sectionoffset = global_offset - sectionHeader->PointerToRawData;
            temp_file_info.sectionName = string(reinterpret_cast<char*>(sectionHeader->Name), 8);
            temp_file_info.stringTosearch = stringTosearch;
            temp_file_info.isPE = "PE";
            all_file_info.push_back(temp_file_info);
        }
        return;
    }

}

void searchStringInDir(const std::string& directory, const string stringTosearch, BOOL isUnicode, vector<file_info>& all_file_info)
{
    WIN32_FIND_DATA findData;
    HANDLE hFind = INVALID_HANDLE_VALUE;
    std::string full_path = directory + "\\*";
  

    hFind = FindFirstFileA(full_path.c_str(), &findData);

    if (hFind == INVALID_HANDLE_VALUE)
    {
        throw std::runtime_error("Invalid handle value! Please check your path...");
    }
    while (FindNextFileA(hFind, &findData) != 0)
    {
        char combined_path[MAX_PATH];
        strcpy_s(combined_path, directory.c_str());
        PathAppend(combined_path, findData.cFileName);
        if (checkFile(combined_path) == 0)
        searchStringinFile(combined_path, stringTosearch, isUnicode, all_file_info);
    }

    FindClose(hFind);

    return;
}


void searchString(const string pathTosearch, const string stringTosearch, BOOL isUnicode, vector<file_info>& all_file_info, BOOL isDir)
{
    if (isDir) 
    {
        try
        {
            searchStringInDir(pathTosearch, stringTosearch, isUnicode, all_file_info);
        }
        catch (std::exception const& e)
        {
            std::cout << "Exception: " << e.what() << std::endl;
        }
        return;
    }

    searchStringinFile(pathTosearch, stringTosearch, isUnicode, all_file_info);
}