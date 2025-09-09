#include <vector>
#include <iostream>
#include <iomanip>
#include <algorithm>
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


static void print_row_stream(const file_info& fi)
{
    std::ios_base::fmtflags f(std::cout.flags());
    size_t maxlen = 90; // fixed width for streaming mode

    std::cout << std::setw(maxlen + 5) << std::left << fi.filepath;
    std::cout << std::setw(12) << std::uppercase << std::hex << fi.fileoffset;
    std::cout << std::setw(12) << fi.sectionindex;
    std::cout << std::setw(12) << fi.sectionoffset;
    std::cout << std::setw(18) << fi.sectionName;
    std::cout << std::setw(38) << fi.isPE;
    std::cout << std::endl;

    std::cout.flags(f);
}

static void status_update(const std::string& text)
{
    static size_t last_len = 0;
    std::string msg = std::string("Processing: ") + text;
    // Trim overly long messages to avoid wrapping
    const size_t max_show = 160;
    if (msg.size() > max_show) {
        msg = msg.substr(0, max_show - 3) + "...";
    }
    // Pad with spaces to fully clear previous content
    size_t pad = (last_len > msg.size()) ? (last_len - msg.size()) : 0;
    std::cout << '\r' << msg << std::string(pad, ' ') << std::flush;
    last_len = msg.size();
}

void searchStringinFile(const string pathTosearch, const string stringTosearch, BOOL isUnicode, vector<file_info>& all_file_info, BOOL stream)
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
        CloseHandle(hHandle);
        return;
    }

    // Read a small header region for later section mapping
    const DWORD HEADER_READ = static_cast<DWORD>(std::min<ULONGLONG>(size.QuadPart, 64ULL * 1024ULL));
    std::vector<BYTE> header_buf(HEADER_READ, 0);
    DWORD header_bytes = 0;
    LARGE_INTEGER zero{}; zero.QuadPart = 0;
    SetFilePointerEx(hHandle, zero, NULL, FILE_BEGIN);
    if (!ReadFile(hHandle, header_buf.data(), HEADER_READ, &header_bytes, NULL))
    {
        CloseHandle(hHandle);
        std::cout << "File header read failed!" << std::endl;
        return;
    }

    // Determine if it looks like a PE (MZ)
    int isPE = checkPE(header_buf.data()) ? 1 : 0;
    int sectionIndex = 0;

    // Build pattern bytes
    int global_offset = -1;
    string::size_type stringsize = stringTosearch.size();
    if (stringsize == 0)
    {
        CloseHandle(hHandle);
        return;
    }

    BYTE* pattern = nullptr;
    int pattern_len = 0;
    std::vector<BYTE> ascii_pat;
    std::vector<WCHAR> wpat;

    if (isUnicode)
    {
        wpat.resize(stringsize + 1);
        int k = MultiByteToWideChar(CP_UTF8, 0, stringTosearch.c_str(), -1, wpat.data(), static_cast<int>(wpat.size()));
        if (!k)
        {
            CloseHandle(hHandle);
            std::cout << "Unicode conversion failed" << std::endl;
            return;
        }
        wpat[static_cast<size_t>(k - 1)] = L'\0';
        pattern = reinterpret_cast<BYTE*>(wpat.data());
        pattern_len = (k - 1) * sizeof(WCHAR); // ignore last null for substring search
    }
    else
    {
        ascii_pat.assign(stringTosearch.begin(), stringTosearch.end());
        pattern = ascii_pat.data();
        pattern_len = static_cast<int>(ascii_pat.size());
    }

    // Stream through file in chunks with overlap to catch boundary matches
    const DWORD CHUNK_SIZE = 8 * 1024 * 1024; // 8 MiB
    const DWORD OVERLAP = (pattern_len > 0) ? static_cast<DWORD>(pattern_len - 1) : 0;
    std::vector<BYTE> buf(CHUNK_SIZE + OVERLAP);
    DWORD overlap_len = 0;
    ULONGLONG base_offset = 0;

    SetFilePointerEx(hHandle, zero, NULL, FILE_BEGIN);
    for (;;)
    {
        DWORD bytesRead = 0;
        if (!ReadFile(hHandle, buf.data() + overlap_len, CHUNK_SIZE, &bytesRead, NULL))
        {
            std::cout << "File reading failed!" << std::endl;
            CloseHandle(hHandle);
            return;
        }
        if (bytesRead == 0)
        {
            break; // EOF
        }

        DWORD search_size = overlap_len + bytesRead;
        int pos = searchHexBytes(buf.data(), pattern, pattern_len, search_size);
        if (pos != -1)
        {
            global_offset = static_cast<int>(base_offset + pos);
            break;
        }

        DWORD new_overlap = std::min<DWORD>(OVERLAP, search_size);
        if (new_overlap > 0)
        {
            memmove(buf.data(), buf.data() + (search_size - new_overlap), new_overlap);
        }
        overlap_len = new_overlap;
        base_offset += (search_size - overlap_len);
    }

    CloseHandle(hHandle);

    // Not found in file
    if (global_offset == -1) return;

    // Use header buffer to derive section information
    PIMAGE_SECTION_HEADER sectionHeader = get_section_hdr(header_buf.data(), header_bytes, global_offset, sectionIndex);

    if (sectionHeader == NULL)
    {
        file_info temp_file_info;
        temp_file_info.filepath = pathTosearch;
        temp_file_info.fileoffset = global_offset;
        temp_file_info.sectionindex = 0;
        temp_file_info.sectionoffset = 0;
        temp_file_info.sectionName = "";
        temp_file_info.stringTosearch = stringTosearch;
        if (isPE) temp_file_info.isPE = "Invalid PE or string not in sections(overlay?)";
        else temp_file_info.isPE = "Not a PE file.";
        all_file_info.push_back(temp_file_info);
        if (stream)
        {
            print_row_stream(temp_file_info);
        }
        return;
    }

    file_info temp_file_info;
    temp_file_info.filepath = pathTosearch;
    temp_file_info.fileoffset = global_offset;
    temp_file_info.sectionindex = sectionIndex;
    temp_file_info.sectionoffset = global_offset - sectionHeader->PointerToRawData;
    temp_file_info.sectionName = string(reinterpret_cast<char*>(sectionHeader->Name), 8);
    temp_file_info.stringTosearch = stringTosearch;
    temp_file_info.isPE = "PE";
    all_file_info.push_back(temp_file_info);
    if (stream)
    {
        print_row_stream(temp_file_info);
    }
    return;

}

void searchStringInDir(const std::string& directory, const string stringTosearch, BOOL isUnicode, vector<file_info>& all_file_info, BOOL stream)
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
        {
            if (!stream)
                status_update(combined_path);
            searchStringinFile(combined_path, stringTosearch, isUnicode, all_file_info, stream);
        }
    }

    FindClose(hFind);

    return;
}


void searchString(const string pathTosearch, const string stringTosearch, BOOL isUnicode, vector<file_info>& all_file_info, BOOL isDir, BOOL stream)
{
    if (isDir) 
    {
        try
        {
            searchStringInDir(pathTosearch, stringTosearch, isUnicode, all_file_info, stream);
        }
        catch (std::exception const& e)
        {
            std::cout << "Exception: " << e.what() << std::endl;
        }
        return;
    }

    if (!stream)
        status_update(pathTosearch);
    searchStringinFile(pathTosearch, stringTosearch, isUnicode, all_file_info, stream);
}
