// PEFindC1.cpp : This file contains the 'main' function. Program execution begins and ends there.
//
#include <algorithm>
#include <iostream>
#include <iomanip>
#include <Windows.h>
#include <vector>

#include "search_helper.h"
#include "file_info.h"

using std::cout;
using std::endl;


BOOL checkString(const string, const string, BOOL, vector<file_info> &, BOOL);
void checkString();

void checkString() {}

void info_banner()
{
    cout << "-a or --ascii                           search for ascii string" << endl;
    cout << "-u or --unicode                         search for unicode string" << endl;
    cout << "-au or (--ascii and --unicode)          search for both ascii and unicode string" << endl;
    //cout << "-ci or --nocase                         search for case insensitive string" << endl;                        //TBD
    //cout << "--h or --hex                            search for hex string" << endl;
    //cout << "--w or --wildcard                       search for hex string with wildcard using xx for byte" << endl;
    cout << "-s  or --sort                           sort the search result with specified predicate" << endl;
    cout << "Example: search for case unicode string and sort the result by filepath(0), offset(1), secIndex(2), secOffset(3), secName(4), isPE(5)" << endl;
    cout << "PEFind.exe -a -s 1 search_dir search_str" << endl;
}
void banner()
{
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    FlushConsoleInputBuffer(hConsole);
    SetConsoleTextAttribute(hConsole, 10);  //Green

    cout << R"(
_____  ______      ______ _____ _   _ _____   _____ 
|  __ \|  ____|    |  ____|_   _| \ | |  __ \ / ____|
| |__) | |__ ______| |__    | | |  \| | |  | | |     
|  ___/|  __|______|  __|   | | | . ` | |  | | |     
| |    | |____     | |     _| |_| |\  | |__| | |____ 
|_|    |______|    |_|    |_____|_| \_|_____/ \_____|     
         )" << endl;

    SetConsoleTextAttribute(hConsole, 15);
    cout << "Welcome to the PE-FindC" << endl << endl;
}

static void print_header(std::size_t maxlen)
{
    std::ios_base::fmtflags f(cout.flags());

    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    FlushConsoleInputBuffer(hConsole);
    SetConsoleTextAttribute(hConsole, 10);  //Light Green
    cout << std::setw(maxlen + 5) << std::left << "FilePath";
    cout << std::setw(12) << "FileOff";
    cout << std::setw(12) << "SecIndex";
    cout << std::setw(12) << "secOffset";
    cout << std::setw(18) << "secName";
    cout << std::setw(38) << "isPE";
    cout << endl;

    SetConsoleTextAttribute(hConsole, 15);
    cout.flags(f);
}

void printfunction(const vector<file_info>& all_file_info)
{
    vector<file_info>::const_iterator it;

    string::size_type maxlen = 0;

    for (it = all_file_info.begin(); it != all_file_info.end(); it++) 
    {
        if (it->filepath.size() > maxlen) maxlen = it->filepath.size();
    }

    //cout << "Maxlen is : " << maxlen << endl;

    //if (maxlen > 100) maxlen = 90;
    if (maxlen < 50) maxlen = 90;

    banner();

    std::ios_base::fmtflags f(cout.flags());

    print_header(maxlen);


    for (it = all_file_info.begin(); it != all_file_info.end(); it++) 
    {
        cout.flags(f);
        cout << std::setw(maxlen + 5) << std::left << (*it).filepath;
        cout << std::setw(12) << std::uppercase << std::hex << (*it).fileoffset;
        cout << std::setw(12) << (*it).sectionindex;
        cout << std::setw(12) << (*it).sectionoffset;
        cout << std::setw(18) << (*it).sectionName;
        cout << std::setw(38) << (*it).isPE;
        cout << endl;
    }
    cout.flags(f);
}

BOOL checkString(const string pathTosearch, const string stringTosearch, BOOL isUnicode, vector<file_info>& all_file_info, BOOL stream)
{
    //cout << pathTosearch << endl;
    if (checkFile(pathTosearch) == -1) 
    {
        //cout << "file or path: " << pathTosearch << " does not exist." << endl;
        return false;
    }
    if (checkFile(pathTosearch) == 0)
    {
        //cout << "calling search for file" << endl;
        searchString(pathTosearch, stringTosearch, isUnicode, all_file_info, false, stream);
        return true;
    }
    else if (checkFile(pathTosearch) == 1)
    {
        //cout << "calling search for directory" << endl;
        searchString(pathTosearch, stringTosearch, isUnicode, all_file_info, true, stream);
        return true;
    }

    //cout << "None matched: " << pathTosearch << endl;
    return false;
}


void sortfunction(vector<file_info> &all_file_info, int predicate)
{
    //cout << "Predicate is : " << predicate << endl;

    switch (predicate)
    {
    case 0:
        sort(all_file_info.begin(), all_file_info.end(), compare_filepath);
        break;
    case 1:
        sort(all_file_info.begin(), all_file_info.end(), compare_fileoffset);
        break;
    case 2:
        sort(all_file_info.begin(), all_file_info.end(), compare_secIndex);
        break;
    case 3:
        sort(all_file_info.begin(), all_file_info.end(), compare_secOffset);
        break;
    case 4:
        sort(all_file_info.begin(), all_file_info.end(), compare_secName);
        break;
    case 5:
        sort(all_file_info.begin(), all_file_info.end(), compare_isPE);
        break;
    default:
        cout << "Please provide valid sort parameter." << endl;
    }
}

int main(int argc, char **argv)
{
    if (argc < 4) 
    {
        banner();
        info_banner();
        return 1;
    }

    vector<file_info> all_file_info;

    bool sortResult = false;
    if (argv[1] == string("-au") || argv[1] == string("-ua"))
    {
        if (argv[2] == string("-s")) sortResult = true;

        if (sortResult && argc >= 6) 
        {
            checkString(argv[4], argv[5], 0, all_file_info, FALSE);
            checkString(argv[4], argv[5], 1, all_file_info, FALSE);
            sortfunction(all_file_info, atoi(argv[3]));
            cout << endl; // finish status line
            printfunction(all_file_info);
        }
        else 
        {
            banner();
            print_header(90);
            checkString(argv[2], argv[3], 0, all_file_info, TRUE);
            checkString(argv[2], argv[3], 1, all_file_info, TRUE);
        }

        return 0;
    }

    if((argv[1] == "-a" || argv[2] == "-a") && (argv[1] == "-u" || argv[2] == "-u") && argc >= 5)
    {
        if (argv[3] == string("-s")) sortResult = true;

        if (sortResult && argc >= 7)
        {
            checkString(argv[5], argv[6], 0, all_file_info, FALSE);
            checkString(argv[5], argv[6], 1, all_file_info, FALSE);
            sortfunction(all_file_info, atoi(argv[3]));
            cout << endl; // finish status line
            printfunction(all_file_info);
        }
        else
        {
            banner();
            print_header(90);
            checkString(argv[3], argv[4], 0, all_file_info, TRUE);
            checkString(argv[3], argv[4], 1, all_file_info, TRUE);
        }

        return 0;
    }


    if (argv[1] == string("-a"))
    {
        if (argv[2] == string("-s")) sortResult = true;

        if (sortResult && argc >= 6)
        {
            checkString(argv[4], argv[5], 0, all_file_info, FALSE);
            sortfunction(all_file_info, atoi(argv[3]));
            cout << endl; // finish status line
            printfunction(all_file_info);
        }
        else
        {
            banner();
            print_header(90);
            checkString(argv[2], argv[3], 0, all_file_info, TRUE);
        }

        return 0;
    }

    if (argv[1] == string("-u"))
    {
        if (argv[2] == string("-s")) sortResult = true;

        if (sortResult && argc >= 6)
        {
            checkString(argv[4], argv[5], 1, all_file_info, FALSE);
            sortfunction(all_file_info, atoi(argv[3]));
            cout << endl; // finish status line
            printfunction(all_file_info);
        }
        else
        {
            banner();
            print_header(90);
            checkString(argv[2], argv[3], 1, all_file_info, TRUE);
        }

        return 0;
    }
}
