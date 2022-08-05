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


BOOL checkString(const string, const string, BOOL, vector<file_info> &);
void checkString();

void checkString() {}

void info_banner()
{
    cout << "-a or --ascii                           search for ascii string" << endl;
    cout << "-u or --unicode                         search for unicode string" << endl;
    cout << "-au or (--ascii and --unicode)          search for both ascii and unicode string" << endl;
    cout << "-ci or --nocase                         search for case insensitive string" << endl;
    cout << "--h or --hex                            search for hex string" << endl;
    cout << "--w or --wildcard                       search for hex string with wildcard using xx for byte" << endl;
    cout << "Example: " << endl;
    cout << "PEFind.exe - a / -u / -au / -ci / -h / -w search_dir search_str" << endl;
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

    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    FlushConsoleInputBuffer(hConsole);
    SetConsoleTextAttribute(hConsole, 9);  //Light Green
    cout << std::setw(maxlen+10) << std::left << "FilePath " << std::setw(12) << "FileOff" << std::setw(9) << "SecIndex" << std::setw(12)
        << "secOffset" << std::setw(10) << "secName" << std::setw(40) << "isPE" << endl;

    SetConsoleTextAttribute(hConsole, 15);

    for (it = all_file_info.begin(); it != all_file_info.end(); it++) 
    {
        cout << std::setw(maxlen+10) << std::left << (*it).filepath << std::setw(12) << std::uppercase << std::hex << (*it).fileoffset <<
            std::setw(9) <<  (*it).sectionindex << std::setw(12) << (*it).sectionoffset << std::setw(10) << (*it).sectionName 
            << std::setw(40) << (*it).isPE << endl;  
    }

}

BOOL checkString(const string pathTosearch, const string stringTosearch, BOOL isUnicode, vector<file_info>& all_file_info)
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
        searchString(pathTosearch, stringTosearch, isUnicode, all_file_info, false);
        return true;
    }
    else if (checkFile(pathTosearch) == 1)
    {
        //cout << "calling search for directory" << endl;
        searchString(pathTosearch, stringTosearch, isUnicode, all_file_info, true);
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

    BOOL sortResult = false;
    if (argv[1] == string("-au") || argv[1] == string("-ua"))
    {
        if (argv[2] == string("-s")) sortResult = true;

        if (sortResult && argc >= 6) 
        {
            checkString(argv[4], argv[5], 0, all_file_info);
            checkString(argv[4], argv[5], 1, all_file_info);
            sortfunction(all_file_info, atoi(argv[3]));
        }
        else 
        {
            checkString(argv[2], argv[3], 0, all_file_info);
            checkString(argv[2], argv[3], 1, all_file_info);
        }

        printfunction(all_file_info);

        return 0;
    }

    if((argv[1] == "-a" || argv[2] == "-a") && (argv[1] == "-u" || argv[2] == "-u") && argc >= 5)
    {
        if (argv[3] == string("-s")) sortResult = true;

        if (sortResult && argc >= 7)
        {
            checkString(argv[5], argv[6], 0, all_file_info);
            checkString(argv[5], argv[6], 1, all_file_info);
            sortfunction(all_file_info, atoi(argv[3]));
        }
        else
        {
            checkString(argv[3], argv[4], 0, all_file_info);
            checkString(argv[3], argv[4], 1, all_file_info);
        }

        printfunction(all_file_info);

        return 0;
    }


    if (argv[1] == string("-a"))
    {
        cout << "In ascii" << endl;
        if (argv[2] == string("-s")) sortResult = true;

        if (sortResult && argc >= 6)
        {
            checkString(argv[4], argv[5], 0, all_file_info);
            sortfunction(all_file_info, atoi(argv[3]));
        }
        else
        {
            checkString(argv[2], argv[3], 0, all_file_info);
        }

        printfunction(all_file_info);

        return 0;
    }

    if (argv[1] == string("-u"))
    {
        if (argv[2] == string("-s")) sortResult = true;

        if (sortResult && argc >= 6)
        {
            checkString(argv[4], argv[5], 1, all_file_info);
            sortfunction(all_file_info, atoi(argv[3]));
        }
        else
        {
            checkString(argv[2], argv[3], 1, all_file_info);
        }

        printfunction(all_file_info);

        return 0;
    }
}