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

enum class SearchMode { Ascii = 1, Unicode = 2 };

struct CliArgs {
    SearchMode mode = SearchMode::Ascii | SearchMode::Unicode; // default: both
    int sortPredicate = -1;       // -1 = no sorting
    string targetPath;            // directory or file path
    string searchString;          // the string to search for
};

void info_banner()
{
    cout << "Usage: PEFindC1.exe [options] <path> <search_string>" << endl << endl;
    cout << "Options:" << endl;
    cout << "  -a or --ascii                           search for ASCII string" << endl;
    cout << "  -u or --unicode                         search for Unicode string" << endl;
    cout << "  -au or --both                           search for both ASCII and Unicode strings (default)" << endl;
    cout << "  -s <n> or --sort <n>                    sort results by predicate:" << endl;
    cout << "      0 = filepath, 1 = fileOffset, 2 = sectionIndex," << endl;
    cout << "      3 = sectionOffset, 4 = sectionName, 5 = isPE" << endl;
    cout << "  -h or --help                            show this help message" << endl;
    cout << endl;
    cout << "Examples:" << endl;
    cout << "  PEFindC1.exe -u E:\\tmp \"Setup\"" << endl;
    cout << "  PEFindC1.exe -a -s 1 E:\\tmp \"Setup\"" << endl;
    cout << "  PEFindC1.exe -au -s 2 E:\\tmp \"Setup\"" << endl;
}

void banner()
{
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    FlushConsoleInputBuffer(hConsole);
    SetConsoleTextAttribute(hConsole, 10);  // Green

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
    SetConsoleTextAttribute(hConsole, 10);  // Light Green
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
    size_t maxlen = 0;

    for (const auto& fi : all_file_info) {
        if (fi.filepath.size() > maxlen) maxlen = fi.filepath.size();
    }

    if (maxlen < 50) maxlen = 90;

    banner();

    std::ios_base::fmtflags f(cout.flags());
    print_header(maxlen);

    for (const auto& fi : all_file_info) {
        cout.flags(f);
        cout << std::setw(maxlen + 5) << std::left << fi.filepath;
        cout << std::setw(12) << std::uppercase << std::hex << fi.fileoffset;
        cout << std::setw(12) << fi.sectionindex;
        cout << std::setw(12) << fi.sectionoffset;
        cout << std::setw(18) << fi.sectionName;
        cout << std::setw(38) << fi.isPE;
        cout << endl;
    }
    cout.flags(f);
}

BOOL checkString(const string pathTosearch, const string stringTosearch, BOOL isUnicode, vector<file_info>& all_file_info, BOOL stream)
{
    if (checkFile(pathTosearch) == -1) {
        return false;
    }
    if (checkFile(pathTosearch) == 0) {
        searchString(pathTosearch, stringTosearch, isUnicode, all_file_info, false, stream);
        return true;
    } else if (checkFile(pathTosearch) == 1) {
        searchString(pathTosearch, stringTosearch, isUnicode, all_file_info, true, stream);
        return true;
    }
    return false;
}

void sortfunction(vector<file_info>& all_file_info, int predicate)
{
    switch (predicate) {
    case 0: sort(all_file_info.begin(), all_file_info.end(), compare_filepath); break;
    case 1: sort(all_file_info.begin(), all_file_info.end(), compare_fileoffset); break;
    case 2: sort(all_file_info.begin(), all_file_info.end(), compare_secIndex); break;
    case 3: sort(all_file_info.begin(), all_file_info.end(), compare_secOffset); break;
    case 4: sort(all_file_info.begin(), all_file_info.end(), compare_secName); break;
    case 5: sort(all_file_info.begin(), all_file_info.end(), compare_isPE); break;
    default: cout << "Please provide valid sort parameter (0-5)." << endl; break;
    }
}

// Parse command-line arguments into CliArgs struct.
// Returns true on success, false if help was requested or args are invalid.
static bool parse_args(int argc, char** argv, CliArgs& out)
{
    // Collect all non-flag tokens (positional args) in order
    vector<string> positional;

    for (int i = 1; i < argc; ++i) {
        string arg = argv[i];

        if (arg == "-h" || arg == "--help") {
            banner();
            info_banner();
            return false; // signal: show help and exit
        }
        else if (arg == "-a" || arg == "--ascii") {
            out.mode = SearchMode::Ascii;
        }
        else if (arg == "-u" || arg == "--unicode") {
            out.mode = SearchMode::Unicode;
        }
        else if (arg == "-au" || arg == "--both" || arg == "-ua") {
            out.mode = SearchMode::Ascii | SearchMode::Unicode;
        }
        else if ((arg == "-s" || arg == "--sort") && i + 1 < argc) {
            ++i; // consume next token as sort value
            out.sortPredicate = atoi(argv[i]);
        }
        else {
            positional.push_back(arg);
        }
    }

    if (positional.size() < 2) return false; // not enough args

    out.targetPath = positional[0];
    out.searchString = positional[1];
    return true;
}

int main(int argc, char** argv)
{
    CliArgs args{};
    if (!parse_args(argc, argv, args)) {
        banner();
        info_banner();
        return 1;
    }

    vector<file_info> all_file_info;

    // Determine which search modes to run based on the mode flag
    bool doAscii = (static_cast<int>(args.mode) & static_cast<int>(SearchMode::Ascii)) != 0;
    bool doUnicode = (static_cast<int>(args.mode) & static_cast<int>(SearchMode::Unicode)) != 0;

    // Check if target is a file or directory
    BOOL isDir = (checkFile(args.targetPath) == 1);

    if (!isDir && !doAscii && !doUnicode) {
        cout << "Please specify at least one search mode: -a, -u, or -au." << endl;
        return 1;
    }

    // Run searches — in streaming mode (no sort), results print as they're found.
    // In non-streaming mode (with sorting), we collect everything then print at the end.
    BOOL stream = (args.sortPredicate < 0);

    if (doAscii && doUnicode) {
        checkString(args.targetPath, args.searchString, FALSE, all_file_info, stream);
        checkString(args.targetPath, args.searchString, TRUE, all_file_info, stream);
    } else if (doAscii) {
        checkString(args.targetPath, args.searchString, FALSE, all_file_info, stream);
    } else if (doUnicode) {
        checkString(args.targetPath, args.searchString, TRUE, all_file_info, stream);
    }

    // Sort results if requested
    if (args.sortPredicate >= 0 && !all_file_info.empty()) {
        cout << endl; // finish any status line from streaming mode
        sortfunction(all_file_info, args.sortPredicate);
        printfunction(all_file_info);
    } else if (!stream && !all_file_info.empty()) {
        // No sorting but still non-streaming — shouldn't happen with current logic,
        // but just in case: print header + results.
        banner();
        size_t maxlen = 0;
        for (const auto& fi : all_file_info) {
            if (fi.filepath.size() > maxlen) maxlen = fi.filepath.size();
        }
        if (maxlen < 50) maxlen = 90;
        print_header(maxlen);
        std::ios_base::fmtflags f(cout.flags());
        for (const auto& fi : all_file_info) {
            cout.flags(f);
            cout << std::setw(maxlen + 5) << std::left << fi.filepath;
            cout << std::setw(12) << std::uppercase << std::hex << fi.fileoffset;
            cout << std::setw(12) << fi.sectionindex;
            cout << std::setw(12) << fi.sectionoffset;
            cout << std::setw(18) << fi.sectionName;
            cout << std::setw(38) << fi.isPE;
            cout << endl;
        }
    }

    return 0;
}
