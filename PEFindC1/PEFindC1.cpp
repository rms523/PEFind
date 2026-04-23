// PEFindC1.cpp : This file contains the 'main' function. Program execution begins and ends there.
//
#include <algorithm>
#include <iostream>
#include <iomanip>
#include <Windows.h>
#include <map>
#include <vector>

#include "search_helper.h"
#include "file_info.h"

using std::cout;
using std::endl;

enum SearchMode { SM_ASCII = 1, SM_UNICODE = 2 };

struct CliArgs {
    int mode = SM_ASCII | SM_UNICODE; // default: both
    int sortPredicate = -1;       // -1 = no sorting
    bool caseInsensitive = false; // -ci / --nocase flag
    bool countMode = false;       // -c / --count flag
    size_t nthMatch = 0;          // 0 = show all matches, N = only Nth match per file
    string hexString;             // --hex <pattern> argument
    string targetPath;            // directory or file path
    string searchString;          // the string to search for (text mode)
};

void info_banner()
{
    cout << "Usage: PEFindC1.exe [options] <path> <search_string>" << endl << endl;
    cout << "Options:" << endl;
    cout << "  -a or --ascii                           search for ASCII string" << endl;
    cout << "  -u or --unicode                         search for Unicode string" << endl;
    cout << "  -au or --both                           search for both ASCII and Unicode strings (default)" << endl;
    cout << "  -ci or --nocase                         case-insensitive search" << endl;
    cout << "  -c or --count                           show match counts per file instead of individual matches" << endl;
    cout << "  -n <n> or --nth <n>                     show only the 1-based Nth match from each file" << endl;
    cout << "  --hex <pattern>                         search for hex pattern (e.g. \"4D5A9000\" or \"xx xx 90 00\")" << endl;
    cout << "  -s <n> or --sort <n>                    sort results by predicate:" << endl;
    cout << "      0 = filepath, 1 = fileOffset, 2 = sectionIndex," << endl;
    cout << "      3 = sectionOffset, 4 = sectionName, 5 = isPE" << endl;
    cout << "  -h or --help                            show this help message" << endl;
    cout << endl;
    cout << "Examples:" << endl;
    cout << "  PEFindC1.exe -u E:\\tmp \"Setup\"" << endl;
    cout << "  PEFindC1.exe -a -ci E:\\tmp \"setup\"" << endl;
    cout << "  PEFindC1.exe --hex \"4D5A9000\" E:\\tmp" << endl;
    cout << "  PEFindC1.exe --hex \"xx xx 90 00\" E:\\tmp" << endl;
    cout << "  PEFindC1.exe -n 1 E:\\tmp \"Setup\"" << endl;
    cout << "  PEFindC1.exe -a -c \"Setup\" E:\\tmp" << endl;
    cout << "  PEFindC1.exe --hex \"4D5A9000\" -c E:\\tmp" << endl;
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

// Count-mode output: one row per file with match count
void print_count_mode(const vector<file_info>& all_file_info)
{
    banner();

    size_t maxlen = 0;
    for (const auto& fi : all_file_info) {
        if (fi.filepath.size() > maxlen) maxlen = fi.filepath.size();
    }
    if (maxlen < 40) maxlen = 40;

    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    FlushConsoleInputBuffer(hConsole);
    SetConsoleTextAttribute(hConsole, 10);  // Light Green

    cout << std::setw(maxlen + 5) << std::left << "FilePath";
    cout << std::setw(12) << "Matches";
    cout << std::setw(18) << "SecName";
    cout << endl;

    SetConsoleTextAttribute(hConsole, 15);

    for (const auto& fi : all_file_info) {
        cout << std::setw(maxlen + 5) << std::left << fi.filepath;
        cout << std::setw(12) << fi.stringTosearch;  // match count stored here in count mode
        cout << std::setw(18) << fi.sectionName;
        cout << endl;
    }
}

// Forward declarations for case-insensitive-aware search dispatchers
static void checkStringFile(const string& path, const string& str, BOOL isUnicode, 
                            vector<file_info>& results, BOOL stream, BOOL ci,
                            BOOL countMode = FALSE, const HexPattern* hexPat = nullptr);
static void checkStringDir(const string& dir, const string& str, BOOL isUnicode,
                           vector<file_info>& results, BOOL stream, BOOL ci,
                           BOOL countMode = FALSE, const HexPattern* hexPat = nullptr);

BOOL checkString(const string pathTosearch, const string stringTosearch, BOOL isUnicode, 
                 vector<file_info>& all_file_info, BOOL isDir, BOOL stream, BOOL caseInsensitive,
                 BOOL countMode, const HexPattern* hexPat)
{
    if (checkFile(pathTosearch.c_str()) == -1) {
        return false;
    }
    if (checkFile(pathTosearch.c_str()) == 0) {
        checkStringFile(pathTosearch, stringTosearch, isUnicode, all_file_info, stream, caseInsensitive, countMode, hexPat);
        return true;
    } else if (checkFile(pathTosearch.c_str()) == 1) {
        checkStringDir(pathTosearch, stringTosearch, isUnicode, all_file_info, stream, caseInsensitive, countMode, hexPat);
        return true;
    }
    return false;
}

// File-level search with case-insensitive and hex/count support
static void checkStringFile(const string& path, const string& str, BOOL isUnicode, 
                            vector<file_info>& results, BOOL stream, BOOL ci,
                            BOOL countMode, const HexPattern* hexPat)
{
    searchStringinFile(path, str, isUnicode, results, stream, ci, countMode, hexPat);
}

// Directory-level search with case-insensitive and hex/count support (forwards to recursive calls)
static void checkStringDir(const string& dir, const string& str, BOOL isUnicode,
                           vector<file_info>& results, BOOL stream, BOOL ci,
                           BOOL countMode, const HexPattern* hexPat)
{
    try {
        searchStringInDir(dir, str, isUnicode, results, stream, ci, countMode, hexPat);
    } catch (std::exception const& e) {
        std::cout << "Exception: " << e.what() << std::endl;
    }
}

static void filter_nth_match_per_file(vector<file_info>& all_file_info, size_t nthMatch)
{
    if (nthMatch == 0 || all_file_info.empty()) return;

    std::map<string, vector<file_info>> matchesByFile;
    for (const auto& fi : all_file_info) {
        matchesByFile[fi.filepath].push_back(fi);
    }

    vector<file_info> filtered;
    for (auto& entry : matchesByFile) {
        auto& matches = entry.second;
        std::stable_sort(matches.begin(), matches.end(), compare_fileoffset);
        if (nthMatch <= matches.size()) {
            filtered.push_back(matches[nthMatch - 1]);
        }
    }

    all_file_info.swap(filtered);
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
static bool parse_args(int argc, char** argv, CliArgs& out)
{
    vector<string> positional;

    for (int i = 1; i < argc; ++i) {
        string arg = argv[i];

        if (arg == "-h" || arg == "--help") {
            banner();
            info_banner();
            return false;
        }
        else if (arg == "-a" || arg == "--ascii") {
            out.mode = SM_ASCII;
        }
        else if (arg == "-u" || arg == "--unicode") {
            out.mode = SM_UNICODE;
        }
        else if (arg == "-au" || arg == "--both" || arg == "-ua") {
            out.mode = SM_ASCII | SM_UNICODE;
        }
        else if (arg == "-ci" || arg == "--nocase") {
            out.caseInsensitive = true;
        }
        else if (arg == "-c" || arg == "--count") {
            out.countMode = true;
        }
        else if ((arg == "-n" || arg == "--nth") && i + 1 < argc) {
            ++i;
            int n = atoi(argv[i]);
            if (n < 1) return false;
            out.nthMatch = static_cast<size_t>(n);
        }
        else if (arg == "--hex" && i + 1 < argc) {
            ++i; // consume next token as hex string
            out.hexString = argv[i];
        }
        else if ((arg == "-s" || arg == "--sort") && i + 1 < argc) {
            ++i;
            out.sortPredicate = atoi(argv[i]);
        }
        else {
            positional.push_back(arg);
        }
    }

    // Validate based on mode
    if (!out.hexString.empty()) {
        // Hex mode: need at least path
        if (positional.size() < 1) return false;
        out.targetPath = positional[0];
    } else {
        // Text mode: need path + search string
        if (positional.size() < 2) return false;
        out.targetPath = positional[0];
        out.searchString = positional[1];
    }

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

    // Determine search mode: hex pattern vs text-based (ASCII/Unicode)
    HexPattern hexPat;
    bool isHexMode = !args.hexString.empty();

    if (isHexMode) {
        hexPat = parse_hex_pattern(args.hexString);
        if (hexPat.bytes.empty()) {
            cout << "Error: could not parse hex pattern \"" << args.hexString << "\"" << endl;
            return 1;
        }
    }

    // Check if target is a file or directory
    BOOL isDir = (checkFile(args.targetPath.c_str()) == 1);

    // In count and nth-match modes, collect results then print at end.
    BOOL stream = (args.sortPredicate < 0) && !args.countMode && args.nthMatch == 0;

    if (isHexMode) {
        // Hex pattern mode: search for raw bytes (ignore -a/-u flags)
        checkString(args.targetPath, args.hexString, FALSE, all_file_info, isDir, stream, 
                    FALSE, args.countMode, &hexPat);  // caseInsensitive doesn't apply to hex mode
    } else {
        // Text search mode: use -a/-u flags as before
        bool doAscii = (args.mode & static_cast<int>(SM_ASCII)) != 0;
        bool doUnicode = (args.mode & static_cast<int>(SM_UNICODE)) != 0;

        if (!isDir && !doAscii && !doUnicode) {
            cout << "Please specify at least one search mode: -a, -u, or -au." << endl;
            return 1;
        }

        if (doAscii && doUnicode) {
            checkString(args.targetPath, args.searchString, FALSE, all_file_info, isDir, stream, 
                        args.caseInsensitive, args.countMode, nullptr);
            checkString(args.targetPath, args.searchString, TRUE,  all_file_info, isDir, stream, 
                        args.caseInsensitive, args.countMode, nullptr);
        } else if (doAscii) {
            checkString(args.targetPath, args.searchString, FALSE, all_file_info, isDir, stream, 
                        args.caseInsensitive, args.countMode, nullptr);
        } else if (doUnicode) {
            checkString(args.targetPath, args.searchString, TRUE,  all_file_info, isDir, stream, 
                        args.caseInsensitive, args.countMode, nullptr);
        }
    }

    if (!args.countMode) {
        filter_nth_match_per_file(all_file_info, args.nthMatch);
    }

    // Sort results if requested
    if (args.sortPredicate >= 0 && !all_file_info.empty()) {
        cout << endl;
        sortfunction(all_file_info, args.sortPredicate);
    }

    // Print results based on mode
    if (!all_file_info.empty()) {
        if (args.countMode) {
            print_count_mode(all_file_info);
        } else {
            printfunction(all_file_info);
        }
    }

    return 0;
}
