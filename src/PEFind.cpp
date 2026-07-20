// PEFind.cpp : main entry point for the PEFind CLI.
//
#include <algorithm>
#include <cerrno>
#include <cstdlib>
#include <iostream>
#include <iomanip>
#include <Windows.h>
#include <map>
#include <unordered_map>
#include <vector>

#include "search_helper.h"
#include "file_info.h"

using std::cout;
using std::endl;

enum SearchMode { SM_ASCII = 1, SM_UNICODE = 2 };

struct CliArgs {
    bool showHelp = false;
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
    cout << "Usage:" << endl;
    cout << "  PEFind.exe [options] <path> <search_string>" << endl;
    cout << "  PEFind.exe [options] --hex <pattern> <path>" << endl;
    cout << endl;
    cout << "Options may appear in any order. In text mode, positional arguments must be" << endl;
    cout << "<path> then <search_string>. In hex mode, supply --hex <pattern> and <path>." << endl;
    cout << "Short flags use one dash (-a, -ci, -au); long flags use two (--ascii, --nocase)." << endl;
    cout << "--hex has no short form (-h is help)." << endl;
    cout << endl;
    cout << "Options:" << endl;
    cout << "  -a, --ascii                             search for ASCII string" << endl;
    cout << "  -u, --unicode                           search for Unicode string" << endl;
    cout << "  -au, -ua, --both                        search for both ASCII and Unicode (default)" << endl;
    cout << "  -ci, --nocase                           case-insensitive text search (ASCII/Unicode only)" << endl;
    cout << "  -c, --count                             show match counts per file instead of individual matches" << endl;
    cout << "  -n, --nth <n>                           show only the 1-based Nth match from each file" << endl;
    cout << "  --hex <pattern>                         search for hex pattern (e.g. \"4D5A9000\" or \"xx xx 90 00\")" << endl;
    cout << "  -s, --sort <n>                          sort results by predicate:" << endl;
    cout << "      0 = filepath, 1 = fileOffset, 2 = sectionIndex," << endl;
    cout << "      3 = sectionOffset, 4 = sectionName, 5 = isPE" << endl;
    cout << "  -h, --help                              show this help message" << endl;
    cout << endl;
    cout << "Examples:" << endl;
    cout << "  PEFind.exe -u E:\\tmp \"Setup\"" << endl;
    cout << "  PEFind.exe -u -s 1 E:\\tmp \"Setup\"" << endl;
    cout << "  PEFind.exe -au -ci -s 2 E:\\tmp \"Setup\"" << endl;
    cout << "  PEFind.exe -a -ci E:\\tmp \"setup\"" << endl;
    cout << "  PEFind.exe -n 1 E:\\tmp \"Setup\"" << endl;
    cout << "  PEFind.exe -c E:\\tmp \"Setup\"" << endl;
    cout << "  PEFind.exe --hex \"4D5A9000\" E:\\tmp" << endl;
    cout << "  PEFind.exe --hex \"xx xx 90 00\" E:\\tmp" << endl;
    cout << "  PEFind.exe --hex \"4D5A9000\" -c E:\\tmp" << endl;
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
    cout << "Welcome to PEFind" << endl << endl;
}

static std::size_t result_path_width(const vector<file_info>& all_file_info)
{
    size_t maxlen = 0;

    for (const auto& fi : all_file_info) {
        if (fi.filepath.size() > maxlen) maxlen = fi.filepath.size();
    }

    if (maxlen < 50) maxlen = 90;
    return maxlen;
}

static void print_header(std::size_t maxlen, bool includeMatchCount)
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
    if (includeMatchCount) {
        cout << std::setw(12) << "Matches";
    }
    cout << endl;

    SetConsoleTextAttribute(hConsole, 15);
    cout.flags(f);
}

static void print_row(const file_info& fi, std::size_t maxlen, bool includeMatchCount)
{
    std::ios_base::fmtflags f(cout.flags());
    cout << std::setw(maxlen + 5) << std::left << fi.filepath;
    cout << std::setw(12) << std::uppercase << std::hex << fi.fileoffset;
    cout << std::setw(12) << std::dec << fi.sectionindex;
    cout << std::setw(12) << std::uppercase << std::hex << fi.sectionoffset;
    cout << std::setw(18) << fi.sectionName;
    cout << std::setw(38) << fi.isPE;
    if (includeMatchCount) {
        cout << std::setw(12) << fi.stringTosearch;
    }
    cout << endl;
    cout.flags(f);
}

static void print_results(const vector<file_info>& all_file_info, bool includeMatchCount)
{
    banner();
    const size_t maxlen = result_path_width(all_file_info);

    print_header(maxlen, includeMatchCount);

    for (const auto& fi : all_file_info) {
        print_row(fi, maxlen, includeMatchCount);
    }
}

static void print_statistics(const ScanStats& stats, size_t resultRows)
{
    std::ios_base::fmtflags f(cout.flags());
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);

    cout << endl;
    SetConsoleTextAttribute(hConsole, 10);
    cout << "Statistics" << endl;
    SetConsoleTextAttribute(hConsole, 15);
    cout << "Files scanned: " << std::dec << stats.filesScanned() << endl;
    cout << "Files with matches: " << stats.filesWithMatches() << endl;
    cout << "Matches found: " << stats.matchesFound << endl;
    cout << "Result rows: " << resultRows << endl;
    cout << "Files with scan errors: " << stats.filesWithErrors() << endl;
    cout.flags(f);
}

class LiveResultPrinter {
public:
    explicit LiveResultPrinter(bool includeMatchCount) : includeMatchCount_(includeMatchCount) {}

    void print(const file_info& fi)
    {
        if (!started_) {
            banner();
            print_header(LIVE_PATH_WIDTH, includeMatchCount_);
            started_ = true;
        }

        print_row(fi, LIVE_PATH_WIDTH, includeMatchCount_);
    }

private:
    static constexpr std::size_t LIVE_PATH_WIDTH = 90;
    bool includeMatchCount_;
    bool started_ = false;
};

// Forward declarations for case-insensitive-aware search dispatchers
static void checkStringFile(const string& path, const string& str, BOOL isUnicode, 
                            vector<file_info>& results, BOOL ci,
                            BOOL countMode = FALSE, const HexPattern* hexPat = nullptr,
                            const ResultCallback& onResult = ResultCallback{},
                            ScanStats* stats = nullptr);
static void checkStringDir(const string& dir, const string& str, BOOL isUnicode,
                           vector<file_info>& results, BOOL ci,
                           BOOL countMode = FALSE, const HexPattern* hexPat = nullptr,
                           const ResultCallback& onResult = ResultCallback{},
                           ScanStats* stats = nullptr);

BOOL checkString(const string pathTosearch, const string stringTosearch, BOOL isUnicode, 
                 vector<file_info>& all_file_info, BOOL isDir, BOOL caseInsensitive,
                 BOOL countMode, const HexPattern* hexPat, const ResultCallback& onResult,
                 ScanStats* stats)
{
    if (!isDir) {
        checkStringFile(pathTosearch, stringTosearch, isUnicode, all_file_info,
                        caseInsensitive, countMode, hexPat, onResult, stats);
        return true;
    }

    checkStringDir(pathTosearch, stringTosearch, isUnicode, all_file_info,
                   caseInsensitive, countMode, hexPat, onResult, stats);
    return true;
}

// File-level search with case-insensitive and hex/count support
static void checkStringFile(const string& path, const string& str, BOOL isUnicode, 
                            vector<file_info>& results, BOOL ci,
                            BOOL countMode, const HexPattern* hexPat, const ResultCallback& onResult,
                            ScanStats* stats)
{
    searchStringinFile(path, str, isUnicode, results, ci, countMode, hexPat, onResult, stats);
}

// Directory-level search with case-insensitive and hex/count support (forwards to recursive calls)
static void checkStringDir(const string& dir, const string& str, BOOL isUnicode,
                           vector<file_info>& results, BOOL ci,
                           BOOL countMode, const HexPattern* hexPat, const ResultCallback& onResult,
                           ScanStats* stats)
{
    try {
        searchStringInDir(dir, str, isUnicode, results, ci, countMode, hexPat, onResult, stats);
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

static void merge_count_results_by_file(vector<file_info>& all_file_info)
{
    std::unordered_map<string, size_t> indexByPath;
    vector<file_info> merged;

    for (const auto& fi : all_file_info) {
        size_t count = 0;
        try {
            count = static_cast<size_t>(std::stoull(fi.stringTosearch));
        } catch (...) {
            count = 0;
        }

        auto existing = indexByPath.find(fi.filepath);
        if (existing == indexByPath.end()) {
            indexByPath[fi.filepath] = merged.size();
            merged.push_back(fi);
        } else {
            file_info& target = merged[existing->second];
            size_t current = 0;
            try {
                current = static_cast<size_t>(std::stoull(target.stringTosearch));
            } catch (...) {
                current = 0;
            }
            target.stringTosearch = std::to_string(current + count);
            if (fi.fileoffset < target.fileoffset) {
                target.sectionindex = fi.sectionindex;
                target.sectionoffset = fi.sectionoffset;
                target.sectionName = fi.sectionName;
                target.isPE = fi.isPE;
                target.fileoffset = fi.fileoffset;
            }
        }
    }

    all_file_info.swap(merged);
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
            out.showHelp = true;
            return true;
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
        else if (arg == "-n" || arg == "--nth") {
            if (i + 1 >= argc) return false;
            ++i;
            char* end = nullptr;
            errno = 0;
            unsigned long n = std::strtoul(argv[i], &end, 10);
            if (errno != 0 || end == argv[i] || *end != '\0' || n == 0) return false;
            out.nthMatch = static_cast<size_t>(n);
        }
        else if (arg == "--hex") {
            if (i + 1 >= argc) return false;
            ++i;
            out.hexString = argv[i];
        }
        else if (arg == "-s" || arg == "--sort") {
            if (i + 1 >= argc) return false;
            ++i;
            char* end = nullptr;
            errno = 0;
            long sortPredicate = std::strtol(argv[i], &end, 10);
            if (errno != 0 || end == argv[i] || *end != '\0' ||
                sortPredicate < 0 || sortPredicate > 5) {
                return false;
            }
            out.sortPredicate = static_cast<int>(sortPredicate);
        }
        else if (!arg.empty() && arg[0] == '-') {
            return false;
        }
        else {
            positional.push_back(arg);
        }
    }

    if (out.showHelp) return true;
    if (out.countMode && out.nthMatch != 0) return false;

    // Validate based on mode
    if (!out.hexString.empty()) {
        // Hex mode: need path only
        if (positional.size() != 1) return false;
        out.targetPath = positional[0];
    } else {
        // Text mode: need path + search string
        if (positional.size() != 2) return false;
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
    if (args.showHelp) {
        banner();
        info_banner();
        return 0;
    }

    vector<file_info> all_file_info;
    ScanStats scanStats;

    // Determine search mode: hex pattern vs text-based (ASCII/Unicode)
    HexPattern hexPat;
    bool isHexMode = !args.hexString.empty();

    if (isHexMode) {
        hexPat = parse_hex_pattern(args.hexString);
        if (!hexPat.isValid || hexPat.bytes.empty() || !hexPat.hasExactByte()) {
            cout << "Error: could not parse hex pattern \"" << args.hexString << "\"" << endl;
            return 1;
        }
    } else if (args.searchString.empty()) {
        cout << "Error: search string cannot be empty." << endl;
        return 1;
    }

    // Check if target is a file or directory
    int targetKind = checkFile(args.targetPath);
    if (targetKind == -1) {
        cout << "Error: file or path does not exist or cannot be accessed: " << args.targetPath << endl;
        return 1;
    }
    BOOL isDir = (targetKind == 1);

    const bool printLive = args.sortPredicate < 0 && !args.countMode && args.nthMatch == 0;
    LiveResultPrinter liveResults(false);
    ResultCallback onResult;
    if (printLive) {
        onResult = [&liveResults](const file_info& fi) {
            liveResults.print(fi);
        };
    }

    if (isHexMode) {
        // Hex pattern mode: search for raw bytes (ignore -a/-u flags)
        checkString(args.targetPath, args.hexString, FALSE, all_file_info, isDir,
                    FALSE, args.countMode, &hexPat, onResult,
                    &scanStats);  // caseInsensitive doesn't apply to hex mode
    } else {
        // Text search mode: use -a/-u flags as before
        bool doAscii = (args.mode & static_cast<int>(SM_ASCII)) != 0;
        bool doUnicode = (args.mode & static_cast<int>(SM_UNICODE)) != 0;

        if (!isDir && !doAscii && !doUnicode) {
            cout << "Please specify at least one search mode: -a, -u, or -au." << endl;
            return 1;
        }

        if (doAscii && doUnicode) {
            checkString(args.targetPath, args.searchString, FALSE, all_file_info, isDir,
                        args.caseInsensitive, args.countMode, nullptr, onResult, &scanStats);
            checkString(args.targetPath, args.searchString, TRUE,  all_file_info, isDir,
                        args.caseInsensitive, args.countMode, nullptr, onResult, &scanStats);
        } else if (doAscii) {
            checkString(args.targetPath, args.searchString, FALSE, all_file_info, isDir,
                        args.caseInsensitive, args.countMode, nullptr, onResult, &scanStats);
        } else if (doUnicode) {
            checkString(args.targetPath, args.searchString, TRUE,  all_file_info, isDir,
                        args.caseInsensitive, args.countMode, nullptr, onResult, &scanStats);
        }
    }

    if (!args.countMode) {
        filter_nth_match_per_file(all_file_info, args.nthMatch);
    } else {
        merge_count_results_by_file(all_file_info);
    }

    // Sort results if requested
    if (args.sortPredicate >= 0 && !all_file_info.empty()) {
        cout << endl;
        sortfunction(all_file_info, args.sortPredicate);
    }

    if (!printLive && !all_file_info.empty()) {
        print_results(all_file_info, args.countMode);
    }

    print_statistics(scanStats, all_file_info.size());

    return 0;
}
