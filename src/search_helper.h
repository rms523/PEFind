#pragma once

#include <cstddef>
#include <functional>
#include <unordered_set>
#include <windows.h>
#include "file_info.h"
#include "algo.h"

using std::vector;

using ResultCallback = std::function<void(const file_info&)>;

struct ScanStats {
    std::unordered_set<string> scannedFiles;
    std::unordered_set<string> matchedFiles;
    std::unordered_set<string> failedFiles;
    std::size_t matchesFound = 0;

    void recordFile(const string& path, std::size_t matchCount)
    {
        scannedFiles.insert(path);
        matchesFound += matchCount;
        if (matchCount != 0) {
            matchedFiles.insert(path);
        }
    }

    void recordFailure(const string& path)
    {
        failedFiles.insert(path);
    }

    std::size_t filesScanned() const { return scannedFiles.size(); }
    std::size_t filesWithMatches() const { return matchedFiles.size(); }
    std::size_t filesWithErrors() const { return failedFiles.size(); }
};

void searchStringinFile(const string pathTosearch, const string stringTosearch, BOOL isUnicode,
                        vector<file_info>& all_file_info, BOOL caseInsensitive = FALSE,
                        BOOL countMode = FALSE, const HexPattern* hexPat = nullptr,
                        const ResultCallback& onResult = ResultCallback{},
                        ScanStats* stats = nullptr);

void searchStringInDir(const std::string& directory, const string stringTosearch, BOOL isUnicode,
                       vector<file_info>& all_file_info, BOOL caseInsensitive = FALSE,
                       BOOL countMode = FALSE, const HexPattern* hexPat = nullptr,
                       const ResultCallback& onResult = ResultCallback{},
                       ScanStats* stats = nullptr);
