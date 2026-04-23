#pragma once

#include<Windows.h>
#include "file_info.h"

using std::vector;

// Hex/wildcard pattern structure for --hex/--wildcard mode
struct HexPattern {
    vector<BYTE> bytes;      // byte values (valid only if !isWildcard[i])
    vector<bool> isWildcard;  // true if this position matches any byte
    
    size_t size() const { return bytes.size(); }
};

// Parse hex string into HexPattern. Supports:
//   "4D5A9000" → exact bytes [0x4D, 0x5A, 0x90, 0x00]
//   "xx xx 90 00" → wildcard + wildcard + exact + exact
HexPattern parse_hex_pattern(const string& hexStr);

void searchString(const string , const string, BOOL, vector<file_info>&, BOOL isDir, BOOL stream, 
                  BOOL caseInsensitive = FALSE, BOOL countMode = FALSE, const HexPattern* hexPat = nullptr);
void searchStringInDir(const std::string& directory, const string stringTosearch, BOOL isUnicode, 
                       vector<file_info>& all_file_info, BOOL stream, BOOL caseInsensitive = FALSE,
                       BOOL countMode = FALSE, const HexPattern* hexPat = nullptr);
