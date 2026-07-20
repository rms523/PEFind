#include <gtest/gtest.h>

#include <string>
#include <vector>

#if !defined(_WIN32)
#include <cstdio>
#include <unistd.h>
#endif

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>
#endif

#include "algo.h"
#include "file_info.h"
#include "pe_hdrs_helper.h"
#include "search_helper.h"

namespace {

class TempFile {
public:
    explicit TempFile(const std::vector<BYTE>& bytes)
    {
#if defined(_WIN32)
        wchar_t tempDir[MAX_PATH]{};
        wchar_t tempFile[MAX_PATH]{};
        if (GetTempPathW(MAX_PATH, tempDir) == 0 ||
            GetTempFileNameW(tempDir, L"pef", 0, tempFile) == 0) {
            ADD_FAILURE() << "Failed to get temp file path.";
            return;
        }

        HANDLE handle = CreateFileW(tempFile, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                                    FILE_ATTRIBUTE_TEMPORARY, nullptr);
        if (handle == INVALID_HANDLE_VALUE) {
            ADD_FAILURE() << "Failed to create temp file.";
            return;
        }

        DWORD written = 0;
        const BOOL ok = WriteFile(handle, bytes.data(), static_cast<DWORD>(bytes.size()), &written, nullptr);
        CloseHandle(handle);
        EXPECT_TRUE(ok);
        EXPECT_EQ(written, static_cast<DWORD>(bytes.size()));

        const int length = WideCharToMultiByte(CP_UTF8, 0, tempFile, -1, nullptr, 0, nullptr, nullptr);
        if (length <= 0) {
            ADD_FAILURE() << "Failed to convert temp file path.";
            return;
        }
        path_.assign(static_cast<size_t>(length - 1), '\0');
        WideCharToMultiByte(CP_UTF8, 0, tempFile, -1, path_.data(), length, nullptr, nullptr);
#else
        char tmpl[] = "/tmp/pefindXXXXXX";
        const int fd = mkstemp(tmpl);
        if (fd < 0) {
            ADD_FAILURE() << "Failed to create temp file.";
            return;
        }
        path_ = tmpl;

        const ssize_t written = write(fd, bytes.data(), bytes.size());
        close(fd);
        if (written != static_cast<ssize_t>(bytes.size())) {
            ADD_FAILURE() << "Failed to write temp file.";
        }
#endif
    }

    ~TempFile()
    {
        if (path_.empty()) {
            return;
        }
#if defined(_WIN32)
        DeleteFileA(path_.c_str());
#else
        ::remove(path_.c_str());
#endif
    }

    std::string utf8Path() const
    {
        return path_;
    }

private:
    std::string path_;
};

std::vector<uint64_t> offsets(const std::vector<file_info>& matches)
{
    std::vector<uint64_t> result;
    for (const auto& match : matches) {
        result.push_back(match.fileoffset);
    }
    return result;
}

} // namespace

TEST(PeProductionHelpers, RejectTruncatedNtOffset)
{
    std::vector<BYTE> bytes(sizeof(IMAGE_DOS_HEADER), 0);
    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(bytes.data());
    dos->e_magic = IMAGE_DOS_SIGNATURE;
    dos->e_lfanew = 4096;

    int sectionIndex = 0;
    EXPECT_EQ(get_nt_hrds(bytes.data(), bytes.size()), nullptr);
    EXPECT_EQ(get_nt_hrds64(bytes.data(), bytes.size()), nullptr);
    EXPECT_EQ(get_section_hdr(bytes.data(), bytes.size(), 0, sectionIndex), nullptr);
}

TEST(ScannerProduction, TextAndHexSearchReturnSameMatchShape)
{
    TempFile file(std::vector<BYTE>{'X', 'A', 'B', 'A', 'B'});
    ASSERT_FALSE(file.utf8Path().empty());
    std::vector<file_info> textMatches;
    std::vector<file_info> hexMatches;

    searchStringinFile(file.utf8Path(), "AB", FALSE, textMatches);

    HexPattern hexPattern = parse_hex_pattern("41 42");
    ASSERT_TRUE(hexPattern.isValid);
    searchStringinFile(file.utf8Path(), "41 42", FALSE, hexMatches,
                       FALSE, FALSE, &hexPattern);

    EXPECT_EQ(offsets(textMatches), offsets(hexMatches));
    ASSERT_EQ(textMatches.size(), 2u);
    ASSERT_EQ(hexMatches.size(), 2u);
    EXPECT_EQ(textMatches[0].isPE, hexMatches[0].isPE);
    EXPECT_EQ(textMatches[0].sectionName, hexMatches[0].sectionName);
}

TEST(ScannerProduction, ResultCallbackReceivesMatchesAsFileCompletes)
{
    TempFile file(std::vector<BYTE>{'X', 'A', 'B', 'A', 'B'});
    ASSERT_FALSE(file.utf8Path().empty());

    std::vector<file_info> matches;
    std::vector<uint64_t> emittedOffsets;
    ScanStats stats;
    searchStringinFile(file.utf8Path(), "AB", FALSE, matches, FALSE, FALSE, nullptr,
                       [&emittedOffsets](const file_info& match) {
                           emittedOffsets.push_back(match.fileoffset);
                       }, &stats);

    EXPECT_EQ(emittedOffsets, offsets(matches));
    EXPECT_EQ(emittedOffsets, (std::vector<uint64_t>{1, 3}));
    EXPECT_EQ(stats.filesScanned(), 1u);
    EXPECT_EQ(stats.filesWithMatches(), 1u);
    EXPECT_EQ(stats.matchesFound, 2u);
    EXPECT_EQ(stats.filesWithErrors(), 0u);
}
