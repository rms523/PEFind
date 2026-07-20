#include <gtest/gtest.h>

#include <string>
#include <vector>

#if !defined(_WIN32)
#include <cstdio>
#include <unistd.h>
#endif

#include "algo.h"
#include "file_info.h"
#include "pe_hdrs_helper.h"
#include "platform.h"
#include "search_helper.h"

namespace {

class TempFile {
public:
    explicit TempFile(const std::vector<BYTE>& bytes)
    {
#if defined(_WIN32)
        wchar_t tempDir[MAX_PATH]{};
        if (GetTempPathW(MAX_PATH, tempDir) == 0 ||
            GetTempFileNameW(tempDir, L"pef", 0, path_) == 0) {
            ADD_FAILURE() << "Failed to get temp file path.";
            return;
        }

        HANDLE handle = CreateFileW(path_, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
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
        DeleteFileW(path_);
#else
        ::remove(path_.c_str());
#endif
    }

    std::string utf8Path() const
    {
#if defined(_WIN32)
        return platform_utf16le_to_utf8(reinterpret_cast<const char16_t*>(path_), wcslen(path_));
#else
        return path_;
#endif
    }

private:
#if defined(_WIN32)
    wchar_t path_[MAX_PATH]{};
#else
    std::string path_;
#endif
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
