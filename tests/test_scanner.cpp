#include <gtest/gtest.h>

#include <cstdio>
#include <filesystem>
#include <fstream>
#include <vector>

#include "algo.h"
#include "file_info.h"
#include "pe_hdrs_helper.h"
#include "search_helper.h"

namespace {

class TempFile {
public:
    explicit TempFile(const std::vector<BYTE>& bytes)
    {
        namespace fs = std::filesystem;
        path_ = fs::temp_directory_path() / "pefind_test_XXXXXX.bin";
        path_ = fs::unique_path(path_);

        std::ofstream out(path_, std::ios::binary);
        if (!out) {
            ADD_FAILURE() << "Failed to create temp file.";
            return;
        }
        out.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
        if (!out) {
            ADD_FAILURE() << "Failed to write temp file.";
        }
    }

    ~TempFile()
    {
        std::error_code ec;
        std::filesystem::remove(path_, ec);
    }

    std::string utf8Path() const
    {
        return path_.string();
    }

private:
    std::filesystem::path path_;
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
