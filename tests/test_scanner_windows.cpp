#include <gtest/gtest.h>
#include <Windows.h>
#include <vector>

#include "algo.h"
#include "file_info.h"
#include "pe_hdrs_helper.h"
#include "search_helper.h"
#include "util.h"

namespace {

class TempFile {
public:
    explicit TempFile(const std::vector<BYTE>& bytes)
    {
        wchar_t tempDir[MAX_PATH]{};
        if (GetTempPathW(MAX_PATH, tempDir) == 0) {
            ADD_FAILURE() << "Failed to get a temp directory.";
            return;
        }
        if (GetTempFileNameW(tempDir, L"pef", 0, path_) == 0) {
            ADD_FAILURE() << "Failed to get a temp file path.";
            return;
        }

        HANDLE handle = CreateFileW(path_, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                                    FILE_ATTRIBUTE_TEMPORARY, nullptr);
        if (handle == INVALID_HANDLE_VALUE) {
            ADD_FAILURE() << "Failed to create the temp file.";
            return;
        }

        DWORD written = 0;
        BOOL ok = WriteFile(handle, bytes.data(), static_cast<DWORD>(bytes.size()), &written, nullptr);
        CloseHandle(handle);
        EXPECT_TRUE(ok);
        EXPECT_EQ(written, static_cast<DWORD>(bytes.size()));
    }

    ~TempFile()
    {
        DeleteFileW(path_);
    }

    std::string utf8Path() const
    {
        return utf16_to_utf8(path_);
    }

private:
    wchar_t path_[MAX_PATH]{};
};

std::vector<DWORD64> offsets(const std::vector<file_info>& matches)
{
    std::vector<DWORD64> result;
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
