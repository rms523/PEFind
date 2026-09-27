#include <gtest/gtest.h>

#include <string>
#include <vector>

#if !defined(_WIN32)
#include <cstdio>
#include <sys/stat.h>
#include <unistd.h>
#endif

#include "algo.h"
#include "elf_defs.h"
#include "file_info.h"
#include "pe_hdrs_helper.h"
#include "platform.h"
#include "search_helper.h"

#include <cstring>

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
            path_[0] = L'\0';
            return;
        }

        DWORD written = 0;
        const BOOL ok = bytes.empty() ? TRUE
            : WriteFile(handle, bytes.data(), static_cast<DWORD>(bytes.size()), &written, nullptr);
        CloseHandle(handle);
        EXPECT_TRUE(ok);
        EXPECT_EQ(written, static_cast<DWORD>(bytes.size()));
        valid_ = ok && written == static_cast<DWORD>(bytes.size());
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
#if defined(_WIN32)
        if (valid_) {
            DeleteFileW(path_);
        }
#else
        if (!path_.empty()) {
            ::remove(path_.c_str());
        }
#endif
    }

    std::string utf8Path() const
    {
#if defined(_WIN32)
        if (!valid_) {
            return {};
        }
        return platform_wide_to_utf8(path_, wcslen(path_));
#else
        return path_;
#endif
    }

private:
#if defined(_WIN32)
    wchar_t path_[MAX_PATH]{};
    bool valid_ = false;
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
    EXPECT_EQ(textMatches[0].format, "Not a PE or ELF file.");
    EXPECT_EQ(textMatches[0].format, hexMatches[0].format);
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

namespace {

// Minimal ELF64 with .text "HELLO" right after the header. `table_gap` bytes of padding are
// inserted before .shstrtab and the section header table, as in large real-world binaries.
std::vector<BYTE> build_elf64(size_t table_gap = 0)
{
    const std::string text_payload = "HELLO";
    const std::string shstrtab = std::string("\0.text\0.shstrtab\0", 16);
    const size_t ehdr_size = sizeof(Elf64_Ehdr);
    const size_t text_off = ehdr_size;
    const size_t shstr_off = text_off + text_payload.size() + table_gap;
    const size_t shoff = shstr_off + shstrtab.size();
    std::vector<BYTE> elf(shoff + 3 * sizeof(Elf64_Shdr), 0);

    elf[0] = ELFMAG0; elf[1] = ELFMAG1; elf[2] = ELFMAG2; elf[3] = ELFMAG3;
    elf[EI_CLASS] = ELFCLASS64;
    elf[EI_DATA] = ELFDATA2LSB;
    elf[EI_VERSION] = EV_CURRENT;

    auto wu16 = [&](size_t o, uint16_t v) {
        elf[o] = static_cast<BYTE>(v & 0xff);
        elf[o + 1] = static_cast<BYTE>((v >> 8) & 0xff);
    };
    auto wu32 = [&](size_t o, uint32_t v) {
        wu16(o, static_cast<uint16_t>(v & 0xffff));
        wu16(o + 2, static_cast<uint16_t>((v >> 16) & 0xffff));
    };
    auto wu64 = [&](size_t o, uint64_t v) {
        wu32(o, static_cast<uint32_t>(v & 0xffffffffu));
        wu32(o + 4, static_cast<uint32_t>((v >> 32) & 0xffffffffu));
    };

    wu16(16, 2); wu16(18, 0x3e); wu32(20, EV_CURRENT);
    wu64(40, shoff);
    wu16(52, static_cast<uint16_t>(ehdr_size));
    wu16(58, static_cast<uint16_t>(sizeof(Elf64_Shdr)));
    wu16(60, 3); wu16(62, 2);
    std::memcpy(elf.data() + text_off, text_payload.data(), text_payload.size());
    std::memcpy(elf.data() + shstr_off, shstrtab.data(), shstrtab.size());

    auto write_shdr = [&](size_t index, uint32_t name, uint32_t type, uint64_t offset, uint64_t size) {
        const size_t base = shoff + index * sizeof(Elf64_Shdr);
        wu32(base + 0, name); wu32(base + 4, type); wu64(base + 8, 0); wu64(base + 16, 0);
        wu64(base + 24, offset); wu64(base + 32, size); wu32(base + 40, 0); wu32(base + 44, 0);
        wu64(base + 48, 1); wu64(base + 56, 0);
    };
    write_shdr(0, 0, SHT_NULL, 0, 0);
    write_shdr(1, 1, SHT_PROGBITS, text_off, text_payload.size());
    write_shdr(2, 7, SHT_STRTAB, shstr_off, shstrtab.size());
    return elf;
}

} // namespace

TEST(ScannerProduction, ElfMatchReportsSectionName)
{
    TempFile file(build_elf64());
    ASSERT_FALSE(file.utf8Path().empty());

    std::vector<file_info> matches;
    searchStringinFile(file.utf8Path(), "HELLO", FALSE, matches);
    ASSERT_EQ(matches.size(), 1u);
    EXPECT_EQ(matches[0].fileoffset, static_cast<uint64_t>(sizeof(Elf64_Ehdr)));
    EXPECT_EQ(matches[0].sectionName, ".text");
    EXPECT_EQ(matches[0].format, "ELF");
    EXPECT_EQ(matches[0].sectionindex, 1);
}

TEST(ScannerProduction, ElfSectionTableFarFromStartStillMaps)
{
    // Large binaries (e.g. libc.so.6) keep the section header table megabytes into the file.
    TempFile file(build_elf64(3 * 1024 * 1024));
    ASSERT_FALSE(file.utf8Path().empty());

    std::vector<file_info> matches;
    searchStringinFile(file.utf8Path(), "HELLO", FALSE, matches);
    ASSERT_EQ(matches.size(), 1u);
    EXPECT_EQ(matches[0].sectionName, ".text");
    EXPECT_EQ(matches[0].format, "ELF");
}

TEST(PeProductionHelpers, MapsSectionsForNonX86Machines)
{
    // ARM64 PE32+ images use the same layout as AMD64; only the Machine field differs.
    auto pe = create_test_pe(0x3000, {{0x1000, 0x1000}, {0x2000, 0x1000}});
    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(pe.data());
    auto* file_hdr = reinterpret_cast<IMAGE_FILE_HEADER*>(pe.data() + dos->e_lfanew + sizeof(DWORD));
    file_hdr->Machine = 0xAA64; // IMAGE_FILE_MACHINE_ARM64

    int sectionIndex = -1;
    const auto* section = get_section_hdr(pe.data(), pe.size(), 0x2010, sectionIndex);
    ASSERT_NE(section, nullptr);
    EXPECT_EQ(sectionIndex, 1);
    EXPECT_TRUE(is64bit(pe.data(), pe.size()));
}

TEST(ScannerProduction, EmptyFileIsScannedNotAnError)
{
    TempFile file(std::vector<BYTE>{});
    ASSERT_FALSE(file.utf8Path().empty());

    std::vector<file_info> matches;
    ScanStats stats;
    searchStringinFile(file.utf8Path(), "AB", FALSE, matches, FALSE, FALSE, nullptr, ResultCallback{}, &stats);
    EXPECT_TRUE(matches.empty());
    EXPECT_EQ(stats.filesScanned(), 1u);
    EXPECT_EQ(stats.filesWithErrors(), 0u);
}

TEST(ScannerProduction, UnicodeCaseInsensitiveFindsOddAndEvenOffsets)
{
    // "Ab" as UTF-16LE at offset 1 (odd) and offset 6 (even), with differing case.
    TempFile file(std::vector<BYTE>{'X', 'A', 0, 'B', 0, 'Y', 'a', 0, 'b', 0});
    ASSERT_FALSE(file.utf8Path().empty());

    std::vector<file_info> matches;
    searchStringinFile(file.utf8Path(), "ab", TRUE, matches, TRUE);
    EXPECT_EQ(offsets(matches), (std::vector<uint64_t>{1, 6}));
}

TEST(ScannerProduction, UnicodeCaseInsensitiveRejectsMisalignedMatch)
{
    // "ĀĀ" (U+0100 x2) lowercases to bytes 01 01 01 01. The byte pair at offset 1 also reads
    // 01 01 there, but in the file it is U+0001 - not "ā" - so it must not be reported.
    TempFile file(std::vector<BYTE>{0x00, 0x01, 0x00, 0x01});
    ASSERT_FALSE(file.utf8Path().empty());

    std::vector<file_info> matches;
    searchStringinFile(file.utf8Path(), "\xC4\x81", TRUE, matches, TRUE); // "ā"
    EXPECT_EQ(offsets(matches), (std::vector<uint64_t>{0, 2}));
}

TEST(PlatformText, LowercasesLatin1GreekAndCyrillic)
{
    std::u16string text = u"ÉÇΣЖЁĀĹŸ";
    platform_lowercase_utf16(&text[0], text.size());
    EXPECT_EQ(text, u"éçσжёāĺÿ");
}

#if !defined(_WIN32)
TEST(ScannerProduction, FifoIsRejectedWithoutBlocking)
{
    char dir[] = "/tmp/pefindfifoXXXXXX";
    ASSERT_NE(mkdtemp(dir), nullptr);
    const std::string fifo = std::string(dir) + "/pipe";
    ASSERT_EQ(mkfifo(fifo.c_str(), 0600), 0);

    PlatformFile* file = nullptr;
    EXPECT_FALSE(platform_file_open(fifo, file));  // would hang forever with a blocking open()
    EXPECT_EQ(file, nullptr);

    ::remove(fifo.c_str());
    ::rmdir(dir);
}
#endif
