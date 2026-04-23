#include <gtest/gtest.h>
#include "winnt_mock.h"
#include "algo.h"

// ============================================================
// Tests for PE header parsing (parse_pe_header)
// ============================================================

TEST(PeParsing, InvalidBufferTooSmall) {
    uint8_t buf[10] = {0};
    auto info = parse_pe_header(buf, 10);
    EXPECT_FALSE(info.is_valid);
}

TEST(PeParsing, InvalidDosSignature) {
    std::vector<uint8_t> buf(64, 0);
    // Write garbage as e_magic (not MZ)
    auto* idh = reinterpret_cast<IMAGE_DOS_HEADER*>(buf.data());
    idh->e_magic = 0x1234; // Not IMAGE_DOS_SIGNATURE

    auto info = parse_pe_header(buf.data(), buf.size());
    EXPECT_FALSE(info.is_valid);
}

TEST(PeParsing, Valid32BitPE) {
    auto pe = create_test_pe(4096, {{512, 1024}});
    auto* idh = reinterpret_cast<IMAGE_DOS_HEADER*>(pe.data());
    DWORD pe_offset = idh->e_lfanew;
    auto* file_hdr = reinterpret_cast<IMAGE_FILE_HEADER*>(pe.data() + pe_offset + sizeof(DWORD));
    file_hdr->Machine = IMAGE_FILE_MACHINE_I386;
    file_hdr->SizeOfOptionalHeader = static_cast<WORD>(sizeof(IMAGE_OPTIONAL_HEADER32));
    auto* opt_hdr = reinterpret_cast<IMAGE_OPTIONAL_HEADER32*>(
        reinterpret_cast<uint8_t*>(file_hdr) + sizeof(IMAGE_FILE_HEADER));
    opt_hdr->Magic = IMAGE_NT_OPTIONAL_HDR_MAGIC32;
    opt_hdr->SizeOfHeaders = 512;

    auto info = parse_pe_header(pe.data(), pe.size());

    ASSERT_TRUE(info.is_valid);
    EXPECT_FALSE(info.is_64bit);
    EXPECT_EQ(info.machine, IMAGE_FILE_MACHINE_I386);
    EXPECT_EQ(info.num_sections, 1u);
}

TEST(PeParsing, Valid64BitPE) {
    auto pe = create_test_pe(4096, {{512, 1024}});
    // Override to AMD64
    auto* idh = reinterpret_cast<IMAGE_DOS_HEADER*>(pe.data());
    DWORD pe_offset = idh->e_lfanew;

    auto* file_hdr = reinterpret_cast<IMAGE_FILE_HEADER*>(pe.data() + pe_offset + sizeof(DWORD));
    file_hdr->Machine = IMAGE_FILE_MACHINE_AMD64;

    // Update optional header magic and image base size for 64-bit
    auto* opt_hdr = reinterpret_cast<IMAGE_OPTIONAL_HEADER64*>(
        reinterpret_cast<uint8_t*>(file_hdr) + sizeof(IMAGE_FILE_HEADER));
    opt_hdr->Magic = IMAGE_NT_OPTIONAL_HDR_MAGIC64;

    auto info = parse_pe_header(pe.data(), pe.size());
    ASSERT_TRUE(info.is_valid);
    EXPECT_TRUE(info.is_64bit);
    EXPECT_EQ(info.machine, IMAGE_FILE_MACHINE_AMD64);
}

TEST(PeParsing, InvalidNtSignature) {
    std::vector<uint8_t> buf(128, 0);
    auto* idh = reinterpret_cast<IMAGE_DOS_HEADER*>(buf.data());
    idh->e_magic = IMAGE_DOS_SIGNATURE;
    idh->e_lfanew = 64;

    // Write garbage as NT signature (not PE\0\0)
    DWORD* sig = reinterpret_cast<DWORD*>(buf.data() + 64);
    *sig = 0xDEADBEEF;

    auto info = parse_pe_header(buf.data(), buf.size());
    EXPECT_FALSE(info.is_valid);
}

TEST(PeParsing, NegativeLfanew) {
    std::vector<uint8_t> buf(128, 0);
    auto* idh = reinterpret_cast<IMAGE_DOS_HEADER*>(buf.data());
    idh->e_magic = IMAGE_DOS_SIGNATURE;
    idh->e_lfanew = -1;

    auto info = parse_pe_header(buf.data(), buf.size());
    EXPECT_FALSE(info.is_valid);
}

// ============================================================
// Tests for section header access (get_section_at)
// ============================================================

TEST(PeSectionAccess, GetFirstSection) {
    std::vector<std::pair<DWORD, DWORD>> sections = {{512, 1024}, {1536, 2048}};
    auto pe = create_test_pe(4096, sections);

    auto info = parse_pe_header(pe.data(), pe.size());
    ASSERT_TRUE(info.is_valid);

    const auto* sec = get_section_at(pe.data(), pe.size(), info.e_lfanew, 0);
    ASSERT_NE(sec, nullptr);
    EXPECT_EQ(sec->PointerToRawData, sections[0].first);
    EXPECT_EQ(sec->SizeOfRawData, sections[0].second);
}

TEST(PeSectionAccess, GetSecondSection) {
    std::vector<std::pair<DWORD, DWORD>> sections = {{512, 1024}, {1536, 2048}};
    auto pe = create_test_pe(4096, sections);

    auto info = parse_pe_header(pe.data(), pe.size());
    ASSERT_TRUE(info.is_valid);

    const auto* sec = get_section_at(pe.data(), pe.size(), info.e_lfanew, 1);
    ASSERT_NE(sec, nullptr);
    EXPECT_EQ(sec->PointerToRawData, sections[1].first);
}

TEST(PeSectionAccess, InvalidIndexNegative) {
    std::vector<std::pair<DWORD, DWORD>> sections = {{512, 1024}};
    auto pe = create_test_pe(4096, sections);

    auto info = parse_pe_header(pe.data(), pe.size());
    const auto* sec = get_section_at(pe.data(), pe.size(), info.e_lfanew, -1);
    EXPECT_EQ(sec, nullptr);
}

TEST(PeSectionAccess, InvalidIndexTooLarge) {
    std::vector<std::pair<DWORD, DWORD>> sections = {{512, 1024}};
    auto pe = create_test_pe(4096, sections);

    auto info = parse_pe_header(pe.data(), pe.size());
    const auto* sec = get_section_at(pe.data(), pe.size(), info.e_lfanew, 5);
    EXPECT_EQ(sec, nullptr);
}

// ============================================================
// Tests for section lookup by offset (find_section_for_offset)
// ============================================================

TEST(PeSectionLookup, OffsetInSection1) {
    std::vector<std::pair<DWORD, DWORD>> sections = {{512, 1024}, {1536, 2048}};
    auto pe = create_test_pe(4096, sections);

    auto info = parse_pe_header(pe.data(), pe.size());
    int idx = find_section_for_offset(pe.data(), pe.size(), info.e_lfanew, 768); // Inside section 0 (512-1535)
    EXPECT_EQ(idx, 0);
}

TEST(PeSectionLookup, OffsetInSection2) {
    std::vector<std::pair<DWORD, DWORD>> sections = {{512, 1024}, {1536, 2048}};
    auto pe = create_test_pe(4096, sections);

    auto info = parse_pe_header(pe.data(), pe.size());
    int idx = find_section_for_offset(pe.data(), pe.size(), info.e_lfanew, 2000); // Inside section 1 (1536-3583)
    EXPECT_EQ(idx, 1);
}

TEST(PeSectionLookup, OffsetAtBoundaryStart) {
    std::vector<std::pair<DWORD, DWORD>> sections = {{512, 1024}};
    auto pe = create_test_pe(4096, sections);

    auto info = parse_pe_header(pe.data(), pe.size());
    int idx = find_section_for_offset(pe.data(), pe.size(), info.e_lfanew, 512); // At start of section 0
    EXPECT_EQ(idx, 0);
}

TEST(PeSectionLookup, OffsetAtBoundaryEnd) {
    std::vector<std::pair<DWORD, DWORD>> sections = {{512, 1024}};
    auto pe = create_test_pe(4096, sections);

    auto info = parse_pe_header(pe.data(), pe.size());
    int idx = find_section_for_offset(pe.data(), pe.size(), info.e_lfanew, 512 + 1024); // At end of section 0
    EXPECT_EQ(idx, -1);
}

TEST(PeSectionLookup, OffsetNotInAnySection) {
    std::vector<std::pair<DWORD, DWORD>> sections = {{512, 1024}};
    auto pe = create_test_pe(4096, sections);

    auto info = parse_pe_header(pe.data(), pe.size());
    int idx = find_section_for_offset(pe.data(), pe.size(), info.e_lfanew, 0); // In header area, not in section
    EXPECT_EQ(idx, -1);
}

TEST(PeSectionLookup, OffsetBeyondFile) {
    std::vector<std::pair<DWORD, DWORD>> sections = {{512, 1024}};
    auto pe = create_test_pe(4096, sections);

    auto info = parse_pe_header(pe.data(), pe.size());
    int idx = find_section_for_offset(pe.data(), pe.size(), info.e_lfanew, 100000); // Way beyond file
    EXPECT_EQ(idx, -1);
}

TEST(PeSectionLookup, MultipleSections) {
    std::vector<std::pair<DWORD, DWORD>> sections = {{512, 512}, {1024, 512}, {1536, 512}};
    auto pe = create_test_pe(4096, sections);

    auto info = parse_pe_header(pe.data(), pe.size());

    EXPECT_EQ(find_section_for_offset(pe.data(), pe.size(), info.e_lfanew, 600), 0); // Section 0
    EXPECT_EQ(find_section_for_offset(pe.data(), pe.size(), info.e_lfanew, 1100), 1); // Section 1
    EXPECT_EQ(find_section_for_offset(pe.data(), pe.size(), info.e_lfanew, 1600), 2); // Section 2
}

// ============================================================
// Tests for test PE buffer creation (create_test_pe)
// ============================================================

TEST(PeBufferCreation, SingleSection) {
    std::vector<std::pair<DWORD, DWORD>> sections = {{512, 1024}};
    auto pe = create_test_pe(4096, sections);

    ASSERT_EQ(pe.size(), static_cast<size_t>(4096));
    // Verify DOS signature
    auto* idh = reinterpret_cast<IMAGE_DOS_HEADER*>(pe.data());
    EXPECT_EQ(idh->e_magic, IMAGE_DOS_SIGNATURE);

    // Verify NT signature
    DWORD* sig = reinterpret_cast<DWORD*>(pe.data() + idh->e_lfanew);
    EXPECT_EQ(*sig, IMAGE_NT_SIGNATURE);
}

TEST(PeBufferCreation, MultipleSections) {
    std::vector<std::pair<DWORD, DWORD>> sections = {{512, 512}, {1024, 512}};
    auto pe = create_test_pe(4096, sections);

    auto info = parse_pe_header(pe.data(), pe.size());
    ASSERT_TRUE(info.is_valid);
    EXPECT_EQ(info.num_sections, static_cast<WORD>(sections.size()));
}

TEST(PeBufferCreation, SectionNames) {
    std::vector<std::pair<DWORD, DWORD>> sections = {{512, 512}, {1024, 512}};
    auto pe = create_test_pe(4096, sections);

    auto info = parse_pe_header(pe.data(), pe.size());
    const auto* sec0 = get_section_at(pe.data(), pe.size(), info.e_lfanew, 0);
    const auto* sec1 = get_section_at(pe.data(), pe.size(), info.e_lfanew, 1);

    ASSERT_NE(sec0, nullptr);
    ASSERT_NE(sec1, nullptr);
    // First section should be ".text"
    EXPECT_EQ(strncmp(sec0->Name, ".text", 5), 0);
}

TEST(PeBufferCreation, LargeFile) {
    std::vector<std::pair<DWORD, DWORD>> sections = {{4096, 8192}};
    auto pe = create_test_pe(32768, sections);

    ASSERT_EQ(pe.size(), static_cast<size_t>(32768));
    auto info = parse_pe_header(pe.data(), pe.size());
    ASSERT_TRUE(info.is_valid);
}

TEST(PeBufferCreation, ZeroSections) {
    std::vector<std::pair<DWORD, DWORD>> sections;
    auto pe = create_test_pe(4096, sections);

    // Should still be a valid PE structure but with 0 sections
    auto info = parse_pe_header(pe.data(), pe.size());
    ASSERT_TRUE(info.is_valid);
    EXPECT_EQ(info.num_sections, 0u);
}
