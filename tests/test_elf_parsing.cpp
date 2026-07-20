#include <gtest/gtest.h>

#include <cstring>
#include <string>
#include <vector>

#include "elf_defs.h"
#include "elf_hdrs_helper.h"
#include "pe_winnt.h"

namespace {

void write_u16(std::vector<BYTE>& buf, size_t offset, uint16_t value)
{
    buf[offset] = static_cast<BYTE>(value & 0xff);
    buf[offset + 1] = static_cast<BYTE>((value >> 8) & 0xff);
}

void write_u32(std::vector<BYTE>& buf, size_t offset, uint32_t value)
{
    buf[offset] = static_cast<BYTE>(value & 0xff);
    buf[offset + 1] = static_cast<BYTE>((value >> 8) & 0xff);
    buf[offset + 2] = static_cast<BYTE>((value >> 16) & 0xff);
    buf[offset + 3] = static_cast<BYTE>((value >> 24) & 0xff);
}

void write_u64(std::vector<BYTE>& buf, size_t offset, uint64_t value)
{
    write_u32(buf, offset, static_cast<uint32_t>(value & 0xffffffffu));
    write_u32(buf, offset + 4, static_cast<uint32_t>((value >> 32) & 0xffffffffu));
}

// Build a tiny ELF64 with null + .text + .shstrtab sections.
// Layout:
//   [Elf64_Ehdr]
//   [.text bytes "HELLO"]
//   [shstrtab: "\0.text\0.shstrtab\0"]
//   [3x Elf64_Shdr]
std::vector<BYTE> create_test_elf64()
{
    const std::string text_payload = "HELLO";
    const std::string shstrtab = std::string("\0.text\0.shstrtab\0", 16);

    const size_t ehdr_size = sizeof(Elf64_Ehdr);
    const size_t text_off = ehdr_size;
    const size_t shstr_off = text_off + text_payload.size();
    const size_t shoff = shstr_off + shstrtab.size();
    const size_t total = shoff + 3 * sizeof(Elf64_Shdr);

    std::vector<BYTE> buf(total, 0);

    // Ident
    buf[0] = ELFMAG0;
    buf[1] = ELFMAG1;
    buf[2] = ELFMAG2;
    buf[3] = ELFMAG3;
    buf[EI_CLASS] = ELFCLASS64;
    buf[EI_DATA] = ELFDATA2LSB;
    buf[EI_VERSION] = EV_CURRENT;

    write_u16(buf, 16, 2);                 // e_type ET_EXEC
    write_u16(buf, 18, 0x3e);              // e_machine EM_X86_64
    write_u32(buf, 20, EV_CURRENT);        // e_version
    write_u64(buf, 24, 0);                 // e_entry
    write_u64(buf, 32, 0);                 // e_phoff
    write_u64(buf, 40, shoff);             // e_shoff
    write_u32(buf, 48, 0);                 // e_flags
    write_u16(buf, 52, static_cast<uint16_t>(ehdr_size));
    write_u16(buf, 54, 0);                 // e_phentsize
    write_u16(buf, 56, 0);                 // e_phnum
    write_u16(buf, 58, static_cast<uint16_t>(sizeof(Elf64_Shdr)));
    write_u16(buf, 60, 3);                 // e_shnum
    write_u16(buf, 62, 2);                 // e_shstrndx

    std::memcpy(buf.data() + text_off, text_payload.data(), text_payload.size());
    std::memcpy(buf.data() + shstr_off, shstrtab.data(), shstrtab.size());

    auto write_shdr = [&](size_t index, uint32_t name, uint32_t type, uint64_t offset, uint64_t size) {
        const size_t base = shoff + index * sizeof(Elf64_Shdr);
        write_u32(buf, base + 0, name);
        write_u32(buf, base + 4, type);
        write_u64(buf, base + 8, 0); // flags
        write_u64(buf, base + 16, 0); // addr
        write_u64(buf, base + 24, offset);
        write_u64(buf, base + 32, size);
        write_u32(buf, base + 40, 0);
        write_u32(buf, base + 44, 0);
        write_u64(buf, base + 48, 1);
        write_u64(buf, base + 56, 0);
    };

    write_shdr(0, 0, SHT_NULL, 0, 0);
    write_shdr(1, 1, SHT_PROGBITS, text_off, text_payload.size()); // ".text"
    write_shdr(2, 7, SHT_STRTAB, shstr_off, shstrtab.size());      // ".shstrtab"

    return buf;
}

std::vector<BYTE> create_test_elf32()
{
    const std::string text_payload = "ABCD";
    const std::string shstrtab = std::string("\0.text\0.shstrtab\0", 16);

    const size_t ehdr_size = sizeof(Elf32_Ehdr);
    const size_t text_off = ehdr_size;
    const size_t shstr_off = text_off + text_payload.size();
    const size_t shoff = shstr_off + shstrtab.size();
    const size_t total = shoff + 3 * sizeof(Elf32_Shdr);

    std::vector<BYTE> buf(total, 0);
    buf[0] = ELFMAG0;
    buf[1] = ELFMAG1;
    buf[2] = ELFMAG2;
    buf[3] = ELFMAG3;
    buf[EI_CLASS] = ELFCLASS32;
    buf[EI_DATA] = ELFDATA2LSB;
    buf[EI_VERSION] = EV_CURRENT;

    write_u16(buf, 16, 2);
    write_u16(buf, 18, 3); // EM_386
    write_u32(buf, 20, EV_CURRENT);
    write_u32(buf, 24, 0);
    write_u32(buf, 28, 0);
    write_u32(buf, 32, static_cast<uint32_t>(shoff));
    write_u32(buf, 36, 0);
    write_u16(buf, 40, static_cast<uint16_t>(ehdr_size));
    write_u16(buf, 42, 0);
    write_u16(buf, 44, 0);
    write_u16(buf, 46, static_cast<uint16_t>(sizeof(Elf32_Shdr)));
    write_u16(buf, 48, 3);
    write_u16(buf, 50, 2);

    std::memcpy(buf.data() + text_off, text_payload.data(), text_payload.size());
    std::memcpy(buf.data() + shstr_off, shstrtab.data(), shstrtab.size());

    auto write_shdr = [&](size_t index, uint32_t name, uint32_t type, uint32_t offset, uint32_t size) {
        const size_t base = shoff + index * sizeof(Elf32_Shdr);
        write_u32(buf, base + 0, name);
        write_u32(buf, base + 4, type);
        write_u32(buf, base + 8, 0);
        write_u32(buf, base + 12, 0);
        write_u32(buf, base + 16, offset);
        write_u32(buf, base + 20, size);
        write_u32(buf, base + 24, 0);
        write_u32(buf, base + 28, 0);
        write_u32(buf, base + 32, 1);
        write_u32(buf, base + 36, 0);
    };

    write_shdr(0, 0, SHT_NULL, 0, 0);
    write_shdr(1, 1, SHT_PROGBITS, static_cast<uint32_t>(text_off), static_cast<uint32_t>(text_payload.size()));
    write_shdr(2, 7, SHT_STRTAB, static_cast<uint32_t>(shstr_off), static_cast<uint32_t>(shstrtab.size()));
    return buf;
}

} // namespace

TEST(ElfParsing, RejectsInvalidMagic)
{
    std::vector<BYTE> buf(64, 0);
    EXPECT_FALSE(checkELF(buf.data(), buf.size()));
}

TEST(ElfParsing, AcceptsElf64)
{
    auto elf = create_test_elf64();
    ASSERT_TRUE(checkELF(elf.data(), elf.size()));
    EXPECT_TRUE(is_elf64(elf.data(), elf.size()));
}

TEST(ElfParsing, AcceptsElf32)
{
    auto elf = create_test_elf32();
    ASSERT_TRUE(checkELF(elf.data(), elf.size()));
    EXPECT_FALSE(is_elf64(elf.data(), elf.size()));
}

TEST(ElfParsing, MapsOffsetToTextSection64)
{
    auto elf = create_test_elf64();
    const size_t text_off = sizeof(Elf64_Ehdr);
    const auto hit = get_elf_section_by_file_offset(elf.data(), elf.size(), text_off + 1);
    ASSERT_TRUE(hit.found);
    EXPECT_EQ(hit.index, 1);
    EXPECT_EQ(hit.section_offset, 1u);
    EXPECT_EQ(hit.name, ".text");
}

TEST(ElfParsing, MapsOffsetToTextSection32)
{
    auto elf = create_test_elf32();
    const size_t text_off = sizeof(Elf32_Ehdr);
    const auto hit = get_elf_section_by_file_offset(elf.data(), elf.size(), text_off);
    ASSERT_TRUE(hit.found);
    EXPECT_EQ(hit.index, 1);
    EXPECT_EQ(hit.section_offset, 0u);
    EXPECT_EQ(hit.name, ".text");
}

TEST(ElfParsing, OffsetOutsideSections)
{
    auto elf = create_test_elf64();
    const auto hit = get_elf_section_by_file_offset(elf.data(), elf.size(), elf.size() + 10);
    EXPECT_FALSE(hit.found);
}
