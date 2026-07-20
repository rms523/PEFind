#include "elf_hdrs_helper.h"

#include <cstring>

#include "util.h"

static bool has_elf_magic(const BYTE* buf, size_t buffer_size)
{
    if (buf == nullptr || buffer_size < EI_NIDENT) {
        return false;
    }
    return buf[EI_MAG0] == ELFMAG0 &&
           buf[EI_MAG1] == ELFMAG1 &&
           buf[EI_MAG2] == ELFMAG2 &&
           buf[EI_MAG3] == ELFMAG3;
}

bool checkELF(const BYTE* buf, size_t buffer_size)
{
    if (!has_elf_magic(buf, buffer_size)) {
        return false;
    }
    const uint8_t elf_class = buf[EI_CLASS];
    if (elf_class != ELFCLASS32 && elf_class != ELFCLASS64) {
        return false;
    }
    // Little-endian only for now (covers Linux/macOS x86_64 and most aarch64 Linux).
    if (buf[EI_DATA] != ELFDATA2LSB) {
        return false;
    }
    if (buf[EI_VERSION] != EV_CURRENT) {
        return false;
    }
    return true;
}

bool is_elf64(const BYTE* buf, size_t buffer_size)
{
    return checkELF(buf, buffer_size) && buf[EI_CLASS] == ELFCLASS64;
}

static std::string elf_section_name(const BYTE* buf, size_t buffer_size,
                                    uint64_t shstrtab_offset, uint64_t shstrtab_size,
                                    uint32_t name_offset)
{
    if (shstrtab_size == 0 || name_offset >= shstrtab_size) {
        return {};
    }
    if (!validate_ptr(buf, buffer_size,
                      buf + shstrtab_offset + name_offset,
                      1)) {
        return {};
    }

    const char* start = reinterpret_cast<const char*>(buf + shstrtab_offset + name_offset);
    const size_t max_len = static_cast<size_t>(shstrtab_size - name_offset);
    size_t len = 0;
    while (len < max_len && start[len] != '\0') {
        ++len;
    }
    return std::string(start, len);
}

template <typename Ehdr, typename Shdr>
static ElfSectionHit lookup_elf_section(const BYTE* buf, size_t buffer_size, uint64_t file_offset)
{
    ElfSectionHit hit;
    if (!validate_ptr(buf, buffer_size, buf, sizeof(Ehdr))) {
        return hit;
    }

    const auto* ehdr = reinterpret_cast<const Ehdr*>(buf);
    if (ehdr->e_shentsize != sizeof(Shdr) || ehdr->e_shnum == 0) {
        return hit;
    }
    if (ehdr->e_shstrndx >= ehdr->e_shnum) {
        return hit;
    }

    const uint64_t shoff = static_cast<uint64_t>(ehdr->e_shoff);
    const uint64_t table_bytes = static_cast<uint64_t>(ehdr->e_shnum) * sizeof(Shdr);
    if (shoff > buffer_size || table_bytes > buffer_size - shoff) {
        return hit;
    }
    if (!validate_ptr(buf, buffer_size, buf + shoff, static_cast<size_t>(table_bytes))) {
        return hit;
    }

    const auto* sections = reinterpret_cast<const Shdr*>(buf + shoff);
    const auto& shstr = sections[ehdr->e_shstrndx];
    if (shstr.sh_type != SHT_STRTAB) {
        return hit;
    }
    const uint64_t shstr_off = static_cast<uint64_t>(shstr.sh_offset);
    const uint64_t shstr_size = static_cast<uint64_t>(shstr.sh_size);
    if (shstr_off > buffer_size || shstr_size > buffer_size - shstr_off) {
        return hit;
    }

    for (uint16_t i = 0; i < ehdr->e_shnum; ++i) {
        const auto& sec = sections[i];
        if (sec.sh_type == SHT_NULL || sec.sh_type == SHT_NOBITS || sec.sh_size == 0) {
            continue;
        }
        const uint64_t start = static_cast<uint64_t>(sec.sh_offset);
        const uint64_t end = start + static_cast<uint64_t>(sec.sh_size);
        if (file_offset < start || file_offset >= end) {
            continue;
        }

        hit.found = true;
        hit.index = static_cast<int>(i);
        hit.section_offset = file_offset - start;
        hit.name = elf_section_name(buf, buffer_size, shstr_off, shstr_size, sec.sh_name);
        return hit;
    }
    return hit;
}

ElfSectionHit get_elf_section_by_file_offset(const BYTE* buf, size_t buffer_size, uint64_t file_offset)
{
    if (!checkELF(buf, buffer_size)) {
        return {};
    }
    if (is_elf64(buf, buffer_size)) {
        return lookup_elf_section<Elf64_Ehdr, Elf64_Shdr>(buf, buffer_size, file_offset);
    }
    return lookup_elf_section<Elf32_Ehdr, Elf32_Shdr>(buf, buffer_size, file_offset);
}
