#include "elf_hdrs_helper.h"

#include <cstring>

namespace {

constexpr uint16_t SHN_UNDEF = 0;
constexpr uint16_t SHN_XINDEX = 0xffff;

// Caps keep hostile headers from forcing huge allocations.
constexpr uint64_t kMaxSectionTableBytes = 16ull * 1024 * 1024;
constexpr uint64_t kMaxStringTableBytes = 16ull * 1024 * 1024;

class FieldReader {
public:
    FieldReader(const BYTE* data, size_t size, bool big_endian)
        : data_(data), size_(size), big_endian_(big_endian) {}

    uint64_t read(size_t offset, size_t width) const
    {
        if (offset > size_ || width > size_ - offset) return 0;
        uint64_t value = 0;
        for (size_t i = 0; i < width; ++i) {
            const size_t byte = big_endian_ ? i : (width - 1 - i);
            value = (value << 8) | data_[offset + byte];
        }
        return value;
    }

private:
    const BYTE* data_;
    size_t size_;
    bool big_endian_;
};

struct ElfLayout {
    size_t ehdr_size;
    size_t shdr_size;
    // Ehdr field offsets
    size_t e_shoff, e_shentsize, e_shnum, e_shstrndx;
    size_t addr_width;
    // Shdr field offsets
    size_t sh_name, sh_type, sh_offset, sh_size, sh_link;
};

constexpr ElfLayout kLayout32 = {52, 40, 32, 46, 48, 50, 4, 0, 4, 16, 20, 24};
constexpr ElfLayout kLayout64 = {64, 64, 40, 58, 60, 62, 8, 0, 4, 24, 32, 40};

struct RawSection {
    uint32_t name = 0;
    uint32_t type = SHT_NULL;
    uint64_t offset = 0;
    uint64_t size = 0;
    uint32_t link = 0;
};

RawSection decode_section(const FieldReader& fields, const ElfLayout& layout, size_t base)
{
    RawSection sec;
    sec.name = static_cast<uint32_t>(fields.read(base + layout.sh_name, 4));
    sec.type = static_cast<uint32_t>(fields.read(base + layout.sh_type, 4));
    sec.offset = fields.read(base + layout.sh_offset, layout.addr_width);
    sec.size = fields.read(base + layout.sh_size, layout.addr_width);
    sec.link = static_cast<uint32_t>(fields.read(base + layout.sh_link, 4));
    return sec;
}

std::string section_name(const std::vector<BYTE>& strtab, uint32_t name_offset)
{
    if (name_offset >= strtab.size()) return {};
    const char* start = reinterpret_cast<const char*>(strtab.data() + name_offset);
    const size_t max_len = strtab.size() - name_offset;
    size_t len = 0;
    while (len < max_len && start[len] != '\0') ++len;
    return std::string(start, len);
}

bool range_fits(uint64_t offset, uint64_t length, uint64_t object_size)
{
    return offset <= object_size && length <= object_size - offset;
}

} // namespace

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
    if (buf[EI_DATA] != ELFDATA2LSB && buf[EI_DATA] != ELFDATA2MSB) {
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

bool parse_elf_sections(const ElfReader& read, uint64_t object_size, std::vector<ElfSection>& out)
{
    out.clear();

    std::vector<BYTE> ident;
    if (object_size < EI_NIDENT || !read(0, EI_NIDENT, ident) || !checkELF(ident.data(), ident.size())) {
        return false;
    }

    const ElfLayout& layout = (ident[EI_CLASS] == ELFCLASS64) ? kLayout64 : kLayout32;
    const bool big_endian = ident[EI_DATA] == ELFDATA2MSB;

    std::vector<BYTE> ehdr;
    if (object_size < layout.ehdr_size || !read(0, layout.ehdr_size, ehdr)) {
        return false;
    }
    const FieldReader eh(ehdr.data(), ehdr.size(), big_endian);

    const uint64_t shoff = eh.read(layout.e_shoff, layout.addr_width);
    const uint64_t shentsize = eh.read(layout.e_shentsize, 2);
    uint64_t shnum = eh.read(layout.e_shnum, 2);
    uint64_t shstrndx = eh.read(layout.e_shstrndx, 2);

    if (shoff == 0 || shentsize < layout.shdr_size) {
        return false;
    }

    // Extended numbering: when e_shnum / e_shstrndx overflow, the real values live in section 0.
    if (shnum == 0 || shstrndx == SHN_XINDEX) {
        std::vector<BYTE> first;
        if (!range_fits(shoff, layout.shdr_size, object_size) || !read(shoff, layout.shdr_size, first)) {
            return false;
        }
        const RawSection sec0 = decode_section(FieldReader(first.data(), first.size(), big_endian), layout, 0);
        if (shnum == 0) shnum = sec0.size;
        if (shstrndx == SHN_XINDEX) shstrndx = sec0.link;
    }

    if (shnum == 0 || shnum > kMaxSectionTableBytes / shentsize) {
        return false;
    }
    const uint64_t table_bytes = shnum * shentsize;
    if (!range_fits(shoff, table_bytes, object_size)) {
        return false;
    }

    std::vector<BYTE> table;
    if (!read(shoff, static_cast<size_t>(table_bytes), table)) {
        return false;
    }
    const FieldReader sh(table.data(), table.size(), big_endian);

    std::vector<RawSection> raw(static_cast<size_t>(shnum));
    for (size_t i = 0; i < raw.size(); ++i) {
        raw[i] = decode_section(sh, layout, static_cast<size_t>(i * shentsize));
    }

    // Section names are optional: a missing or malformed .shstrtab still yields usable offsets.
    std::vector<BYTE> strtab;
    if (shstrndx != SHN_UNDEF && shstrndx < shnum) {
        const RawSection& str = raw[static_cast<size_t>(shstrndx)];
        if (str.type == SHT_STRTAB && str.size != 0 && str.size <= kMaxStringTableBytes &&
            range_fits(str.offset, str.size, object_size)) {
            if (!read(str.offset, static_cast<size_t>(str.size), strtab)) {
                strtab.clear();
            }
        }
    }

    for (size_t i = 0; i < raw.size(); ++i) {
        const RawSection& sec = raw[i];
        if (sec.type == SHT_NULL || sec.type == SHT_NOBITS || sec.size == 0) {
            continue;
        }
        ElfSection section;
        section.index = static_cast<int>(i);
        section.type = sec.type;
        section.offset = sec.offset;
        section.size = sec.size;
        section.name = section_name(strtab, sec.name);
        out.push_back(std::move(section));
    }
    return true;
}

bool parse_elf_sections(const BYTE* buf, size_t buffer_size, std::vector<ElfSection>& out)
{
    if (buf == nullptr) {
        out.clear();
        return false;
    }
    const ElfReader read = [buf, buffer_size](uint64_t offset, size_t length, std::vector<BYTE>& dest) {
        if (!range_fits(offset, length, buffer_size)) return false;
        dest.assign(buf + offset, buf + offset + length);
        return true;
    };
    return parse_elf_sections(read, buffer_size, out);
}

ElfSectionHit find_elf_section(const std::vector<ElfSection>& sections, uint64_t file_offset)
{
    ElfSectionHit hit;
    for (const auto& sec : sections) {
        if (file_offset < sec.offset || file_offset - sec.offset >= sec.size) {
            continue;
        }
        hit.found = true;
        hit.index = sec.index;
        hit.section_offset = file_offset - sec.offset;
        hit.name = sec.name;
        return hit;
    }
    return hit;
}

ElfSectionHit get_elf_section_by_file_offset(const BYTE* buf, size_t buffer_size, uint64_t file_offset)
{
    std::vector<ElfSection> sections;
    if (!parse_elf_sections(buf, buffer_size, sections)) {
        return {};
    }
    return find_elf_section(sections, file_offset);
}
