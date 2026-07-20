#include "elf_header_reader.h"

#include <algorithm>

#include "elf_defs.h"
#include "elf_hdrs_helper.h"
#include "platform.h"

namespace {

constexpr uint32_t kMaxElfMeta = 1024 * 1024; // 1 MiB cap for header + section tables

bool read_range(PlatformFile* file, uint64_t offset, size_t length, std::vector<BYTE>& dest)
{
    if (file == nullptr || length == 0) {
        return false;
    }
    if (!platform_file_seek(file, offset)) {
        return false;
    }
    dest.resize(length);
    size_t bytes_read = 0;
    if (!platform_file_read(file, dest.data(), length, bytes_read) || bytes_read != length) {
        return false;
    }
    return true;
}

template <typename Ehdr, typename Shdr>
uint32_t load_elf_metadata(PlatformFile* file, std::vector<BYTE>& out_buf, const Ehdr& ehdr)
{
    if (ehdr.e_shentsize != sizeof(Shdr) || ehdr.e_shnum == 0) {
        return static_cast<uint32_t>(out_buf.size());
    }
    if (ehdr.e_shstrndx >= ehdr.e_shnum) {
        return static_cast<uint32_t>(out_buf.size());
    }

    const uint64_t file_size = platform_file_size(file);
    const uint64_t shoff = static_cast<uint64_t>(ehdr.e_shoff);
    const uint64_t table_bytes = static_cast<uint64_t>(ehdr.e_shnum) * sizeof(Shdr);
    if (shoff > file_size || table_bytes > file_size - shoff) {
        return static_cast<uint32_t>(out_buf.size());
    }
    if (table_bytes > kMaxElfMeta) {
        return static_cast<uint32_t>(out_buf.size());
    }

    // Ensure out_buf covers from 0 through the section header table end when possible.
    // If the table is far from the start, stitch: keep ehdr at front and append tables.
    const uint64_t table_end = shoff + table_bytes;
    if (table_end <= kMaxElfMeta && table_end <= file_size) {
        std::vector<BYTE> full;
        if (!read_range(file, 0, static_cast<size_t>(table_end), full)) {
            return static_cast<uint32_t>(out_buf.size());
        }
        out_buf.swap(full);

        if (out_buf.size() < sizeof(Ehdr) + table_bytes) {
            return static_cast<uint32_t>(out_buf.size());
        }
        const auto* sections = reinterpret_cast<const Shdr*>(out_buf.data() + shoff);
        const auto& shstr = sections[ehdr.e_shstrndx];
        if (shstr.sh_type != SHT_STRTAB) {
            return static_cast<uint32_t>(out_buf.size());
        }

        const uint64_t str_off = static_cast<uint64_t>(shstr.sh_offset);
        const uint64_t str_size = static_cast<uint64_t>(shstr.sh_size);
        if (str_size == 0 || str_size > kMaxElfMeta) {
            return static_cast<uint32_t>(out_buf.size());
        }
        if (str_off > file_size || str_size > file_size - str_off) {
            return static_cast<uint32_t>(out_buf.size());
        }

        const uint64_t str_end = str_off + str_size;
        const uint64_t needed = (std::max)(table_end, str_end);
        if (needed <= kMaxElfMeta && needed > out_buf.size() && needed <= file_size) {
            std::vector<BYTE> bigger;
            if (read_range(file, 0, static_cast<size_t>(needed), bigger)) {
                out_buf.swap(bigger);
            }
        }
        return static_cast<uint32_t>(out_buf.size());
    }

    // Sparse layout: keep ELF header, then copy section headers to a contiguous buffer
    // starting after the header, and remap offsets so lookup still works via a packed view.
    // For simplicity when tables are sparse/far, expand only if total needed stays under cap
    // by reading [0, e_ehsize) + section table + strtab into one linear buffer with rewritten
    // e_shoff. That requires mutating the header; instead fail closed to header-only.
    return static_cast<uint32_t>(out_buf.size());
}

} // namespace

uint32_t read_elf_header(PlatformFile* file, std::vector<BYTE>& out_buf)
{
    if (file == nullptr) {
        return 0;
    }

    const uint64_t file_size = platform_file_size(file);
    if (file_size < EI_NIDENT) {
        return 0;
    }

    const size_t initial = static_cast<size_t>((std::min)(file_size, static_cast<uint64_t>(64)));
    if (!read_range(file, 0, initial, out_buf)) {
        return 0;
    }
    if (!checkELF(out_buf.data(), out_buf.size())) {
        return static_cast<uint32_t>(out_buf.size());
    }

    if (is_elf64(out_buf.data(), out_buf.size())) {
        if (out_buf.size() < sizeof(Elf64_Ehdr)) {
            const size_t need = (std::min)(file_size, static_cast<uint64_t>(sizeof(Elf64_Ehdr)));
            if (!read_range(file, 0, need, out_buf)) {
                return 0;
            }
        }
        if (out_buf.size() < sizeof(Elf64_Ehdr)) {
            return static_cast<uint32_t>(out_buf.size());
        }
        const auto ehdr = *reinterpret_cast<const Elf64_Ehdr*>(out_buf.data());
        return load_elf_metadata<Elf64_Ehdr, Elf64_Shdr>(file, out_buf, ehdr);
    }

    if (out_buf.size() < sizeof(Elf32_Ehdr)) {
        const size_t need = (std::min)(file_size, static_cast<uint64_t>(sizeof(Elf32_Ehdr)));
        if (!read_range(file, 0, need, out_buf)) {
            return 0;
        }
    }
    if (out_buf.size() < sizeof(Elf32_Ehdr)) {
        return static_cast<uint32_t>(out_buf.size());
    }
    const auto ehdr = *reinterpret_cast<const Elf32_Ehdr*>(out_buf.data());
    return load_elf_metadata<Elf32_Ehdr, Elf32_Shdr>(file, out_buf, ehdr);
}
