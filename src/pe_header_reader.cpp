#include "pe_header_reader.h"

#include <algorithm>

#include "platform.h"

uint32_t read_pe_header(PlatformFile* file, std::vector<BYTE>& out_buf)
{
    if (file == nullptr) return 0;

    const ULONGLONG file_size = static_cast<ULONGLONG>(platform_file_size(file));
    if (file_size == 0) return 0;

    const DWORD MIN_HEADER = 1024;
    const DWORD MAX_PE_HEADER = 64 * 1024;
    DWORD read_size = static_cast<DWORD>((std::min)(file_size, static_cast<ULONGLONG>(MIN_HEADER)));
    if (read_size == 0) return 0;

    out_buf.resize(read_size);
    DWORD header_bytes = 0;
    if (!platform_file_seek(file, 0)) return 0;

    size_t bytes_read = 0;
    if (!platform_file_read(file, out_buf.data(), read_size, bytes_read)) return 0;
    header_bytes = static_cast<DWORD>(bytes_read);
    if (header_bytes < sizeof(IMAGE_DOS_HEADER)) return header_bytes;

    const IMAGE_DOS_HEADER* idh = reinterpret_cast<const IMAGE_DOS_HEADER*>(out_buf.data());
    if (idh->e_magic != IMAGE_DOS_SIGNATURE) return header_bytes;

    LONG pe_offset = idh->e_lfanew;
    if (pe_offset < 0) return header_bytes;

    ULONGLONG nt_header_minimum = static_cast<ULONGLONG>(pe_offset) + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER);
    if (nt_header_minimum > header_bytes) {
        read_size = static_cast<DWORD>((std::min)(file_size, (std::max)(nt_header_minimum, static_cast<ULONGLONG>(MIN_HEADER))));
        if (read_size > MAX_PE_HEADER) return header_bytes;

        out_buf.resize(read_size);
        if (!platform_file_seek(file, 0)) return 0;
        if (!platform_file_read(file, out_buf.data(), read_size, bytes_read)) return 0;
        header_bytes = static_cast<DWORD>(bytes_read);
        if (nt_header_minimum > header_bytes) return header_bytes;
        idh = reinterpret_cast<const IMAGE_DOS_HEADER*>(out_buf.data());
        if (idh->e_magic != IMAGE_DOS_SIGNATURE) return header_bytes;
        pe_offset = idh->e_lfanew;
        if (pe_offset < 0) return header_bytes;
    }

    const BYTE* nt_sig_ptr = out_buf.data() + pe_offset;
    if (reinterpret_cast<const DWORD*>(nt_sig_ptr)[0] != IMAGE_NT_SIGNATURE) return header_bytes;

    bool is64b = false;
    const auto* file_hdr = reinterpret_cast<const IMAGE_FILE_HEADER*>(nt_sig_ptr + sizeof(DWORD));

    ULONGLONG nt_header_size = sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + file_hdr->SizeOfOptionalHeader;
    ULONGLONG section_table_end = static_cast<ULONGLONG>(pe_offset) + nt_header_size +
                                  static_cast<ULONGLONG>(file_hdr->NumberOfSections) * IMAGE_SIZEOF_SECTION_HEADER;
    if (section_table_end > header_bytes) {
        ULONGLONG needed_size = (std::min)(file_size, section_table_end);
        if (needed_size > MAX_PE_HEADER) return header_bytes;
        out_buf.resize(static_cast<size_t>(needed_size));
        if (!platform_file_seek(file, 0)) return 0;
        if (!platform_file_read(file, out_buf.data(), static_cast<size_t>(needed_size), bytes_read)) return 0;
        header_bytes = static_cast<DWORD>(bytes_read);
        if (section_table_end > header_bytes) return header_bytes;
        nt_sig_ptr = out_buf.data() + pe_offset;
        file_hdr = reinterpret_cast<const IMAGE_FILE_HEADER*>(nt_sig_ptr + sizeof(DWORD));
    }

    if (file_hdr->SizeOfOptionalHeader < sizeof(WORD)) return header_bytes;
    const BYTE* optional_header = nt_sig_ptr + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER);
    const WORD optional_magic = *reinterpret_cast<const WORD*>(optional_header);
    if (optional_magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        if (file_hdr->SizeOfOptionalHeader < sizeof(IMAGE_OPTIONAL_HEADER64)) return header_bytes;
        is64b = true;
    } else if (optional_magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        if (file_hdr->SizeOfOptionalHeader < sizeof(IMAGE_OPTIONAL_HEADER32)) return header_bytes;
    } else {
        return header_bytes;
    }

    DWORD size_of_headers = 0;
    if (is64b) {
        const auto* nthdr = reinterpret_cast<const IMAGE_NT_HEADERS64*>(nt_sig_ptr);
        size_of_headers = nthdr->OptionalHeader.SizeOfHeaders;
    } else {
        const auto* nthdr = reinterpret_cast<const IMAGE_NT_HEADERS32*>(nt_sig_ptr);
        size_of_headers = nthdr->OptionalHeader.SizeOfHeaders;
    }

    if (size_of_headers > 0 && static_cast<DWORD>(size_of_headers) > header_bytes) {
        DWORD needed = static_cast<DWORD>((std::min)(file_size, (std::max)(static_cast<ULONGLONG>(size_of_headers),
                                                                           static_cast<ULONGLONG>(MIN_HEADER))));
        if (needed > MAX_PE_HEADER) return header_bytes;
        out_buf.resize(needed);
        if (!platform_file_seek(file, 0)) return 0;
        if (!platform_file_read(file, out_buf.data(), needed, bytes_read)) return 0;
        header_bytes = static_cast<DWORD>(bytes_read);
    }

    const BYTE* sig = out_buf.data() + pe_offset;
    const auto* fh = reinterpret_cast<const IMAGE_FILE_HEADER*>(sig + sizeof(DWORD));
    ULONGLONG sec_needed = static_cast<ULONGLONG>(pe_offset) + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) +
                           fh->SizeOfOptionalHeader +
                           static_cast<ULONGLONG>(fh->NumberOfSections) * IMAGE_SIZEOF_SECTION_HEADER;
    if (sec_needed > header_bytes && sec_needed <= file_size) {
        if (sec_needed > MAX_PE_HEADER) return header_bytes;
        out_buf.resize(static_cast<size_t>(sec_needed));
        if (!platform_file_seek(file, 0)) return 0;
        if (!platform_file_read(file, out_buf.data(), static_cast<size_t>(sec_needed), bytes_read)) return 0;
        header_bytes = static_cast<DWORD>(bytes_read);
    }

    return header_bytes;
}
