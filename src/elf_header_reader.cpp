#include "elf_header_reader.h"

#include "platform.h"

bool read_elf_sections(PlatformFile* file, std::vector<ElfSection>& out)
{
    out.clear();
    if (file == nullptr) {
        return false;
    }

    const ElfReader read = [file](uint64_t offset, size_t length, std::vector<BYTE>& dest) {
        if (!platform_file_seek(file, offset)) {
            return false;
        }
        dest.resize(length);
        size_t bytes_read = 0;
        return platform_file_read(file, dest.data(), length, bytes_read) && bytes_read == length;
    };
    return parse_elf_sections(read, platform_file_size(file), out);
}
