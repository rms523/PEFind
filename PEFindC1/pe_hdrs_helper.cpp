#include "pe_hdrs_helper.h"
#include "util.h"

BYTE* get_nt_hrds(const BYTE* pe_buffer)
{
    if (pe_buffer == NULL) return NULL;

    const IMAGE_DOS_HEADER* idh = reinterpret_cast<const IMAGE_DOS_HEADER*>(pe_buffer);
    if (idh->e_magic != IMAGE_DOS_SIGNATURE) {
        return NULL;
    }
    // Allow e_lfanew up to 64KB — real PE files can have NT headers far beyond offset 1024
    const LONG kMaxOffset = 65536;
    LONG pe_offset = idh->e_lfanew;
    if (pe_offset < 0 || pe_offset > kMaxOffset) return NULL;
    BYTE* nt_ptr = const_cast<BYTE*>(pe_buffer) + pe_offset;
    if (reinterpret_cast<const DWORD*>(nt_ptr)[0] != IMAGE_NT_SIGNATURE) return NULL;
    return nt_ptr;
}

IMAGE_NT_HEADERS32* get_nt_hrds32(BYTE* pe_buffer)
{
    BYTE* ptr = get_nt_hrds(pe_buffer);
    if (ptr == NULL) return NULL;

    auto* inh = reinterpret_cast<IMAGE_NT_HEADERS32*>(ptr);
    if (inh->FileHeader.Machine == IMAGE_FILE_MACHINE_I386 &&
        inh->FileHeader.SizeOfOptionalHeader >= sizeof(IMAGE_OPTIONAL_HEADER32) &&
        inh->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        return inh;
    }
    return NULL;
}

IMAGE_NT_HEADERS64* get_nt_hrds64(const BYTE* pe_buffer)
{
    const BYTE* ptr = get_nt_hrds(pe_buffer);
    if (ptr == NULL) return NULL;

    auto* inh32 = reinterpret_cast<const IMAGE_NT_HEADERS32*>(ptr);
    if (inh32->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64) {
        const auto* inh64 = reinterpret_cast<const IMAGE_NT_HEADERS64*>(ptr);
        if (inh64->FileHeader.SizeOfOptionalHeader < sizeof(IMAGE_OPTIONAL_HEADER64) ||
            inh64->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
            return NULL;
        }
        return const_cast<IMAGE_NT_HEADERS64*>(reinterpret_cast<const IMAGE_NT_HEADERS64*>(ptr));
    }
    return NULL;
}

bool is64bit(const BYTE* pe_buffer)
{
    return get_nt_hrds64(pe_buffer) != NULL;
}

IMAGE_DATA_DIRECTORY* get_pe_directory(const BYTE* pe_buffer, DWORD dir_id)
{
    if (dir_id >= IMAGE_NUMBEROF_DIRECTORY_ENTRIES) return NULL;

    BYTE* nt_headers = const_cast<BYTE*>(get_nt_hrds(pe_buffer));
    if (nt_headers == NULL) return NULL;

    IMAGE_DATA_DIRECTORY* peDir = nullptr;
    if (is64bit(pe_buffer)) {
        auto* nthdr64 = reinterpret_cast<IMAGE_NT_HEADERS64*>(nt_headers);
        peDir = &(nthdr64->OptionalHeader.DataDirectory[dir_id]);
    } else {
        auto* nthdr32 = reinterpret_cast<IMAGE_NT_HEADERS32*>(nt_headers);
        peDir = &(nthdr32->OptionalHeader.DataDirectory[dir_id]);
    }
    if (peDir->VirtualAddress == 0) {
        return NULL;
    }
    return peDir;
}

ULONGLONG get_module_base(const BYTE* pe_buffer)
{
    bool is64b = is64bit(pe_buffer);
    BYTE* payload_nt_hdr = const_cast<BYTE*>(get_nt_hrds(pe_buffer));
    if (payload_nt_hdr == NULL) {
        return 0;
    }
    if (is64b) {
        auto* nthdr64 = reinterpret_cast<const IMAGE_NT_HEADERS64*>(payload_nt_hdr);
        return nthdr64->OptionalHeader.ImageBase;
    }
    auto* nthdr32 = reinterpret_cast<const IMAGE_NT_HEADERS32*>(payload_nt_hdr);
    return static_cast<ULONGLONG>(nthdr32->OptionalHeader.ImageBase);
}

// Get the section header that contains a given file offset.
// Uses DWORD64 for globalOffset to correctly handle files larger than 4 GB.
PIMAGE_SECTION_HEADER get_section_hdr(const BYTE* payload, const size_t buffer_size, DWORD64 globalOffset, int &sectionIndex)
{
    if (payload == NULL) return NULL;

    const BYTE* nt_hdr = get_nt_hrds(payload);
    if (nt_hdr == NULL) {
        return NULL;
    }

    // Validate we have enough data for the signature and file header.
    if (!validate_ptr(payload, static_cast<SIZE_T>(buffer_size), nt_hdr, sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER))) {
        return NULL;
    }

    const IMAGE_FILE_HEADER* fileHdr = reinterpret_cast<const IMAGE_FILE_HEADER*>(nt_hdr + sizeof(DWORD));
    const BYTE* optionalHeader = reinterpret_cast<const BYTE*>(fileHdr) + sizeof(IMAGE_FILE_HEADER);
    if (fileHdr->SizeOfOptionalHeader < sizeof(WORD) ||
        !validate_ptr(payload, static_cast<SIZE_T>(buffer_size), optionalHeader, fileHdr->SizeOfOptionalHeader)) {
        return NULL;
    }

    const WORD optionalMagic = *reinterpret_cast<const WORD*>(optionalHeader);
    const BYTE* secPtr = nullptr;

    if (optionalMagic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        if (fileHdr->Machine != IMAGE_FILE_MACHINE_AMD64 ||
            fileHdr->SizeOfOptionalHeader < sizeof(IMAGE_OPTIONAL_HEADER64)) {
            return NULL;
        }
        auto* nthdr64 = reinterpret_cast<const IMAGE_NT_HEADERS64*>(nt_hdr);
        secPtr = reinterpret_cast<const BYTE*>(&nthdr64->OptionalHeader) + fileHdr->SizeOfOptionalHeader;
    } else if (optionalMagic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        if (fileHdr->Machine != IMAGE_FILE_MACHINE_I386 ||
            fileHdr->SizeOfOptionalHeader < sizeof(IMAGE_OPTIONAL_HEADER32)) {
            return NULL;
        }
        auto* nthdr32 = reinterpret_cast<const IMAGE_NT_HEADERS32*>(nt_hdr);
        secPtr = reinterpret_cast<const BYTE*>(&nthdr32->OptionalHeader) + fileHdr->SizeOfOptionalHeader;
    } else {
        return NULL;
    }

    if (fileHdr->NumberOfSections == 0) {
        return NULL;
    }

    // Iterate section headers using proper struct array indexing.
    const size_t secSize = sizeof(IMAGE_SECTION_HEADER);

    for (int numberOfSections = 0; numberOfSections < fileHdr->NumberOfSections; ++numberOfSections) {
        const auto* section = reinterpret_cast<const IMAGE_SECTION_HEADER*>(secPtr + (numberOfSections * secSize));

        // Validate the struct pointer is within bounds before accessing fields
        if (!validate_ptr(payload, static_cast<SIZE_T>(buffer_size), section, sizeof(IMAGE_SECTION_HEADER))) {
            return NULL;
        }

        DWORD64 rawAddress = section->PointerToRawData;
        DWORD64 rawSize    = section->SizeOfRawData;

        // Check if the global offset falls within this section's raw data range.
        // Use 64-bit arithmetic to avoid overflow on large files.
        if (rawAddress <= globalOffset && globalOffset < (rawAddress + rawSize)) {
            sectionIndex = numberOfSections;
            return const_cast<IMAGE_SECTION_HEADER*>(section);
        }
    }

    // Not found in any section
    return NULL;
}

BOOL checkPE(const BYTE* buf) 
{
    const IMAGE_DOS_HEADER* idh = reinterpret_cast<const IMAGE_DOS_HEADER*>(buf);
    if (idh->e_magic != IMAGE_DOS_SIGNATURE) {
        return false;
    }
    return true;
}
