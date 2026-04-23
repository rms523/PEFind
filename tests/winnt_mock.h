#pragma once
// Minimal Windows PE type definitions for unit testing.
// Only defines what algo.h needs — no full Windows SDK required.

#include <cstdint>
#include <cstddef>

// Basic types
typedef uint8_t  BYTE;
typedef uint16_t WORD;
typedef uint32_t DWORD;
typedef int      LONG;
typedef ULONG    ULONG;
typedef void     *LPVOID;
typedef const void *LPCVOID;
typedef char     CHAR;
typedef wchar_t  WCHAR;

// PE signatures and constants
#define IMAGE_DOS_SIGNATURE             0x5A4D      // MZ
#define IMAGE_NT_SIGNATURE              0x00004550  // PE\0\0
#define IMAGE_NT_OPTIONAL_HDR_MAGIC32   0x10b
#define IMAGE_NT_OPTIONAL_HDR_MAGIC64   0x20b

// Machine types
#define IMAGE_FILE_MACHINE_I386         0x014c
#define IMAGE_FILE_MACHINE_AMD64        0x8664

// File characteristics
#define IMAGE_FILE_EXECUTABLE_IMAGE     0x0002
#define IMAGE_FILE_LARGE_ADDRESS_AWARE  0x0020

// Size constants
#define IMAGE_SIZEOF_SECTION_HEADER     40
#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES 16

#pragma pack(push, 1)

struct IMAGE_DOS_HEADER {
    WORD   e_magic;
    WORD   e_cblp;
    WORD   e_cp;
    WORD   e_crlc;
    WORD   e_cparhdr;
    WORD   e_minalloc;
    WORD   e_maxalloc;
    WORD   e_ss;
    WORD   e_sp;
    WORD   e_csum;
    WORD   e_ip;
    WORD   e_cs;
    WORD   e_lfarlc;
    WORD   e_ovno;
    WORD   e_res[4];
    WORD   e_oemid;
    WORD   e_oeminfo;
    WORD   e_res2[10];
    LONG   e_lfanew;
};

struct IMAGE_FILE_HEADER {
    WORD    Machine;
    WORD    NumberOfSections;
    DWORD   TimeDateStamp;
    DWORD   PointerToSymbolTable;
    DWORD   NumberOfSymbols;
    WORD    SizeOfOptionalHeader;
    WORD    Characteristics;
};

struct IMAGE_OPTIONAL_HEADER32 {
    WORD    Magic;
    BYTE    MajorLinkerVersion;
    BYTE    MinorLinkerVersion;
    DWORD   SizeOfCode;
    DWORD   SizeOfInitializedData;
    DWORD   SizeOfUninitializedData;
    DWORD   AddressOfEntryPoint;
    DWORD   BaseOfCode;
    DWORD   BaseOfData;
    DWORD   ImageBase;
    DWORD   SectionAlignment;
    DWORD   FileAlignment;
    WORD    MajorOperatingSystemVersion;
    WORD    MinorOperatingSystemVersion;
    WORD    MajorImageVersion;
    WORD    MinorImageVersion;
    WORD    MajorSubsystemVersion;
    WORD    MinorSubsystemVersion;
    DWORD   Win32VersionValue;
    DWORD   SizeOfImage;
    DWORD   SizeOfHeaders;
    DWORD   CheckSum;
    WORD    Subsystem;
    WORD    DllCharacteristics;
    DWORD   SizeOfStackReserve;
    DWORD   SizeOfStackCommit;
    DWORD   SizeOfHeapReserve;
    DWORD   SizeOfHeapCommit;
    DWORD   LoaderFlags;
    DWORD   NumberOfRvaAndSizes;
    // DataDirectory omitted — not needed for tests
};

struct IMAGE_OPTIONAL_HEADER64 {
    WORD    Magic;
    BYTE    MajorLinkerVersion;
    BYTE    MinorLinkerVersion;
    DWORD   SizeOfCode;
    DWORD   SizeOfInitializedData;
    DWORD   SizeOfUninitializedData;
    DWORD   AddressOfEntryPoint;
    DWORD   BaseOfCode;
    ULONGLONG ImageBase;
    DWORD   SectionAlignment;
    DWORD   FileAlignment;
    WORD    MajorOperatingSystemVersion;
    WORD    MinorOperatingSystemVersion;
    WORD    MajorImageVersion;
    WORD    MinorImageVersion;
    WORD    MajorSubsystemVersion;
    WORD    MinorSubsystemVersion;
    DWORD   Win32VersionValue;
    DWORD   SizeOfImage;
    DWORD   SizeOfHeaders;
    DWORD   CheckSum;
    WORD    Subsystem;
    WORD    DllCharacteristics;
    ULONGLONG SizeOfStackReserve;
    ULONGLONG SizeOfStackCommit;
    ULONGLONG SizeOfHeapReserve;
    ULONGLONG SizeOfHeapCommit;
    DWORD   LoaderFlags;
    DWORD   NumberOfRvaAndSizes;
    // DataDirectory omitted — not needed for tests
};

struct IMAGE_NT_HEADERS32 {
    DWORD               Signature;
    IMAGE_FILE_HEADER   FileHeader;
    IMAGE_OPTIONAL_HEADER32 OptionalHeader;
};

struct IMAGE_NT_HEADERS64 {
    DWORD               Signature;
    IMAGE_FILE_HEADER   FileHeader;
    IMAGE_OPTIONAL_HEADER64 OptionalHeader;
};

struct IMAGE_SECTION_HEADER {
    CHAR     Name[8];
    union {
        DWORD PhysicalAddress;
        DWORD VirtualSize;
    } Misc;
    DWORD    VirtualAddress;
    DWORD    SizeOfRawData;
    DWORD    PointerToRawData;
    DWORD    PointerToRelocations;
    DWORD    PointerToLinenumbers;
    WORD     NumberOfRelocations;
    WORD     NumberOfLinenumbers;
    DWORD    Characteristics;
};

#pragma pack(pop)

// Re-define ULONGLONG for completeness
typedef unsigned long long ULONGLONG;
