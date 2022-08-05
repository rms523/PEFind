#include "pe_hdrs_helper.h"

BYTE* get_nt_hrds(const BYTE* pe_buffer)
{
	if (pe_buffer == NULL) return NULL;

	IMAGE_DOS_HEADER* idh = (IMAGE_DOS_HEADER*)pe_buffer;
	if (idh->e_magic != IMAGE_DOS_SIGNATURE) {
		return NULL;
	}
	const LONG kMaxOffset = 1024;
	LONG pe_offset = idh->e_lfanew;
	if (pe_offset > kMaxOffset) return NULL;
	IMAGE_NT_HEADERS32* inh = (IMAGE_NT_HEADERS32*)((BYTE*)pe_buffer + pe_offset);
	if (inh->Signature != IMAGE_NT_SIGNATURE) return NULL;
	return (BYTE*)inh;
}

IMAGE_NT_HEADERS32* get_nt_hrds32(BYTE* pe_buffer)
{
	BYTE* ptr = get_nt_hrds(pe_buffer);
	if (ptr == NULL) return NULL;

	IMAGE_NT_HEADERS32* inh = (IMAGE_NT_HEADERS32*)(ptr);
	if (inh->FileHeader.Machine == IMAGE_FILE_MACHINE_I386) {
		return inh;
	}
	return NULL;
}

IMAGE_NT_HEADERS64* get_nt_hrds64(const BYTE* pe_buffer)
{
	BYTE* ptr = get_nt_hrds(pe_buffer);
	if (ptr == NULL) return NULL;

	IMAGE_NT_HEADERS32* inh = (IMAGE_NT_HEADERS32*)(ptr);
	if (inh->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64) {
		return (IMAGE_NT_HEADERS64*)(ptr);
	}
	return NULL;
}

bool is64bit(const BYTE* pe_buffer)
{
	BYTE* ptr = get_nt_hrds(pe_buffer);
	if (ptr == NULL) return false;

	IMAGE_NT_HEADERS32* inh = (IMAGE_NT_HEADERS32*)(ptr);
	if (inh->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64) {
		return true;
	}
	return false;
}

IMAGE_DATA_DIRECTORY* get_pe_directory(const BYTE* pe_buffer, DWORD dir_id)
{
	if (dir_id >= IMAGE_NUMBEROF_DIRECTORY_ENTRIES) return NULL;

	BYTE* nt_headers = get_nt_hrds((BYTE*)pe_buffer);
	if (nt_headers == NULL) return NULL;

	IMAGE_DATA_DIRECTORY* peDir = NULL;
	if (is64bit((BYTE*)pe_buffer)) {
		IMAGE_NT_HEADERS64* nt_headers64 = (IMAGE_NT_HEADERS64*)nt_headers;
		peDir = &(nt_headers64->OptionalHeader.DataDirectory[dir_id]);
	}
	else {
		IMAGE_NT_HEADERS32* nt_headers64 = (IMAGE_NT_HEADERS32*)nt_headers;
		peDir = &(nt_headers64->OptionalHeader.DataDirectory[dir_id]);
	}
	if (peDir->VirtualAddress == NULL) {
		return NULL;
	}
	return peDir;
}

ULONGLONG get_module_base(const BYTE* pe_buffer)
{
	bool is64b = is64bit(pe_buffer);
	//update image base in the written content:
	BYTE* payload_nt_hdr = get_nt_hrds(pe_buffer);
	if (payload_nt_hdr == NULL) {
		return 0;
	}
	if (is64b) {
		IMAGE_NT_HEADERS64* payload_nt_hdr64 = (IMAGE_NT_HEADERS64*)payload_nt_hdr;
		return payload_nt_hdr64->OptionalHeader.ImageBase;
	}
	IMAGE_NT_HEADERS32* payload_nt_hdr32 = (IMAGE_NT_HEADERS32*)payload_nt_hdr;
	return static_cast<ULONGLONG>(payload_nt_hdr32->OptionalHeader.ImageBase);
}

PIMAGE_SECTION_HEADER get_section_hdr(const BYTE* payload, const size_t buffer_size, int globalOffset, int &sectionIndex)
{
	if (payload == NULL) return NULL;

	bool is64b = is64bit(payload);

	BYTE* payload_nt_hdr = get_nt_hrds(payload);
	if (payload_nt_hdr == NULL) {
		return NULL;
	}

	IMAGE_FILE_HEADER* fileHdr = NULL;
	DWORD hdrsSize = 0;
	LPVOID secptr = NULL;
	if (is64b) {
		IMAGE_NT_HEADERS64* payload_nt_hdr64 = (IMAGE_NT_HEADERS64*)payload_nt_hdr;
		fileHdr = &(payload_nt_hdr64->FileHeader);
		hdrsSize = payload_nt_hdr64->OptionalHeader.SizeOfHeaders;
		secptr = (LPVOID)((ULONGLONG) & (payload_nt_hdr64->OptionalHeader) + fileHdr->SizeOfOptionalHeader);
	}
	else {
		IMAGE_NT_HEADERS32* payload_nt_hdr32 = (IMAGE_NT_HEADERS32*)payload_nt_hdr;
		fileHdr = &(payload_nt_hdr32->FileHeader);
		hdrsSize = payload_nt_hdr32->OptionalHeader.SizeOfHeaders;
		secptr = (LPVOID)((ULONGLONG) & (payload_nt_hdr32->OptionalHeader) + fileHdr->SizeOfOptionalHeader);
	}


	if (fileHdr->NumberOfSections == 0) 
	{
		//NO sections
		return NULL;
	}

	int found = 0, numberOfSections = 0;
	while (numberOfSections < fileHdr->NumberOfSections)
	{

		ULONGLONG rawAddress = (ULONGLONG) * (DWORD*)((ULONGLONG)secptr + 20);
		ULONGLONG rawsize = (ULONGLONG) * (DWORD*)((ULONGLONG)secptr + 16);
		//cout << std::hex << "rawAddress: " << rawAddress << " rawsize: " << rawsize << endl;

		if (rawAddress <= (ULONGLONG)globalOffset && (ULONGLONG)globalOffset <= (rawAddress + rawsize) )
		{
			found = 1;
			sectionIndex = numberOfSections;
			break;
		}
		numberOfSections++;
		secptr = (PIMAGE_SECTION_HEADER)(
			(ULONGLONG)secptr + (IMAGE_SIZEOF_SECTION_HEADER)
			);
	}

	if (!found) 
	{
		// Not in sections
		return NULL;
	}


	//validate pointer
	if (!validate_ptr((const LPVOID)payload, buffer_size, (const LPVOID)secptr, sizeof(IMAGE_SECTION_HEADER))) {
		return NULL;
	}
	return (PIMAGE_SECTION_HEADER)secptr;
}

BOOL checkPE(const BYTE* buf) 
{
	IMAGE_DOS_HEADER* idh = (IMAGE_DOS_HEADER*)buf;
	if (idh->e_magic != IMAGE_DOS_SIGNATURE) {
		return false;
	}
	return true;
}