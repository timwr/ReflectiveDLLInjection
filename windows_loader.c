// The entrypoint stub lives in shellcode_entry.c and the embedded DLL bytes in
// shellcode_data.c; source order in CMakeLists.txt defines the shellcode blob
// layout [entrypoint][DLL bytes][helpers + entry_function].
//
// A plain C reference to the cross-TU symbol would make clang emit a
// .refptr.myapplib_dll indirection in .rdata (outside the dumped shellcode
// blob), so the address is resolved with inline asm PC-relative addressing.
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

static inline const unsigned char *shellcode_dll_base(void)
{
	const unsigned char *p;
#if defined(__aarch64__) || defined(_M_ARM64)
	__asm__ volatile (
			"adrp %0, myapplib_dll\n\t"
			"add  %0, %0, :lo12:myapplib_dll\n"
			: "=r"(p));
#else
	// x86_64: RIP-relative lea is position-independent. The whole .text
	// section (the shellcode blob) is copied verbatim at runtime, and source
	// and target of the displacement stay in the same relative layout, so the
	// link-time resolved offset remains valid at the injection address.
	__asm__ volatile (
			"lea myapplib_dll(%%rip), %0\n"
			: "=r"(p));
#endif
	return p;
}

#define DEREF( name )*(UINT_PTR *)(name)
#define DEREF_64( name )*(DWORD64 *)(name)
#define DEREF_32( name )*(DWORD *)(name)
#define DEREF_16( name )*(WORD *)(name)
#define DEREF_8( name )*(BYTE *)(name)

typedef ULONG_PTR (* REFLECTIVELOADER)( LPVOID );
typedef BOOL (WINAPI * DLLMAIN)( HINSTANCE, DWORD, LPVOID );

static DWORD Rva2Offset(DWORD dwRva, PIMAGE_NT_HEADERS pNtHeaders)
{
	PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);

	// Iterate through the PE sections to find which one contains the RVA.
	for (WORD i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++, pSectionHeader++)
	{
		// Check if the RVA is within the current section's virtual address space.
		// We use VirtualSize for the upper bound, as this is the true size of the
		// section in memory. SizeOfRawData is its size on disk, which can be smaller,
		// and using it can lead to failing to find RVAs on some platforms (e.g., ARM64).
		if (dwRva >= pSectionHeader->VirtualAddress && dwRva < (pSectionHeader->VirtualAddress + pSectionHeader->Misc.VirtualSize))
		{
			// The file offset is calculated by taking the RVA, subtracting the section's
			// base virtual address, and adding the section's file offset (PointerToRawData).
			return (dwRva - pSectionHeader->VirtualAddress + pSectionHeader->PointerToRawData);
		}
	}

	// If the RVA was not found in any section, it must be within the PE header itself.
	// In this case, the RVA is the same as the file offset.
	if (dwRva < pNtHeaders->OptionalHeader.SizeOfHeaders)
	{
		return dwRva;
	}

	return 0;
}

int compare(const char *X, const char *Y)
{
	while (*X && *Y)
	{
		if (*X != *Y) {
			return 0;
		}

		X++;
		Y++;
	}

	return (*Y == '\0');
}

// Precise strcmp replacement: the loader DLL is compiled with -nostdlib
// (it is raw shellcode), so no CRT is available to link against.
static int my_strcmp(const char *X, const char *Y)
{
	while (*X && *X == *Y)
	{
		X++;
		Y++;
	}

	return (unsigned char)*X - (unsigned char)*Y;
}

const char* _strstr(const char* X, const char* Y)
{
	while (*X != '\0')
	{
		if ((*X == *Y) && compare(X, Y)) {
			return X;
		}
		X++;
	}

	return NULL;
}

DWORD GetReflectiveLoaderOffset(VOID* lpReflectiveDllBuffer, LPCSTR cpReflectiveLoaderName)
{
	UINT_PTR uiBaseAddress = (UINT_PTR)lpReflectiveDllBuffer;
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_NT_HEADERS pNtHeaders = NULL;

	// Validate the PE headers.
	pDosHeader = (PIMAGE_DOS_HEADER)uiBaseAddress;
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
		return 0;

	pNtHeaders = (PIMAGE_NT_HEADERS)(uiBaseAddress + pDosHeader->e_lfanew);
	if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE)
		return 0;

	// Get the export directory RVA.
	PIMAGE_DATA_DIRECTORY pDataDirectory = &pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	if (pDataDirectory->VirtualAddress == 0)
		return 0;

	// Convert the RVA to a file offset to get the export directory structure.
	DWORD dwExportDirOffset = Rva2Offset(pDataDirectory->VirtualAddress, pNtHeaders);
	if (dwExportDirOffset == 0)
		return 0;

	PIMAGE_EXPORT_DIRECTORY pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(uiBaseAddress + dwExportDirOffset);

	// Get pointers to the three critical arrays within the EAT, using file offsets.
	PDWORD pdwAddressArray = (PDWORD)(uiBaseAddress + Rva2Offset(pExportDirectory->AddressOfFunctions, pNtHeaders));
	PDWORD pdwNameArray = (PDWORD)(uiBaseAddress + Rva2Offset(pExportDirectory->AddressOfNames, pNtHeaders));
	PWORD pwNameOrdinals = (PWORD)(uiBaseAddress + Rva2Offset(pExportDirectory->AddressOfNameOrdinals, pNtHeaders));

	// Search for the loader function by name or by ordinal.
	if (((DWORD_PTR)cpReflectiveLoaderName >> 16) == 0)
	{
		// By ordinal
		WORD wOrdinal = LOWORD((DWORD_PTR)cpReflectiveLoaderName);
		DWORD dwOrdinalBase = pExportDirectory->Base;

		if (wOrdinal < dwOrdinalBase || wOrdinal >= dwOrdinalBase + pExportDirectory->NumberOfFunctions)
			return 0;

		DWORD dwFunctionRva = pdwAddressArray[wOrdinal - dwOrdinalBase];
		return Rva2Offset(dwFunctionRva, pNtHeaders);
	}
	else
	{
		// By name
		for (DWORD i = 0; i < pExportDirectory->NumberOfNames; i++)
		{
			LPCSTR cpExportedFunctionName = (LPCSTR)(uiBaseAddress + Rva2Offset(pdwNameArray[i], pNtHeaders));

			// Precise name match (no CRT strcmp available in -nostdlib shellcode).
			if (my_strcmp(cpExportedFunctionName, cpReflectiveLoaderName) == 0)
			{
				WORD wFunctionOrdinal = pwNameOrdinals[i];
				DWORD dwFunctionRva = pdwAddressArray[wFunctionOrdinal];
				return Rva2Offset(dwFunctionRva, pNtHeaders);
			}
		}
	}

	return 0;
}

int entry_function()
{
	// Pinned to .text so the dumped shellcode blob stays self-contained
	// (clang would otherwise emit this string constant into .rdata).
	static __attribute__((section(".text"))) const char reflectiveloader_name[] = "ReflectiveLoader";
	const unsigned char *pMyapplibDll = shellcode_dll_base();
	DWORD dwReflectiveLoaderOffset = GetReflectiveLoaderOffset((VOID*)pMyapplibDll, reflectiveloader_name);
	if( dwReflectiveLoaderOffset != 0 )
	{
		REFLECTIVELOADER pReflectiveLoader = (REFLECTIVELOADER)((UINT_PTR)pMyapplibDll + dwReflectiveLoaderOffset);
		// ReflectiveLoader() maps the image and calls the entry point/DllMain itself.
		// Pass NULL explicitly: a no-arg call would leave a stale x0 as lpParameter
		// on ARM64, which the loader forwards to the entry point.
		(void)pReflectiveLoader(NULL);
	}

	return 0;
}


