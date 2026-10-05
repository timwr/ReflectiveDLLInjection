//===============================================================================================//
// Copyright (c) 2013, Stephen Fewer of Harmony Security (www.harmonysecurity.com)
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification, are permitted
// provided that the following conditions are met:
//
//     * Redistributions of source code must retain the above copyright notice, this list of
// conditions and the following disclaimer.
//
//     * Redistributions in binary form must reproduce the above copyright notice, this list of
// conditions and the following disclaimer in the documentation and/or other materials provided
// with the distribution.
//
//     * Neither the name of Harmony Security nor the names of its contributors may be used to
// endorse or promote products derived from this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR
// IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
// FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
// CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
// OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.
//===============================================================================================//
// #ifdef ARKARI_OBFUSCATOR
// #pragma optimize("", off)
// #pragma clang optimize off
// #endif
#include "ReflectiveLoader.h"

// ---- RDI debug logging (enabled via -DRDI_DEBUG_LOG) -------------------------
// NOTE: this logger must be safe to execute from the raw PE file copy (before
// the image is mapped). It therefore contains NO .rdata string references:
// every string is built on the stack byte-by-byte, and kernel32 is resolved
// manually by walking the PEB loader lists.
#ifdef RDI_DEBUG_LOG
typedef void *RDI_HANDLE;
typedef RDI_HANDLE (WINAPI *pfnCreateFileA_t)(LPCSTR, DWORD, DWORD, LPVOID, DWORD, DWORD, RDI_HANDLE);
typedef BOOL (WINAPI *pfnWriteFile_t)(RDI_HANDLE, LPCVOID, DWORD, LPDWORD, LPVOID);
typedef BOOL (WINAPI *pfnCloseHandle_t)(RDI_HANDLE);

static int _fold_eq(const char *a, const char *b, DWORD cbLen)
{
	for (DWORD i = 0; i < cbLen; i++) {
		char ca = a[i], cb = b[i];
		if (ca >= 'a' && ca <= 'z') ca -= 0x20;
		if (cb >= 'a' && cb <= 'z') cb -= 0x20;
		if (ca != cb)
			return 0;
	}
	return 1;
}

static void rdi_log(DWORD dwStage, ULONG_PTR val)
{
	// Build the strings we need on the stack (no .rdata references).
	char k32name[13];  // "KERNEL32.DLL"
	char szPath[24];   // "C:\Users\Public\rdi.log"
	char aCreate[12];  // "CreateFileA"
	char aWrite[10];   // "WriteFile"
	char aClose[12];   // "CloseHandle"

	k32name[0] = 'K'; k32name[1] = 'E'; k32name[2] = 'R'; k32name[3] = 'N';
	k32name[4] = 'E'; k32name[5] = 'L'; k32name[6] = '3'; k32name[7] = '2';
	k32name[8] = '.'; k32name[9] = 'D'; k32name[10] = 'L'; k32name[11] = 'L';
	k32name[12] = 0;

	szPath[0] = 'C'; szPath[1] = ':'; szPath[2] = '\\'; szPath[3] = 'U';
	szPath[4] = 's'; szPath[5] = 'e'; szPath[6] = 'r'; szPath[7] = 's';
	szPath[8] = '\\'; szPath[9] = 'P'; szPath[10] = 'u'; szPath[11] = 'b';
	szPath[12] = 'l'; szPath[13] = 'i'; szPath[14] = 'c'; szPath[15] = '\\';
	szPath[16] = 'r'; szPath[17] = 'd'; szPath[18] = 'i'; szPath[19] = '.';
	szPath[20] = 'l'; szPath[21] = 'o'; szPath[22] = 'g'; szPath[23] = 0;

	aCreate[0] = 'C'; aCreate[1] = 'r'; aCreate[2] = 'e'; aCreate[3] = 'a';
	aCreate[4] = 't'; aCreate[5] = 'e'; aCreate[6] = 'F'; aCreate[7] = 'i';
	aCreate[8] = 'l'; aCreate[9] = 'e'; aCreate[10] = 'A'; aCreate[11] = 0;

	aWrite[0] = 'W'; aWrite[1] = 'r'; aWrite[2] = 'i'; aWrite[3] = 't';
	aWrite[4] = 'e'; aWrite[5] = 'F'; aWrite[6] = 'i'; aWrite[7] = 'l';
	aWrite[8] = 'e'; aWrite[9] = 0;

	aClose[0] = 'C'; aClose[1] = 'l'; aClose[2] = 'o'; aClose[3] = 's';
	aClose[4] = 'e'; aClose[5] = 'H'; aClose[6] = 'a'; aClose[7] = 'n';
	aClose[8] = 'd'; aClose[9] = 'l'; aClose[10] = 'e'; aClose[11] = 0;

	// Walk the PEB loader lists (same technique as _resolve_dependencies) to
	// find kernel32's base. Entry base = InMemoryOrderLinks.
	ULONG_PTR uiPeb = 0;
	__asm__ volatile ("mov %0, x18" : "=r"(uiPeb));
	uiPeb = *(ULONG_PTR *)(uiPeb + 0x60);            // TEB->ProcessEnvironmentBlock
	ULONG_PTR uiLdr = *(ULONG_PTR *)(uiPeb + 0x18);  // PEB->Ldr
	ULONG_PTR pEntry = *(ULONG_PTR *)(uiLdr + 0x20); // InMemoryOrderModuleList.Flink

	ULONG_PTR uiKernel32 = 0;
	while (pEntry) {
		ULONG_PTR uiDllBase = *(ULONG_PTR *)(pEntry + 0x20);
		USHORT cbLen = *(USHORT *)(pEntry + 0x48);       // BaseDllName.Length
		ULONG_PTR pwsName = *(ULONG_PTR *)(pEntry + 0x50); // BaseDllName.Buffer
		// Wide -> narrow fold-compare against "KERNEL32.DLL" (12 chars).
		if (cbLen / 2 == 12) {
			char szStack[12];
			for (int i = 0; i < 12; i++)
				szStack[i] = (char)(*(WCHAR *)(pwsName + (ULONG_PTR)i * 2) & 0xFF);
			if (_fold_eq(szStack, k32name, 12)) {
				uiKernel32 = uiDllBase;
				break;
			}
		}
		pEntry = *(ULONG_PTR *)pEntry; // LIST_ENTRY.Flink
	}
	if (!uiKernel32)
		return;

	// Parse kernel32's export table and find the three logging APIs.
	ULONG_PTR uiNtHeaders = uiKernel32 + *(LONG *)(uiKernel32 + 0x3c);
	ULONG_PTR uiOptHeader = uiNtHeaders + 0x18;
	ULONG_PTR uiExportRva = *(DWORD *)(uiOptHeader + 112); // DataDirectory[0].VirtualAddress
	ULONG_PTR uiExportDir = uiKernel32 + uiExportRva;

	DWORD dwNumNames = *(DWORD *)(uiExportDir + 0x18);
	ULONG_PTR uiNames = uiKernel32 + *(DWORD *)(uiExportDir + 0x20);
	ULONG_PTR uiOrds  = uiKernel32 + *(DWORD *)(uiExportDir + 0x24);
	ULONG_PTR uiFuncs = uiKernel32 + *(DWORD *)(uiExportDir + 0x1c);

	pfnCreateFileA_t pCreateFileA = NULL;
	pfnWriteFile_t pWriteFile = NULL;
	pfnCloseHandle_t pCloseHandle = NULL;
	for (DWORD i = 0; i < dwNumNames && (!pCreateFileA || !pWriteFile || !pCloseHandle); i++) {
		ULONG_PTR uiNameRva = *(DWORD *)(uiNames + (ULONG_PTR)i * 4);
		const char *pName = (const char *)(uiKernel32 + uiNameRva);
		WORD wOrd = *(WORD *)(uiOrds + (ULONG_PTR)i * 2);
		ULONG_PTR uiFunc = uiKernel32 + *(DWORD *)(uiFuncs + (ULONG_PTR)wOrd * 4);
		// Exact-length + case-sensitive compare against the stack strings.
		if (pName[0] == 'C' && pName[1] == 'r' && pName[2] == 'e' && pName[3] == 'a' &&
		    pName[4] == 't' && pName[5] == 'e' && pName[6] == 'F' && pName[7] == 'i' &&
		    pName[8] == 'l' && pName[9] == 'e' && pName[10] == 'A' && pName[11] == 0)
			pCreateFileA = (pfnCreateFileA_t)uiFunc;
		else if (pName[0] == 'W' && pName[1] == 'r' && pName[2] == 'i' && pName[3] == 't' &&
		         pName[4] == 'e' && pName[5] == 'F' && pName[6] == 'i' && pName[7] == 'l' &&
		         pName[8] == 'e' && pName[9] == 0)
			pWriteFile = (pfnWriteFile_t)uiFunc;
		else if (pName[0] == 'C' && pName[1] == 'l' && pName[2] == 'o' && pName[3] == 's' &&
		         pName[4] == 'e' && pName[5] == 'H' && pName[6] == 'a' && pName[7] == 'n' &&
		         pName[8] == 'd' && pName[9] == 'l' && pName[10] == 'e' && pName[11] == 0)
			pCloseHandle = (pfnCloseHandle_t)uiFunc;
	}
	if (!pCreateFileA || !pWriteFile || !pCloseHandle)
		return;

	// One file per stage: "C:\Users\Public\rdiXX.log" (XX = stage hex).
	// CREATE_ALWAYS(2) + GENERIC_WRITE(0x40000000): a fresh single-line file
	// per call, avoiding append semantics entirely.
	szPath[16 + 0] = 'r'; szPath[16 + 1] = 'd'; szPath[16 + 2] = 'i';
	szPath[16 + 3] = (char)((dwStage >> 4 & 0xF) < 10 ? '0' + (dwStage >> 4 & 0xF) : 'A' + (dwStage >> 4 & 0xF) - 10);
	szPath[16 + 4] = (char)((dwStage & 0xF) < 10 ? '0' + (dwStage & 0xF) : 'A' + (dwStage & 0xF) - 10);
	szPath[16 + 5] = '.'; szPath[16 + 6] = 'l'; szPath[16 + 7] = 'o';
	szPath[16 + 8] = 'g'; szPath[16 + 9] = 0;

	// "S <val hex16>\r\n" built in a stack buffer.
	char buf[24];
	DWORD len = 0;
	buf[len++] = 'S';
	buf[len++] = ' ';
	for (int shift = 60; shift >= 0; shift -= 4) {
		ULONG_PTR nib = (val >> shift) & 0xF;
		buf[len++] = (char)(nib < 10 ? '0' + nib : 'A' + nib - 10);
	}
	buf[len++] = '\r';
	buf[len++] = '\n';
	RDI_HANDLE h = pCreateFileA(szPath, 0x40000000, 0x3, NULL, 2, 0x80, NULL);
	if (h == (RDI_HANDLE)-1 || !h)
		return;
	DWORD written = 0;
	pWriteFile(h, buf, len, &written, NULL);
	pCloseHandle(h);
}

#define RDI_LOG(stage, val) rdi_log((DWORD)(stage), (ULONG_PTR)(val))
#else
#define RDI_LOG(stage, val) ((void)0)
#endif

// Crash-marker: write a canary to a wild address derived from __LINE__ so a
// crash names the exact source line in the WER event log (faulting address
// 0x4141410000 | (line<<8)). Enabled via -DRDI_DEBUG_FAULT.
#ifdef RDI_DEBUG_FAULT
#define RDI_FAULT(line) \
	do { \
		volatile ULONG *pCanary = (volatile ULONG *)(0x4141410000ULL + ((ULONG_PTR)(line) << 8)); \
		*pCanary = 0x42424242; \
	} while (0)
#else
#define RDI_FAULT(line) ((void)0)
#endif

// Our loader will set this to a pseudo correct HINSTANCE/HMODULE value
HINSTANCE hAppInstance = NULL;

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable : 4127) // conditional expression is constant
#else
static inline __attribute__((always_inline))
unsigned char *__x18_base(void)
{
    unsigned char *base;
    __asm__ volatile ("mov %0, x18" : "=r"(base));
    return base;
}

static inline __attribute__((always_inline))
unsigned long long __readx18qword(unsigned long offset)
{
    return *(volatile unsigned long long *)(__x18_base() + offset);
}
#endif

#ifdef __MINGW32__
#define WIN_GET_CALLER() __builtin_extract_return_addr(__builtin_return_address(0))
#else
#pragma intrinsic(_ReturnAddress)
#define WIN_GET_CALLER() _ReturnAddress()
#endif
// This function can not be inlined by the compiler, ensuring we get the address of the
// instruction that called into the loader, which is critical for finding our own image base.
__declspec(noinline) ULONG_PTR caller(VOID)
{
	return (ULONG_PTR)WIN_GET_CALLER();
}
//===============================================================================================//
#ifdef RDIDLL_NOEXPORT
#define RDIDLLEXPORT
#else
#define RDIDLLEXPORT DLLEXPORT
#endif

//===============================================================================================//
//                                     INTERNAL DEBUGGING CODES                                  //
//===============================================================================================//
#define RDI_ERR_BASE 0xE0000000
#define RDI_SUCCESS (0x00000001)
#define RDI_ERR_FIND_IMAGE_BASE (RDI_ERR_BASE | 0x1000)
#define RDI_ERR_RESOLVE_DEPS (RDI_ERR_BASE | 0x2000) // Generic dependency failure
#define RDI_ERR_ALLOC_MEM (RDI_ERR_BASE | 0x3000)
// Granular codes for dependency resolution:
#define RDI_ERR_NO_KERNEL32 (RDI_ERR_BASE | 0x2100)		 // Failed to find kernel32.dll by hash
#define RDI_ERR_NO_NTDLL (RDI_ERR_BASE | 0x2200)		 // Failed to find ntdll.dll by hash
#define RDI_ERR_NO_EXPORTS (RDI_ERR_BASE | 0x2300)		 // Found kernel32, but couldn't find required exports
#define RDI_ERR_GETSYSCALLS_FAIL (RDI_ERR_BASE | 0x2400) // getSyscalls() failed

// Helper to return a unique error code, making remote debugging possible.
static ULONG_PTR _report_and_exit(DWORD dwErrorCode)
{
	RDI_LOG(0xE0, dwErrorCode);
	return dwErrorCode;
}

//===============================================================================================//
//                                      INTERNAL LOADER CONTEXT                                  //
//===============================================================================================//
// An enum to provide symbolic, compile-time-checked names for syscall array indices.
typedef enum _SYSCALL_INDEX
{
	SyscallIndexAllocateVirtualMemory,
	SyscallIndexProtectVirtualMemory,
	SyscallIndexFlushInstructionCache,
#ifdef ENABLE_STOPPAGING
	SyscallIndexLockVirtualMemory,
#endif
	// This special value is used to keep track of the number of syscall indices and should
	// always be the last element of the enum. Its value will equal the total count of
	// syscalls required by the loader.
	SyscallIndexMax
} SYSCALL_INDEX;

// A context structure to hold all state for the loader, improving readability.
typedef struct
{
	ULONG_PTR uiLibraryAddress;
	ULONG_PTR uiBaseAddress;
	PIMAGE_NT_HEADERS pNtHeaders;
	LOADLIBRARYA pLoadLibraryA;
	GETPROCADDRESS pGetProcAddress;
	PVOID pNtdllBase;

	// Centralized array for all required syscalls.
	Syscall Syscalls[SyscallIndexMax];

} LOADER_CONTEXT, *PLOADER_CONTEXT;


#include "DirectSyscall.c"


//===============================================================================================//
//                                    INTERNAL HELPER FUNCTIONS                                  //
//===============================================================================================//

// STEP 0: Finds the loader's own image base in memory by searching backwards from the caller's address.
static COMPILER_OPTIONS ULONG_PTR _find_image_base(VOID)
{
	ULONG_PTR uiLibraryAddress = caller();
	RDI_LOG(0x12, uiLibraryAddress);
	DWORD dwIters = 0;
	while (TRUE)
	{
		if ((++dwIters & 0xFFFF) == 0)
			RDI_LOG(0x13, uiLibraryAddress);
		PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)uiLibraryAddress;
		if (pDosHeader->e_magic == IMAGE_DOS_SIGNATURE)
		{
			ULONG_PTR uiHeaderValue = pDosHeader->e_lfanew;
			// Sanity check the e_lfanew value to avoid problems with bogus PE signatures.
			if (uiHeaderValue >= sizeof(IMAGE_DOS_HEADER) && uiHeaderValue < 1024)
			{
				if (((PIMAGE_NT_HEADERS)(uiLibraryAddress + uiHeaderValue))->Signature == IMAGE_NT_SIGNATURE)
				{
					RDI_LOG(0x14, uiLibraryAddress);
					return uiLibraryAddress;
				}
			}
		}
		uiLibraryAddress--;
	}
}

// STEP 1: Resolves all required functions and prepares for direct syscalls.
static COMPILER_OPTIONS DWORD _resolve_dependencies(PLOADER_CONTEXT pContext)
{
	ULONG_PTR uiBaseAddress;
	USHORT usCounter;
	DWORD dwHashValue;
	BOOL bFoundKernel32 = FALSE;
	BOOL bFoundNtdll = FALSE;

	// X plicitly allocate a temporary array of pointers to the Syscall entries in our context.
	// P rovide this array to satisfy the getSyscalls function signature.
	// S uppress compiler-driven vectorization by explicitly unrolling the loop.
	// U tilize simple MOV instructions to eliminate 16-byte alignment requirements on 32-bit stacks.
	// C onsider constrained loader execution environments (e.g., within Meterpreter) where alignment isn’t guaranteed.
	// K eep manual assignments to prevent emission of SSE MOVAPS instructions.
	// S afeguard Windows XP builds against potential general protection faults.
	Syscall *pSyscalls[SyscallIndexMax];
	pSyscalls[SyscallIndexAllocateVirtualMemory] = &pContext->Syscalls[SyscallIndexAllocateVirtualMemory];
	pSyscalls[SyscallIndexProtectVirtualMemory] = &pContext->Syscalls[SyscallIndexProtectVirtualMemory];
	pSyscalls[SyscallIndexFlushInstructionCache] = &pContext->Syscalls[SyscallIndexFlushInstructionCache];
	#ifdef ENABLE_STOPPAGING
		pSyscalls[SyscallIndexLockVirtualMemory] = &pContext->Syscalls[SyscallIndexLockVirtualMemory];
	#endif

	// Get the Process Environment Block (PEB) pointer in an architecture-specific way.
#if defined(_M_X64)
	uiBaseAddress = __readgsqword(0x60);
#elif defined(_M_ARM64)
	uiBaseAddress = __readx18qword(0x60);
#elif defined(_M_IX86)
	uiBaseAddress = __readfsdword(0x30);
#elif defined(_M_ARM)
	uiBaseAddress = *(DWORD *)((BYTE *)_MoveFromCoprocessor(15, 0, 13, 0, 2) + 0x30);
#endif

	// Navigate to the list of loaded modules.
	// Ref: https://learn.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb_ldr_data
	uiBaseAddress = (ULONG_PTR)((_PPEB)uiBaseAddress)->pLdr;

	ULONG_PTR pModuleListEntry = (ULONG_PTR)((PPEB_LDR_DATA)uiBaseAddress)->InMemoryOrderModuleList.Flink;

	// Iterate through the loaded modules to find kernel32.dll and ntdll.dll by hash.
	while (pModuleListEntry)
	{
		PLDR_DATA_TABLE_ENTRY pLdrEntry = (PLDR_DATA_TABLE_ENTRY)pModuleListEntry;

		ULONG_PTR pModuleName = (ULONG_PTR)pLdrEntry->BaseDllName.pBuffer;
		DWORD dwModuleHash = 0;
		usCounter = pLdrEntry->BaseDllName.Length;

		// Compute the hash of the module name.
		do
		{
			dwModuleHash = ror(dwModuleHash);
			if (*((BYTE *)pModuleName) >= 'a')
				dwModuleHash += *((BYTE *)pModuleName) - 0x20;
			else
				dwModuleHash += *((BYTE *)pModuleName);
			pModuleName++;
		} while (--usCounter);

		RDI_LOG(0xB0 + usCounter, dwModuleHash);

		if (dwModuleHash == KERNEL32DLL_HASH)
		{
			bFoundKernel32 = TRUE;
			uiBaseAddress = (ULONG_PTR)pLdrEntry->DllBase;

			// Parse the kernel32 export table to find LoadLibraryA and GetProcAddress.
			// We must correctly handle both 32-bit and 64-bit PE headers.
			PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)(uiBaseAddress + ((PIMAGE_DOS_HEADER)uiBaseAddress)->e_lfanew);
			ULONG_PTR uiExportDirRva = 0;

			if (pNtHeaders->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
			{
				// 64-bit PE header
				uiExportDirRva = ((PIMAGE_NT_HEADERS64)pNtHeaders)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
			}
			else
			{
				// 32-bit PE header
				uiExportDirRva = ((PIMAGE_NT_HEADERS32)pNtHeaders)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
			}

			PIMAGE_EXPORT_DIRECTORY pExportDir = (PIMAGE_EXPORT_DIRECTORY)(uiBaseAddress + uiExportDirRva);
 
			PDWORD pdwNameArray = (PDWORD)(uiBaseAddress + pExportDir->AddressOfNames);
			PWORD pwNameOrdinals = (PWORD)(uiBaseAddress + pExportDir->AddressOfNameOrdinals);
			PDWORD pdwAddressArray = (PDWORD)(uiBaseAddress + pExportDir->AddressOfFunctions);

			for (usCounter = 0; usCounter < pExportDir->NumberOfNames; usCounter++)
			{
				dwHashValue = _hash((char *)(uiBaseAddress + pdwNameArray[usCounter]));
				if (dwHashValue == LOADLIBRARYA_HASH)
					pContext->pLoadLibraryA = (LOADLIBRARYA)(uiBaseAddress + pdwAddressArray[pwNameOrdinals[usCounter]]);
				else if (dwHashValue == GETPROCADDRESS_HASH)
					pContext->pGetProcAddress = (GETPROCADDRESS)(uiBaseAddress + pdwAddressArray[pwNameOrdinals[usCounter]]);
				if (pContext->pLoadLibraryA && pContext->pGetProcAddress)
					break;
			}
		}
		else if (dwModuleHash == NTDLLDLL_HASH)
		{
			bFoundNtdll = TRUE;
			pContext->pNtdllBase = pLdrEntry->DllBase;
		}

		if (bFoundKernel32 && bFoundNtdll)
			break;

		pModuleListEntry = DEREF(pModuleListEntry);
	}

	if (!bFoundKernel32)
		return RDI_ERR_NO_KERNEL32;
	if (!bFoundNtdll)
		return RDI_ERR_NO_NTDLL;
	if (!pContext->pLoadLibraryA || !pContext->pGetProcAddress)
		return RDI_ERR_NO_EXPORTS;

	RDI_LOG(3, pContext->pLoadLibraryA);
	RDI_LOG(4, pContext->pGetProcAddress);
	RDI_LOG(0xC0, pContext->pNtdllBase);

	if (!getSyscalls(pContext->pNtdllBase, pSyscalls, SyscallIndexMax))
		return RDI_ERR_GETSYSCALLS_FAIL;

	RDI_LOG(5, pSyscalls[0] ? pSyscalls[0]->pStub : 0);

	return RDI_SUCCESS;
}

static COMPILER_OPTIONS BOOL _load_image_into_memory(PLOADER_CONTEXT pContext)
{
	SIZE_T RegionSize = pContext->pNtHeaders->OptionalHeader.SizeOfImage;

	pContext->uiBaseAddress = 0;
	if (rdiNtAllocateVirtualMemory(&pContext->Syscalls[SyscallIndexAllocateVirtualMemory], (HANDLE)-1, (PVOID *)&pContext->uiBaseAddress, 0, &RegionSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE) != 0)
		return FALSE;

#ifdef ENABLE_STOPPAGING
	// This call can fail on older systems (e.g. Server 2012) with
	// STATUS_WORKING_SET_QUOTA, but this failure is not critical.
	rdiNtLockVirtualMemory(&pContext->Syscalls[SyscallIndexLockVirtualMemory], (HANDLE)-1, (PVOID *)&pContext->uiBaseAddress, &RegionSize, 1);
#endif

	// Copy the PE headers from the original image to the newly allocated buffer.
	DWORD dwSizeOfHeaders = pContext->pNtHeaders->OptionalHeader.SizeOfHeaders;
	PBYTE pSourceBase = (PBYTE)pContext->uiLibraryAddress;
	PBYTE pDestinationBase = (PBYTE)pContext->uiBaseAddress;

	while (dwSizeOfHeaders--)
		*pDestinationBase++ = *pSourceBase++;

	PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pContext->pNtHeaders);
	for (USHORT i = 0; i < pContext->pNtHeaders->FileHeader.NumberOfSections; i++, pSectionHeader++)
	{
		PBYTE pDestination = (PBYTE)(pContext->uiBaseAddress + pSectionHeader->VirtualAddress);
		PBYTE pSource = (PBYTE)(pContext->uiLibraryAddress + pSectionHeader->PointerToRawData);
		DWORD dwSectionSize = pSectionHeader->SizeOfRawData;

		while (dwSectionSize--)
			*pDestination++ = *pSource++;
	}

	return TRUE;
}

// STEP 4: Process the image's Import Address Table (IAT).
static COMPILER_OPTIONS void _process_imports(PLOADER_CONTEXT pContext)
{
	PIMAGE_DATA_DIRECTORY pDataDirectory = &pContext->pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	if (pDataDirectory->Size == 0)
		return;

	PIMAGE_IMPORT_DESCRIPTOR pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)(pContext->uiBaseAddress + pDataDirectory->VirtualAddress);

	// Iterate through each imported DLL.
	for (; pImportDesc->Name; pImportDesc++)
	{
		ULONG_PTR uiLibraryAddress = (ULONG_PTR)pContext->pLoadLibraryA((LPCSTR)(pContext->uiBaseAddress + pImportDesc->Name));
		if (!uiLibraryAddress)
			continue;

		PIMAGE_THUNK_DATA pOriginalFirstThunk = (PIMAGE_THUNK_DATA)(pContext->uiBaseAddress + pImportDesc->OriginalFirstThunk);
		PIMAGE_THUNK_DATA pFirstThunk = (PIMAGE_THUNK_DATA)(pContext->uiBaseAddress + pImportDesc->FirstThunk);

		// Iterate through each function imported from the DLL.
		for (; pFirstThunk->u1.AddressOfData; pFirstThunk++, pOriginalFirstThunk++)
		{
			if (pOriginalFirstThunk && (pOriginalFirstThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG))
			{
				// Import by ordinal
				PIMAGE_NT_HEADERS pLibNtHeaders = (PIMAGE_NT_HEADERS)(uiLibraryAddress + ((PIMAGE_DOS_HEADER)uiLibraryAddress)->e_lfanew);
				PIMAGE_DATA_DIRECTORY pLibDataDirectory = &pLibNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
				PIMAGE_EXPORT_DIRECTORY pLibExportDir = (PIMAGE_EXPORT_DIRECTORY)(uiLibraryAddress + pLibDataDirectory->VirtualAddress);
				PDWORD pdwAddressArray = (PDWORD)(uiLibraryAddress + pLibExportDir->AddressOfFunctions);

				pFirstThunk->u1.Function = (uiLibraryAddress + pdwAddressArray[IMAGE_ORDINAL(pOriginalFirstThunk->u1.Ordinal) - pLibExportDir->Base]);
			}
			else
			{
				// Import by name
				PIMAGE_IMPORT_BY_NAME pImportByName = (PIMAGE_IMPORT_BY_NAME)(pContext->uiBaseAddress + pFirstThunk->u1.AddressOfData);
				pFirstThunk->u1.Function = (ULONG_PTR)pContext->pGetProcAddress((HMODULE)uiLibraryAddress, (LPCSTR)pImportByName->Name);
			}
		}
	}
}

// STEP 5: Process the image's base relocations.
static COMPILER_OPTIONS void _process_relocations(PLOADER_CONTEXT pContext)
{
	ULONG_PTR uiDelta = pContext->uiBaseAddress - pContext->pNtHeaders->OptionalHeader.ImageBase;
	if (uiDelta == 0)
		return; // No relocation needed if loaded at preferred base.

	PIMAGE_DATA_DIRECTORY pDataDirectory = &pContext->pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	if (pDataDirectory->Size == 0)
		return;

	PIMAGE_BASE_RELOCATION pBaseReloc = (PIMAGE_BASE_RELOCATION)(pContext->uiBaseAddress + pDataDirectory->VirtualAddress);

	for (; pBaseReloc->SizeOfBlock; pBaseReloc = (PIMAGE_BASE_RELOCATION)((ULONG_PTR)pBaseReloc + pBaseReloc->SizeOfBlock))
	{
		ULONG_PTR pRelocationBlockBase = (pContext->uiBaseAddress + pBaseReloc->VirtualAddress);
		ULONG uiEntryCount = (pBaseReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(IMAGE_RELOC);
		PIMAGE_RELOC pReloc = (PIMAGE_RELOC)((ULONG_PTR)pBaseReloc + sizeof(IMAGE_BASE_RELOCATION));

		// Perform the relocation, skipping IMAGE_REL_BASED_ABSOLUTE as required.
		// We don't use a switch statement to avoid the compiler building a jump table
		// which would not be very position independent.
		// Iterate through each relocation block.
		for (ULONG i = 0; i < uiEntryCount; i++, pReloc++)
		{
			if (pReloc->type == IMAGE_REL_BASED_DIR64)
				*(ULONG_PTR *)((ULONG_PTR)pRelocationBlockBase + pReloc->offset) += uiDelta;
			else if (pReloc->type == IMAGE_REL_BASED_HIGHLOW)
				*(DWORD *)((ULONG_PTR)pRelocationBlockBase + pReloc->offset) += (DWORD)uiDelta;
#if defined(_M_ARM)
			// Note: On ARM, the compiler optimization /O2 seems to introduce an off by one issue, possibly a code gen bug.
			// Using /O1 instead avoids this problem.
			else if (pReloc->type == IMAGE_REL_BASED_ARM_MOV32T)
			{
				// Handle 32-bit ARM-specific relocations for MOVW/MOVT instruction pairs.
				// This involves extracting and re-encoding a 16-bit immediate value.
				// Get the MOV.T instruction's DWORD value (We add 4 to the offset to go past the first MOV.W which handles the low word).
				DWORD dwInstruction = *(DWORD *)((ULONG_PTR)pRelocationBlockBase + pReloc->offset + sizeof(DWORD));
				// Flip the words to get the instruction as expected (account for endianness/instruction packing).
				dwInstruction = MAKELONG(HIWORD(dwInstruction), LOWORD(dwInstruction));
				// Sanity check we are processing a MOVT instruction.
				if ((dwInstruction & ARM_MOV_MASK) == ARM_MOVT)
				{
					// Pull out the encoded 16-bit immediate value (high portion of the address-to-relocate).
					WORD wImm = (WORD)(dwInstruction & 0x000000FF);
					wImm |= (WORD)((dwInstruction & 0x00007000) >> 4);
					wImm |= (WORD)((dwInstruction & 0x04000000) >> 15);
					wImm |= (WORD)((dwInstruction & 0x000F0000) >> 4);
					// Apply the relocation delta to the target address.
					DWORD dwAddress = ((WORD)HIWORD(uiDelta) + wImm) & 0xFFFF;
					// Create a new instruction with the same opcode and register parameters.
					dwInstruction &= ARM_MOV_MASK2;
					// Patch in the relocated address, re-encoding the immediate value.
					dwInstruction |= (DWORD)(dwAddress & 0x00FF);
					dwInstruction |= (DWORD)(dwAddress & 0x0700) << 4;
					dwInstruction |= (DWORD)(dwAddress & 0x0800) << 15;
					dwInstruction |= (DWORD)(dwAddress & 0xF000) << 4;
					// Flip the instructions words and patch back into the code.
					*(DWORD *)((ULONG_PTR)pRelocationBlockBase + pReloc->offset + sizeof(DWORD)) = MAKELONG(HIWORD(dwInstruction), LOWORD(dwInstruction));
				}
			}
#endif
			else if (pReloc->type == IMAGE_REL_BASED_HIGH)
				*(WORD *)((ULONG_PTR)pRelocationBlockBase + pReloc->offset) += HIWORD(uiDelta);
			else if (pReloc->type == IMAGE_REL_BASED_LOW)
				*(WORD *)((ULONG_PTR)pRelocationBlockBase + pReloc->offset) += LOWORD(uiDelta);
		}
	}
}

// STEP 6: Set the correct memory protections on each section of the newly loaded image.
static COMPILER_OPTIONS void _set_memory_protections(PLOADER_CONTEXT pContext)
{
	PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pContext->pNtHeaders);
	for (USHORT i = 0; i < pContext->pNtHeaders->FileHeader.NumberOfSections; i++, pSectionHeader++)
	{
		PVOID pSectionBase = (PVOID)(pContext->uiBaseAddress + pSectionHeader->VirtualAddress);
		SIZE_T dwSectionSize = pSectionHeader->Misc.VirtualSize;
		DWORD dwProtect = 0, dwOldProtect;
		// Characteristics processing courtesy of Dark Vort∑x, 2021-06-01
		// See: https://bruteratel.com/research/feature-update/2021/06/01/PE-Reflection-Long-Live-The-King/
		DWORD characteristics = pSectionHeader->Characteristics;

		if (dwSectionSize == 0)
			continue;

		// Map PE section characteristics to Windows memory protection constants.
		if (characteristics & IMAGE_SCN_MEM_EXECUTE)
		{
			if (characteristics & IMAGE_SCN_MEM_READ)
				dwProtect = (characteristics & IMAGE_SCN_MEM_WRITE) ? PAGE_EXECUTE_READWRITE : PAGE_EXECUTE_READ;
			else
				dwProtect = (characteristics & IMAGE_SCN_MEM_WRITE) ? PAGE_EXECUTE_WRITECOPY : PAGE_EXECUTE;
		}
		else
		{
			if (characteristics & IMAGE_SCN_MEM_READ)
				dwProtect = (characteristics & IMAGE_SCN_MEM_WRITE) ? PAGE_READWRITE : PAGE_READONLY;
			else if (characteristics & IMAGE_SCN_MEM_WRITE)
				dwProtect = PAGE_WRITECOPY;
			else
				dwProtect = PAGE_NOACCESS;
		}

		rdiNtProtectVirtualMemory(&pContext->Syscalls[SyscallIndexProtectVirtualMemory], (HANDLE)-1, &pSectionBase, &dwSectionSize, dwProtect, &dwOldProtect);
	}
}

// STEP 7 & 8: Call the image's entry point and return its address.
static COMPILER_OPTIONS ULONG_PTR _call_entry_point(PLOADER_CONTEXT pContext, LPVOID lpParameter)
{
	// Get the address of the entry point.
	ULONG_PTR pEntryPoint = (pContext->uiBaseAddress + pContext->pNtHeaders->OptionalHeader.AddressOfEntryPoint);

	// Flush the instruction cache to avoid executing stale code after relocations.
	rdiNtFlushInstructionCache(&pContext->Syscalls[SyscallIndexFlushInstructionCache], (HANDLE)-1, NULL, 0);

	RDI_LOG(0xA0, pEntryPoint);

// If we are injecting a DLL via LoadRemoteLibraryR, we call DllMain and pass in our parameter (via the DllMain lpReserved parameter).
// Otherwise, if we are injecting a DLL via a stub, we call DllMain with no parameter.
#ifdef REFLECTIVEDLLINJECTION_VIA_LOADREMOTELIBRARYR
	((DLLMAIN)pEntryPoint)((HINSTANCE)pContext->uiBaseAddress, DLL_PROCESS_ATTACH, lpParameter);
#else
	((DLLMAIN)pEntryPoint)((HINSTANCE)pContext->uiBaseAddress, DLL_PROCESS_ATTACH, NULL);
#endif
	return pEntryPoint;
}

//===============================================================================================//
//                                         PUBLIC LOADER                                         //
//===============================================================================================//
// This is our position independent reflective DLL loader/injector
// On 32-bit systems, the default __stdcall convention causes name mangling (_FunctionName@Bytes).
// By explicitly declaring the loader as __cdecl, we ensure the name is exported simply
// as "ReflectiveLoader" on all platforms, which is what the injector expects.
#ifdef REFLECTIVEDLLINJECTION_VIA_LOADREMOTELIBRARYR
RDIDLLEXPORT COMPILER_OPTIONS ULONG_PTR __cdecl ReflectiveLoader(LPVOID lpParameter)
#else
RDIDLLEXPORT COMPILER_OPTIONS ULONG_PTR WINAPI ReflectiveLoader(VOID)
#endif
{
	// NOTE:    Zeroing by hand instead of SecureZeroMemory/memset: the loader runs
	//          from the raw PE file copy before its IAT is bound, so it must not
	//          call any imported function (SecureZeroMemory can lower to a memset
	//          import call via an unbound IAT thunk).

	LOADER_CONTEXT context;
	{
		volatile ULONG_PTR *p = (volatile ULONG_PTR *)&context;
		for (SIZE_T i = 0; i < sizeof(LOADER_CONTEXT) / sizeof(ULONG_PTR); i++)
			p[i] = 0;
	}
	RDI_LOG(1, 0);
	RDI_LOG(0x11, (ULONG_PTR)&context);

	context.Syscalls[SyscallIndexAllocateVirtualMemory].dwCryptedHash = ZWALLOCATEVIRTUALMEMORY_HASH;
	context.Syscalls[SyscallIndexAllocateVirtualMemory].dwNumberOfArgs = 6;

	context.Syscalls[SyscallIndexProtectVirtualMemory].dwCryptedHash = ZWPROTECTVIRTUALMEMORY_HASH;
	context.Syscalls[SyscallIndexProtectVirtualMemory].dwNumberOfArgs = 5;

	context.Syscalls[SyscallIndexFlushInstructionCache].dwCryptedHash = ZWFLUSHINSTRUCTIONCACHE_HASH;
	context.Syscalls[SyscallIndexFlushInstructionCache].dwNumberOfArgs = 3;

#ifdef ENABLE_STOPPAGING
	context.Syscalls[SyscallIndexLockVirtualMemory].dwCryptedHash = ZWLOCKVIRTUALMEMORY_HASH;
	context.Syscalls[SyscallIndexLockVirtualMemory].dwNumberOfArgs = 4;
#endif

	// STEP 0: Find our own image base in memory.
	context.uiLibraryAddress = _find_image_base();
	if (!context.uiLibraryAddress)
		return _report_and_exit(RDI_ERR_FIND_IMAGE_BASE);

	context.pNtHeaders = (PIMAGE_NT_HEADERS)(context.uiLibraryAddress + ((PIMAGE_DOS_HEADER)context.uiLibraryAddress)->e_lfanew);

	// STEP 1: Resolve kernel32.dll/ntdll.dll functions and prepare for direct syscalls.
	DWORD dwResolveResult = _resolve_dependencies(&context);
	if (dwResolveResult != RDI_SUCCESS)
		return _report_and_exit(dwResolveResult);

	// STEP 2 & 3: Allocate a new permanent memory location and copy the image.
	RDI_LOG(2, context.uiLibraryAddress);

	if (!_load_image_into_memory(&context))
		return _report_and_exit(RDI_ERR_ALLOC_MEM);

	RDI_LOG(6, context.uiBaseAddress);

	// STEP 4: Process the image's import table.
	_process_imports(&context);
	RDI_LOG(7, 0);

	// STEP 5: Process the image's base relocations.
	_process_relocations(&context);
	RDI_LOG(8, context.uiBaseAddress - context.pNtHeaders->OptionalHeader.ImageBase);

	// STEP 6: Set final memory protections on the image sections.
	_set_memory_protections(&context);
	RDI_LOG(9, context.pNtHeaders->OptionalHeader.AddressOfEntryPoint);

	// STEP 7 & 8
	ULONG_PTR uiEntryPoint = _call_entry_point(&context,
#ifdef REFLECTIVEDLLINJECTION_VIA_LOADREMOTELIBRARYR
								 lpParameter
#else
								 NULL
#endif
	);
	RDI_LOG(0xA1, uiEntryPoint);
	return uiEntryPoint;

	// STEP 7 & 8: Call the DLL's entry point and return the new base address.
	return _call_entry_point(&context,
#ifdef REFLECTIVEDLLINJECTION_VIA_LOADREMOTELIBRARYR
							 lpParameter
#else
							 NULL
#endif
	);
}
//===============================================================================================//

#ifndef REFLECTIVEDLLINJECTION_CUSTOM_DLLMAIN
// Default DllMain if the user does not supply their own.
COMPILER_OPTIONS BOOL  WINAPI DllMain(HINSTANCE hinstDLL, DWORD dwReason, LPVOID lpReserved)
{
	BOOL bReturnValue = TRUE;
	switch (dwReason)
	{
	case DLL_QUERY_HMODULE:
		if (lpReserved != NULL)
			*(HMODULE *)lpReserved = hAppInstance;
		break;
	case DLL_PROCESS_ATTACH:
		hAppInstance = hinstDLL;
		break;
	case DLL_PROCESS_DETACH:
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
		break;
	}
	return bReturnValue;
}
#endif

#ifdef _MSC_VER
#pragma warning(pop)
#endif