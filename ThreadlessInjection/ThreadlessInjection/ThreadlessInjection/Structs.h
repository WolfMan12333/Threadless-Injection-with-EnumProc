#pragma once

#ifndef STRUCTS
#define STRUCTS

#include <Windows.h>

#define STATUS_SUCCESS	    0x00000000
#define NtCurrentProcess()  ( (HANDLE)-1 )
#define NtCurrentThread()   ( (HANDLE)-2 )
#define NT_SUCCESS(STATUS)	(((NTSTATUS)(STATUS)) >= STATUS_SUCCESS)


typedef NTSTATUS(NTAPI* fnNtAllocateVirtualMemory)(
	IN		HANDLE			ProcessHandle,
	IN OUT	PVOID*			BaseAddress,
	IN		ULONG_PTR		ZeroBits, 
	IN OUT	PSIZE_T			RegionSize,
	IN		ULONG			AllocationType,
	IN		ULONG			Protect
);

typedef NTSTATUS(NTAPI* fnNtProtectVirtualMemory)(
	IN		HANDLE		ProcessHandle,
	IN OUT	PVOID*		BaseAddress,
	IN OUT	PSIZE_T		NumberOfBytesToProtect,
	IN		ULONG		NewAccessProtection,
	OUT		PULONG		OldAccessPRotection
);

typedef NTSTATUS(NTAPI* fnNtWriteVirtualMemory)(
	IN	HANDLE	ProcessHandle, 
	IN	PVOID	BaseAddress,
	IN	PVOID	Buffer,
	IN	ULONG	NumberOfBytesToWrite,
	OUT PULONG	NumberOfBytesWritten OPTIONAL
);

#endif // !STRUCTS



