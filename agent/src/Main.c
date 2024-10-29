#include <Common.h>
#include <Constexpr.h>

FUNC VOID BlackoutMain(
    _In_ PVOID Param
) {
    BLACKOUT_INSTANCE
    
    BlackoutInit();

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

