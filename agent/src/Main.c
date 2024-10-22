#include <Common.h>
#include <Constexpr.h>

FUNC VOID BlackoutMain(
    _In_ PVOID Param
) {
    BLACKOUT_INSTANCE
        
    BlackoutInit();
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

