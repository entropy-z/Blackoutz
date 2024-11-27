#include <windows.h>

VOID MsgBox(
    VOID
) {
    MessageBoxA( NULL, "box reflected", "blackout", MB_OK );
}

int WINAPI WinMain(
    HINSTANCE hInstance, 
    HINSTANCE hPrevInstance, 
    LPSTR lpCmdLine, 
    int nShowCmd
) {
    printf( "Running in process id: %d\n", GetCurrentProcessId() );

    VirtualAlloc( NULL, 0x1000, 0x3000, 0x20 );
    VirtualAlloc( NULL, 0x1000, 0x3000, 0x40 );

    Sleep( 50000 );
}
