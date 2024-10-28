#include <windows.h>

#include "./include/Native.h"

INT WINAPI WinMain(
    HINSTANCE hInstance, 
    HINSTANCE hPrevInstance, 
    LPSTR lpCmdLine, 
    INT nShowCmd
) {
    RTL_HEAP_PARAMETERS RtlHeapParam = { 0 };
        
    RtlSecureZeroMemory( &RtlHeapParam, sizeof( RTL_HEAP_PARAMETERS ) );

    PVOID Heap = RtlCreateHeap( HEAP_GROWABLE, NULL, 0, 0, 0, &RtlHeapParam );
    
    printf( "[I] Own Heap @ 0x%p\n", Heap );
}