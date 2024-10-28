#include <Utils.h>
#include <Common.h>

FUNC PVOID bkHeapAlloc(
    UINT64 Size
) {
    BLACKOUT_INSTANCE

    PVOID VmHeap = Instance()->Win32.RtlAllocateHeap( Instance()->Config.Session.Heap, HEAP_ZERO_MEMORY, Size );

    return VmHeap;
}

FUNC PVOID bkHeapReAlloc(
    PVOID  Addr,
    UINT64 Size
) {
    BLACKOUT_INSTANCE

    PVOID VmHeap = Instance()->Win32.RtlReAllocateHeap( Instance()->Config.Session.Heap, HEAP_ZERO_MEMORY, Addr, Size );

    return VmHeap;
}

FUNC BOOL bkHeapFree(
    PVOID  Data,
    UINT64 Size
) {
    BLACKOUT_INSTANCE

    MmSet( Data, 0x00, Size );
    BOOL bSuc = Instance()->Win32.RtlFreeHeap( Instance()->Config.Session.Heap, NULL, Data );
    Data = NULL;

    return bSuc;
}

