#include <Utils.h>
#include <Common.h>

/*=================================[ Heap bkAPIs ]=================================*/

FUNC PVOID bkHeapAlloc(
    _In_ UINT64 Size
) {
    BLACKOUT_INSTANCE

    PVOID VmHeap = Instance()->Win32.RtlAllocateHeap( Instance()->Config.Session.Heap, HEAP_ZERO_MEMORY, Size );

    return VmHeap;
}

FUNC PVOID bkHeapReAlloc(
    _In_ PVOID  Addr,
    _In_ UINT64 Size
) {
    BLACKOUT_INSTANCE

    PVOID VmHeap = Instance()->Win32.RtlReAllocateHeap( Instance()->Config.Session.Heap, HEAP_ZERO_MEMORY, Addr, Size );

    return VmHeap;
}

FUNC BOOL bkHeapFree(
    _In_ PVOID  Data,
    _In_ UINT64 Size
) {
    BLACKOUT_INSTANCE

    MmZero( Data, Size );
    BOOL bSuc = Instance()->Win32.RtlFreeHeap( Instance()->Config.Session.Heap, NULL, Data );
    Data = NULL;

    return bSuc;
}

/*=================================[ Process bkAPIs ]=================================*/

FUNC HANDLE bkOpenProcess(
    _In_ DWORD DesiredAccess,
    _In_ BOOL  InheritHandle,
    _In_ DWORD ProcessId
) {
    BLACKOUT_INSTANCE

    HANDLE hProcess = NULL;
#ifdef _WINAPI
    hProcess = Instance()->Win32.OpenProcess( DesiredAccess, InheritHandle, ProcessId );
#elif _NTAPI
    NTSTATUS  Status = 0;
    CLIENT_ID ClientId = { 0 };
    OBJECT_ATTRIBUTES ProcAttr = RTL_CONSTANT_OBJECT_ATTRIBUTES( NULL, 0 );

    MmZero( ClientId, sizeof( CLIENT_ID ) );
    
    ClientId.UniqueProcess = ProcessId;
    
    Status = Instance()->Win32.NtOpenProcess( &hProcess, DesiredAccess, &ProcAttr, &ClientId );
    if ( Status != STATUS_SUCCESS )
        return INVALID_HANDLE_VALUE;
#endif
    return hProcess;
}

FUNC BOOL bkTerminateProcess( 
    _In_ HANDLE hProcess,
    _In_ UINT32 ExitStatus
) {
    BLACKOUT_INSTANCE

    BOOL bCheck = FALSE;
#ifdef _WINAPI
    bCheck = Instance()->Win32.TerminateProcess( hProcess, ExitStatus );
#elif _NTAPI
    bCheck = Instance()->Win32.NtTerminateProcess( hProcess, ExitStatus );
#endif
    return bCheck;
}

/*=================================[ Memory bkAPIs ]=================================*/

FUNC DWORD bkMemAlloc(
    _In_opt_    HANDLE  hProcess,
    _Inout_opt_ PVOID  *BaseAddr,
    _In_        UINT64 *RegionSize,
    _In_        DWORD   AllocationType,
    _In_        DWORD   Protection
) {
    BLACKOUT_INSTANCE

    DWORD Err = 0;

#ifdef _WINAPI
    if ( hProcess ) {
       *BaseAddr = Instance()->Win32.VirtualAllocEx( hProcess, *BaseAddr, *RegionSize, AllocationType, Protection );
    } else {
        *BaseAddr = Instance()->Win32.VirtualAlloc( *BaseAddr, *RegionSize, AllocationType, Protection );
    }

    Err = NtGetLastError();
#elif _NTAPI
    NTSTATUS Status = 0;

    Status = Instance()->Win32.NtAllocateVirtualMemory( hProcess, &BaseAddr, 0, &RegionSize, AllocationType, Protection );

    Err = Status;
#endif

    return Err;
}

/*=================================[ Thread bkAPIs ]=================================*/


/*=================================[ Miscellaneous bkAPIs ]=================================*/

FUNC BOOL bkCloseHandle(
    _In_ HANDLE hObject
) {
    BLACKOUT_INSTANCE

    BOOL bCheck = FALSE;
#ifdef _WINAPI
    Instance()->Win32.CloseHandle( hObject );
#elif _NTAPI
    Instance()->Win32.NtClose( hObject );
#endif

    return bCheck;
}
