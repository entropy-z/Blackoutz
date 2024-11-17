#include <windows.h>
#include <native.h>

/*
BOOL IsDbgrPresent(
    void
) {
    PTEB Teb  = NtCurrentTeb();
    BOOL bDbg = FALSE;

    bDbg = Teb->ProcessEnvironmentBlock->BeingDebugged;

    return bDbg;
}

BOOL GlobalFlagCheck(
    void
) {
    PTEB Teb = NtCurrentTeb();

    if ( Teb->ProcessEnvironmentBlock->NtGlobalFlag == ( 0x10 | 0x20 | 0x40 ) )
        return TRUE;

    return FALSE;
}

BOOL QueryDbgPortObj(
    void
) {
    ULONG  Status = 0;
    UINT64 IsDbg  = 0;
    UINT64 DbgObj = 0;    

    NtQueryInformationProcess( 
        NtCurrentProcess(), 
        ProcessDebugPort, 
        &IsDbg, sizeof( UINT64 ), NULL 
    );
    
    if ( IsDbg != NULL )
        return TRUE;

    return FALSE;
}

BOOL HwbpCheck(
    void
) {
    CONTEXT Ctx = { .ContextFlags = CONTEXT_DEBUG_REGISTERS };

    GetThreadContext( NtCurrentThread(), &Ctx );

    if ( 
        Ctx.Dr0 != NULL || 
        Ctx.Dr1 != NULL ||
        Ctx.Dr2 != NULL ||
        Ctx.Dr3 != NULL
    );
        return FALSE;

    return TRUE;
}

BOOL BlackListCheck(
    void
) {
    UCHAR x64dbgEnc[] = { 0x6B, 0x8F, 0x4D, 0x0F, 0x1D, 0xF0, 0x38, 0x3B, 0x19, 0x5E };
    UCHAR idaEnc[] = { 0x7A, 0xDD, 0x18, 0x45, 0x1A, 0xEF, 0x73 };
    UCHAR binaryninjaEnc[] = { 0x71, 0xD0, 0x17, 0x0A, 0x0D, 0xEE, 0x78, 0x37, 0x0F, 0x51, 0xA7, 0x85, 0x48, 0xF2, 0x03 };
}
*/