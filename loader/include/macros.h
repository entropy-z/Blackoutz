#pragma once

#include <windows.h>

// pseudo handles
#define NtCurrentProcess()              ( (HANDLE)(-1) )
#define NtCurrentThread()               ( (HANDLE)(-2) )
#define NtCurrentProcessToken()         ( (HANDLE)(-4) )
#define NtCurrentThreadToken()          ( (HANDLE)(-5) )
#define NtCurrentThreadEffectiveToken() ( (HANDLE)(-6) )

SIZE_T StringLengthA(
	_In_ LPCSTR String
) ;

//
// type castinng lenght 
//
#define C_8( x )   ( ( INT8 )   ( X ) )
#define C_16( x )  ( ( INT16 )  ( x ) )
#define C_32( x )  ( ( INT32 )  ( x ) )
#define C_64( x )  ( ( INT64 )  ( x ) )
#define U_8( x )  ( ( UINT8 )  ( x ) )
#define U_16( x ) ( ( UINT16 ) ( x ) )
#define U_32( x ) ( ( UINT32 ) ( x ) )
#define U_64( x ) ( ( UINT64 ) ( x ) )

//
// casting macros
//
#define C_PTR( x )   ( ( PVOID    ) ( x ) )
#define U_PTR( x )   ( ( UINT_PTR ) ( x ) )
#define B_PTR( x )   ( ( PBYTE    ) ( x ) )
#define U_PTR32( x ) ( ( ULONG    ) ( x ) )
#define U_PTR64( x ) ( ( ULONG64  ) ( x ) )
#define A_PTR( x )   ( ( PCHAR    ) ( x ) )
#define W_PTR( x )   ( ( PWCHAR   ) ( x ) )

//
// dereference memory macros
//
#define C_DEF( x )   ( * ( PVOID* )  ( x ) )
#define C_DEF08( x ) ( * ( UINT8*  ) ( x ) )
#define C_DEF16( x ) ( * ( UINT16* ) ( x ) )
#define C_DEF32( x ) ( * ( UINT32* ) ( x ) )
#define C_DEF64( x ) ( * ( UINT64* ) ( x ) )

//
// memory related macros
//
#define MmCopy __builtin_memcpy
#define MmSet  __stosb
#define MmZero RtlSecureZeroMemory
