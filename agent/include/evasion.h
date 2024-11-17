#include <common.h>

/*====================================[ Hardware Breakpoint Macros ]====================================*/

typedef enum _DRX{
	Dr0,
	Dr1,
	Dr2,
	Dr3
} DRX, *PDRX;

BOOL  InitHwbp( VOID );
VOID  UninitHwbp( VOID );
BOOL  SetHwbp( PVOID pAddress, PVOID fnHookFunc, DRX Drx );
BOOL  RmvHwbp( DRX Drx );
VOID  SetFuncArg( PCONTEXT  pThreadCtx, ULONG_PTR uValue, DWORD dwParmIndex );
PBYTE GetFuncArg( PCONTEXT pThreadCtx, DWORD dwParmIndex );

#define GETPARM_1( CTX )( GetFuncArg( CTX, 0x1 ) )	
#define GETPARM_2( CTX )( GetFuncArg( CTX, 0x2 ) ) 
#define GETPARM_3( CTX )( GetFuncArg( CTX, 0x3 ) )
#define GETPARM_4( CTX )( GetFuncArg( CTX, 0x4 ) )
#define GETPARM_5( CTX )( GetFuncArg( CTX, 0x5 ) )
#define GETPARM_6( CTX )( GetFuncArg( CTX, 0x6 ) )
#define GETPARM_7( CTX )( GetFuncArg( CTX, 0x7 ) )
#define GETPARM_8( CTX )( GetFuncArg( CTX, 0x8 ) )
#define GETPARM_9( CTX )( GetFuncArg( CTX, 0x9 ) )
#define GETPARM_A( CTX )( GetFuncArg( CTX, 0xA ) )
#define GETPARM_B( CTX )( GetFuncArg( CTX, 0xB ) )

#define SETPARM_1( CTX, VALUE )( SetFuncArg( CTX, VALUE, 0x1 ) )
#define SETPARM_2( CTX, VALUE )( SetFuncArg( CTX, VALUE, 0x2 ) )
#define SETPARM_3( CTX, VALUE )( SetFuncArg( CTX, VALUE, 0x3 ) )
#define SETPARM_4( CTX, VALUE )( SetFuncArg( CTX, VALUE, 0x4 ) )
#define SETPARM_5( CTX, VALUE )( SetFuncArg( CTX, VALUE, 0x5 ) )
#define SETPARM_6( CTX, VALUE )( SetFuncArg( CTX, VALUE, 0x6 ) )
#define SETPARM_7( CTX, VALUE )( SetFuncArg( CTX, VALUE, 0x7 ) )
#define SETPARM_8( CTX, VALUE )( SetFuncArg( CTX, VALUE, 0x8 ) )
#define SETPARM_9( CTX, VALUE )( SetFuncArg( CTX, VALUE, 0x9 ) )
#define SETPARM_A( CTX, VALUE )( SetFuncArg( CTX, VALUE, 0xA ) )
#define SETPARM_B( CTX, VALUE )( SetFuncArg( CTX, VALUE, 0xB ) )

#define CONTINUE_EXEC( CTX )( CTX->EFlags = CTX->EFlags | (1 << 16) )

#ifdef _WIN64
#define RET_VALUE( CTX, VALUE )( (ULONG_PTR)CTX->Rax = (ULONG_PTR)VALUE )
#elif _WIN32
#define RET_VALUE( CTX, VALUE )( (ULONG_PTR)CTX->Eax = (ULONG_PTR)VALUE )
#endif // _WIN64
