#pragma once

#include <windows.h>

#define H_MAGIC_KEY          5381
#define H_MAGIC_SEED         5
#define H_MODULE_NTDLL       0x70e61753
#define H_MODULE_KERNELBASE  0x6F1259F0
#define H_MODULE_KERNEL32    0xadd31df0

#ifdef  __cplusplus
#define CONSTEXPR         constexpr
#define TEMPLATE_TYPENAME template <typename T>
#define INLINE            inline
#else
#define CONSTEXPR
#define TEMPLATE_TYPENAME
#define INLINE
#endif

typedef HMODULE (*fnLoadLibraryA)( LPCSTR );

ULONG HashString(
    _In_ PVOID  String,
    _In_ SIZE_T Length
);

ULONG ExprHashStringA(
    _In_ PCHAR String
);

#define HASH_STR( x ) ExprHashStringA( ( x ) )

PVOID LdrLoadModule(
    _In_ ULONG Hash
);

PVOID LdrLoadFunc( 
    _In_ PVOID BaseModule, 
    _In_ ULONG FuncName 
); 

SIZE_T WCharStringToCharString(
    _Inout_ PCHAR Destination, 
    _In_    PWCHAR Source, 
    _In_    SIZE_T MaximumAllowed
);