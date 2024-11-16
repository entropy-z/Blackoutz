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

#define HASH_STR( x ) ExprHashStringA( ( x ) )

CONSTEXPR ULONG ExprHashStringA(
    _In_ PCHAR String
) {
    ULONG Hash = { 0 };
    CHAR  Char = { 0 };

    Hash = H_MAGIC_KEY;

    if ( ! String ) {
        return 0;
    }

    while ( ( Char = *String++ ) ) {
        /* turn current character to uppercase */
        if ( Char >= 'a' ) {
            Char -= 0x20;
        }

        Hash = ( ( Hash << H_MAGIC_SEED ) + Hash ) + Char;
    }

    return Hash;
}

PVOID LdrModuleAddr(
    _In_ ULONG Hash
);

PVOID LdrFuncAddr( 
    _In_ PVOID BaseModule, 
    _In_ ULONG FuncName 
); 

SIZE_T WCharStringToCharString(
    _Inout_ PCHAR Destination, 
    _In_    PWCHAR Source, 
    _In_    SIZE_T MaximumAllowed
);