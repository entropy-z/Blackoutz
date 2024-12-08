#include <windows.h>

#include <Native.hh>
#include <Macros.h>

// constexpr ULONG ExprHashStringA(
//     _In_ PCHAR String
// ) {
//     ULONG Hash = { 0 };
//     CHAR  Char = { 0 };

//     Hash = 5576;

//     if ( ! String ) {
//         return 0;
//     }

//     while ( ( Char = *String++ ) ) {
//         if ( Char >= 'a' ) {
//             Char -= 0x20;
//         }

//         Hash = ( ( Hash << 5 ) + Hash ) + Char;
//     }

//     return Hash;
// }

ULONG Random32(
	void
) {
    UINT32 Seed = 0;

    _rdrand32_step(&Seed);

    return Seed;
}

ULONG HashString(
    _In_ PVOID  String,
    _In_ SIZE_T Length
) {
    ULONG  Hash  = 5576;
    PUCHAR Ptr  = { 0 };
    UCHAR  Char = { 0 };

    if ( ! String ) {
        return 0;
    }

    Ptr  = ( ( PUCHAR ) String );

    do {
        Char = *Ptr;

        if ( ! Length ) {
            if ( ! *Ptr ) break;
        } else {
            if ( U_PTR( Ptr - U_PTR( String ) ) >= Length ) break;
            if ( !*Ptr ) ++Ptr;
        }

        if ( Char >= 'a' ) {
            Char -= 0x20;
        }

        Hash = ( ( Hash << 5 ) + Hash ) + Char;

        ++Ptr;
    } while ( TRUE );

    return Hash;
}