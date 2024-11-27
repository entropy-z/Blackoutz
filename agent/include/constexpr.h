#ifndef BLACKOUT_CONSTEXPR_H
#define BLACKOUT_CONSTEXPR_H

#pragma once

#include <macros.h>

#define HASH_STR( x ) ExprHashStringA( ( x ) )

CONSTEXPR ULONG ExprHashStringA(_In_ PCHAR String)
{
    ULONG Hash = 5576;
    CHAR Char  = 0;

    if (!String) {
        return 0;
    }

    while ((Char = *String++)) {
        if (Char >= 'a' && Char <= 'z') {
            Char -= 0x20;
        }

        Hash = ((Hash << 5) + Hash) + Char;
    }

    return Hash;
}


#endif //BLACKOUT_CONSTEXPR_H
