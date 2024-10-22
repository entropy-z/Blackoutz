#ifndef BLACKOUT_PACKAGE_H
#define BLACKOUT_PACKAGE_H

#include <windows.h>

typedef struct {
    UINT32  CommandID;
    PVOID   Buffer;
    size_t  Length;
    size_t  Size;
    BOOL    Encrypt;
} PACKAGE, *PPACKAGE;


typedef struct {
    PCHAR   Original;
    PCHAR   Buffer;
    UINT32  Size;
    UINT32  Length;

    BOOL    Endian;
} PARSER, *PPARSER;

VOID   ParserNew( PPARSER parser, PVOID buffer, UINT32 size );
VOID   ParserDecrypt( PPARSER parser, PBYTE Key, PBYTE IV );
INT16  ParserGetInt16( PPARSER parser );
INT    ParserGetInt32( PPARSER parser );
INT64  ParserGetInt64( PPARSER parser );
BOOL   ParserGetBool( PPARSER parser );
BYTE   ParserGetByte( PPARSER parser );
PCHAR  ParserGetBytes( PPARSER parser, PUINT32 size );
PCHAR  ParserGetString( PPARSER parser, PUINT32 size );
PWCHAR ParserGetWString( PPARSER parser, PUINT32 size );
VOID   ParserDestroy( PPARSER Parser );

PPACKAGE PackageCreate( UINT32 CommandID );
PPACKAGE PackageNew( VOID );

VOID PackageAddInt32(
        PPACKAGE package,
        UINT32 iData
);

VOID PackageAddInt64(
        PPACKAGE Package,
        UINT64 dataInt
);

VOID PackageAddBytes(
        PPACKAGE package,
        PUCHAR data,
        size_t dataSize
);

VOID PackageAddPad(
        PPACKAGE package,
        PUCHAR data,
        size_t dataSize
);

VOID PackageDestroy(
        PPACKAGE package
);

BOOL PackageTransmit(
        PPACKAGE Package,
        PVOID*   Response,
        PSIZE_T  Size
);

VOID PackageAddBool(
    _Inout_ PPACKAGE Package,
    _In_    BOOLEAN  Data
);

VOID PackageTransmitError(
        PPACKAGE Package,
        UINT32   ErrorCode,
        BOOL     NtError
);


VOID PackageAddString( 
        PPACKAGE package, 
        PCHAR data 
);

VOID PackageAddWString( 
        PPACKAGE package, 
        PWCHAR data 
);

#endif
