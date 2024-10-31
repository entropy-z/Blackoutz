#include <Common.h>


/*=================================[ Heap bkAPIs ]=================================*/

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

/*=================================[ Process bkAPIs ]=================================*/

/*!
 * @brief
 * open handler to target process id 
 * 
 * @param DesiredAccess
 * access rights
 * 
 * @param InheritHandle
 * if handle will be inherit
 * 
 * @param ProcessId
 * target process id to open handle
 * 
 * @return
 * target process handle 
 */
HANDLE bkOpenProcess(
    _In_ DWORD DesiredAccess,
    _In_ BOOL  InheritHandle,
    _In_ DWORD ProcessId
);

/*!
 * @brief 
 * terminate target process
 * 
 * @param hProcess
 * handle to target process for terminate
 * 
 * @param ExitStatus
 * Ending status exit of the process
 * 
 * @return
 * returns boolean value based in process terminated operation
 */
BOOL bkTerminateProcess( 
    _In_ HANDLE hProcess,
    _In_ UINT32 ExitStatus
);

BOOL bkCreateProcess(
    _In_ PSTR ProcCmd,
    _In_ BOOL InheritHandle,
    _In_opt_  DWORD   Flags,
    _Out_opt_ HANDLE *ProcessHandle,
    _Out_opt_ DWORD  *ProcessId,
    _Out_opt_ HANDLE *ThreadHandle,
    _Out_opt_ DWORD  *ThreadId
);

/*=================================[ Memory bkAPIs ]=================================*/

/*!
 * @brief
 * alloc private memory 
 * 
 * @param hProcess
 * handle of the target process for memory allocation, optional parameter 
 * that must be passed for remote allocation, if it is in the current process pass NULL
 * 
 * @param BaseAddr
 * 
 */
DWORD bkMemAlloc(
    _In_opt_    HANDLE  hProcess,
    _Inout_opt_ PVOID  *BaseAddr,
    _In_        UINT64  RegionSize,
    _In_        DWORD   AllocationType,
    _In_        DWORD   Protection
);

DWORD bkMemWrite(
    _In_ HANDLE ProcessHandle,
    _In_ PBYTE  MemBaseAddr,
    _In_ PBYTE  Buffer,
    _In_ DWORD  BufferSize
);

DWORD bkMemProtect(
    _In_ HANDLE ProcessHandle,
    _In_ PVOID  BaseAddr,
    _In_ UINT64 RegionSize,
    _In_ DWORD  NewProtection
);

/*=================================[ Miscellaneous bkAPIs ]=================================*/

/*!
 * @brief
 * close target handle 
 * 
 * @param hObject
 * handle for target object to close
 * 
 * @return 
 * returns boolean value based in close handle operation
 */
BOOL bkCloseHandle(
    _In_ HANDLE hObject
);
