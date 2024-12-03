#include <common.h>

/*=================================[ Heap bkAPIs ]=================================*/

/*!
 * @brief
 * Allocates memory in the heap.
 * 
 * @param Size
 * Size of the memory allocation, in bytes.
 * 
 * @return 
 * Returns the address of the allocated memory, or NULL if the allocation fails.
 * 
 * @retval NULL if memory allocation fails.
 * 
 * @note
 * The returned memory is uninitialized. Ensure you properly initialize or use the memory.
 * 
 * @warning
 * Remember to free the allocated memory with `bkHeapFree` to avoid memory leaks.
 */
PVOID bkHeapAlloc( 
    UINT64 Size
);

/*!
 * @brief 
 * Reallocates memory in the heap.
 * 
 * @param Addr
 * Address of the memory block to reallocate, which must have been previously allocated by `bkHeapAlloc`.
 * 
 * @param Size
 * New size for the reallocation, in bytes.
 * 
 * @return
 * Returns the address of the reallocated memory block, or NULL if the reallocation fails.
 * 
 * @retval NULL if memory reallocation fails.
 * 
 * @note
 * If `Addr` is NULL, the function behaves like `bkHeapAlloc`.
 * 
 * @warning
 * If the reallocation fails, the original memory block remains unchanged, and you must still free it if it is no longer needed.
 */
PVOID bkHeapReAlloc(
    PVOID  Addr,
    UINT64 Size
);

/*!
 * @brief
 * Frees memory in the heap.
 * 
 * @param Data
 * Address of the memory block to free, which must have been previously allocated by `bkHeapAlloc`.
 * 
 * @param Size
 * Size of the memory block to zero out before freeing, in bytes.
 * 
 * @return
 * Returns a boolean value indicating the success of the memory-free operation.
 * 
 * @retval TRUE if the memory is freed successfully.
 * @retval FALSE if the free operation fails.
 * 
 * @note
 * Zeroing the memory before freeing can help prevent data leaks if sensitive information was stored.
 * 
 * @warning
 * Passing an invalid or already freed address can cause undefined behavior.
 */
BOOL bkHeapFree(
    PVOID  Data,
    UINT64 Size
);

/*=================================[ Process bkAPIs ]=================================*/

/*!
 * @brief
 * Opens a handle to the specified process by its process ID.
 * 
 * @param DesiredAccess
 * Access rights for the handle. Specifies the level of access required.
 * 
 * @param InheritHandle
 * Determines if the handle can be inherited by child processes.
 * 
 * @param ProcessId
 * ID of the target process for which the handle will be opened.
 * 
 * @param ProcessHandle
 * Output parameter that receives the handle to the target process.
 * 
 * @return
 * Returns the last error code based on WinAPI or NTAPI, depending on the compilation.
 * 
 * @retval ERROR_SUCCESS if the handle is opened successfully.
 * @retval ERROR_ACCESS_DENIED if access to the target process is denied.
 * 
 * @note
 * Ensure that `DesiredAccess` permissions align with your intended operations on the process.
 * 
 * @warning
 * Using an incorrect ProcessId may lead to unexpected behavior or errors.
 */
 DWORD bkProcessOpen(
    _In_  DWORD   DesiredAccess,
    _In_  BOOL    InheritHandle,
    _In_  DWORD   ProcessId,
    _Out_ HANDLE *ProcessHandle
);

/*!
 * @brief 
 * Terminates the specified target process.
 * 
 * @param hProcess
 * Handle to the target process to be terminated.
 * 
 * @param ExitStatus
 * Exit code to be set for the terminated process.
 * 
 * @return
 * Returns the last error code based on WinAPI or NTAPI, depending on the compilation.
 * 
 * @retval TRUE if the process is terminated successfully.
 * @retval FALSE if the termination operation fails.
 * 
 * @note
 * Ensure that `hProcess` has sufficient rights to terminate the process.
 * 
 * @warning
 * Terminating a process can cause data loss or corruption if the process is handling sensitive operations.
 */
DWORD bkProcessTerminate( 
    _In_ HANDLE hProcess,
    _In_ UINT32 ExitStatus
);

/*!
 * @brief
 * Creates a new process with the specified command and settings.
 * 
 * @param ProcCmd
 * Command line to execute for the new process.
 * 
 * @param InheritHandle
 * Determines if the handle can be inherited by child processes.
 * 
 * @param Flags
 * Creation flags that control the priority and behavior of the new process.
 * 
 * @param ProcessHandle
 * Optional output parameter to receive a handle to the newly created process.
 * 
 * @param ProcessId
 * Optional output parameter to receive the ID of the newly created process.
 * 
 * @param ThreadHandle
 * Optional output parameter to receive a handle to the primary thread of the new process.
 * 
 * @param ThreadId
 * Optional output parameter to receive the ID of the primary thread of the new process.
 * 
 * @return
 * Returns the last error code based on WinAPI or NTAPI, depending on the compilation.
 * 
 * @retval TRUE if the process is created successfully.
 * @retval FALSE if process creation fails.
 * 
 * @note
 * Ensure the `ProcCmd` is a valid command line for successful execution.
 * 
 * @warning
 * Misconfigured `Flags` may lead to unintended behavior in the newly created process.
 */
DWORD bkProcessCreate(
    _In_      PSTR    ProcCmd,
    _In_      BOOL    InheritHandle,
    _In_      BOOL    Pipe,
    _In_opt_  DWORD   Flags,
    _Out_opt_ HANDLE *ProcessHandle,
    _Out_opt_ DWORD  *ProcessId,
    _Out_opt_ HANDLE *ThreadHandle,
    _Out_opt_ DWORD  *ThreadId
);

/*=================================[ Thread bkAPIs ]=================================*/

/*!
 * @brief
 * Creates a new thread in the specified process.
 * 
 * @param ProcessHandle
 * Handle to the target process in which the thread will be created. 
 * 
 * @param BaseAddr
 * Starting address of the thread, typically the entry point of the function to be executed.
 * 
 * @param Parameter
 * Optional parameter passed to the thread function at BaseAddr.
 * 
 * @param Flags
 * Flags controlling thread creation and behavior.
 * 
 * @param StackSize
 * Initial stack size for the new thread.
 * 
 * @param ThreadId
 * Optional pointer to receive the new thread's identifier.
 * 
 * @param ThreadHandle
 * Optional pointer to receive a handle to the newly created thread.
 * 
 * @return
 * Returns the last error code based on WinAPI or NTAPI, depending on the compilation.
 * 
 * @retval ERROR_SUCCESS if the thread is created successfully.
 * @retval ERROR_ACCESS_DENIED if the function lacks permission to create the thread.
 * 
 * @note
 * Ensure the process has sufficient privileges to create threads.
 * 
 * @warning
 * Avoid passing a NULL ProcessHandle for remote thread creation; this may lead to undefined behavior.
 */
DWORD bkThreadCreate( 
    _In_     HANDLE  ProcessHandle,
    _In_     PVOID   BaseAddr,
    _In_opt_ PVOID   Parameter,
    _In_     DWORD   Flags,
    _In_     DWORD   StackSize,
    _In_opt_ PDWORD  ThreadId,
    _In_opt_ PHANDLE ThreadHandle
);

/*!
 * @brief
 * Terminates the specified thread and sets its exit code.
 * 
 * @param ThreadHandle
 * Handle to the thread to be terminated. This handle must have the THREAD_TERMINATE access right.
 * 
 * @param ExitCode
 * Exit code to be set for the terminated thread. This value is returned to the thread's creator.
 * 
 * @return
 * Returns the last error code based on WinAPI or NTAPI, depending on the compilation.
 * 
 * @retval ERROR_SUCCESS if the thread is terminated successfully.
 * @retval ERROR_INVALID_HANDLE if the provided thread handle is not valid.
 * @retval ERROR_ACCESS_DENIED if the handle does not have the required access rights to terminate the thread.
 * 
 * @note
 * Use this function with caution, as terminating a thread can result in resource leaks or inconsistent application state.
 * 
 * @warning
 * Avoid terminating threads that are performing critical operations, as this may lead to data corruption or other unintended side effects.
 */
DWORD bkThreadTerminate(
    _In_ HANDLE ThreadHandle,
    _In_ DWORD  ExitCode
);

/*!
 * @brief
 * Suspends the specified thread.
 * 
 * @param ThreadHandle
 * Handle to the thread to be suspended. This handle must have the THREAD_SUSPEND_RESUME access right.
 * 
 * @return
 * Returns the last error code based on WinAPI or NTAPI, depending on the compilation.
 * 
 * @retval ERROR_SUCCESS if the thread is suspended successfully.
 * @retval ERROR_INVALID_HANDLE if the provided thread handle is not valid.
 * @retval ERROR_ACCESS_DENIED if the handle does not have the required access rights to suspend the thread.
 * 
 * @note
 * Ensure that the thread is not already suspended before calling this function to avoid deadlock situations.
 * 
 * @warning
 * Suspending threads can lead to issues in multithreaded applications. Use this function with caution, as it can cause resource contention or deadlocks.
 */
DWORD bkThreadSuspend(
    _In_ HANDLE ThreadHandle
);

/*!
 * @brief
 * Resumes a suspended thread.
 * 
 * @param ThreadHandle
 * Handle to the thread to be resumed. This handle must have the THREAD_SUSPEND_RESUME access right.
 * 
 * @return
 * Returns the last error code based on WinAPI or NTAPI, depending on the compilation.
 * 
 * @retval ERROR_SUCCESS if the thread is resumed successfully.
 * @retval ERROR_INVALID_HANDLE if the provided thread handle is not valid.
 * @retval ERROR_ACCESS_DENIED if the handle does not have the required access rights to resume the thread.
 * 
 * @note
 * Ensure that the thread was previously suspended using a corresponding suspend function before calling this function.
 * 
 * @warning
 * Resuming a thread that was not suspended may lead to undefined behavior or application instability. Use with caution.
 */
DWORD bkThreadResume(
    _In_ HANDLE ThreadHandle
);

/*=================================[ Memory bkAPIs ]=================================*/

/*!
 * @brief
 * Allocates private memory in a specified process.
 * 
 * @param ProcessHandle
 * Handle of the target process for memory allocation. This is an optional parameter 
 * and must be provided for remote allocation; if allocating in the current process, pass NULL.
 * 
 * @param BaseAddr
 * Base address for the memory allocation. Can be NULL to allow the system to choose an address. 
 * Returns the memory address of the allocation.
 * 
 * @param RegionSize
 * Size of the memory region to allocate.
 * 
 * @param AllocationType
 * Type of memory allocation.
 * 
 * @param Protection
 * Memory protection for the allocated region.
 * 
 * @return
 * Returns the last error code according to WinAPI or NTAPI, depending on the compilation.
 * 
 * @retval ERROR_SUCCESS if memory is allocated successfully.
 * @retval ERROR_ACCESS_DENIED if the function lacks permission to allocate memory.
 * 
 * @note
 * Use proper cleanup (e.g., VirtualFree) after allocation to prevent memory leaks.
 * 
 * @warning
 * Specifying an invalid BaseAddr can cause allocation failure or unexpected behavior.
 */
DWORD bkMemAlloc(
    _In_opt_    HANDLE  ProcessHandle,
    _Inout_opt_ PVOID  *BaseAddr,
    _In_        UINT64  RegionSize,
    _In_        DWORD   AllocationType,
    _In_        DWORD   Protection
);

/*!
 * @brief
 * Writes data to a specified memory region.
 *
 * @param ProcessHandle
 * Handle to the target process for writing. Can be null for the current process.
 *
 * @param MemBaseAddr
 * Base memory address where the data will be written.
 *
 * @param Buffer
 * Pointer to the buffer containing the data to be written into memory.
 *
 * @param BufferSize
 * Size of the buffer to write.
 *
 * @return
 * Returns the last error according to WinAPI or NTAPI, depending on the compilation.
 */
DWORD bkMemWrite(
    _In_ HANDLE ProcessHandle,
    _In_ PBYTE  MemBaseAddr,
    _In_ PBYTE  Buffer,
    _In_ DWORD  BufferSize
);

/*!
 * @brief
 * Changes the memory protection of a specified region.
 * 
 * @param ProcessHandle
 * Handle to the target process whose memory protection will be modified.
 * For the current process, pass NULL.
 * 
 * @param BaseAddr
 * Base address of the memory region whose protection will be changed.
 * 
 * @param RegionSize
 * Size of the memory region to modify.
 * 
 * @param NewProtection
 * New protection level to apply to the memory region.
 * 
 * @return
 * Returns the last error code based on WinAPI or NTAPI, depending on the compilation.
 * 
 * @retval ERROR_SUCCESS if the protection is changed successfully.
 * @retval ERROR_INVALID_PARAMETER if the provided parameters are invalid.
 * 
 * @note
 * Ensure the process has sufficient privileges to modify memory protection.
 * 
 * @warning
 * Changing memory protection of shared memory regions may affect other threads or processes.
 */
DWORD bkMemProtect(
    _In_  HANDLE ProcessHandle,
    _In_  PVOID  BaseAddr,
    _In_  UINT64 RegionSize,
    _In_  DWORD  NewProtection
);

/*!
 * @brief
 * Retrieves information about a range of pages in the virtual memory of a specified process.
 * 
 * @param ProcessHandle
 * Handle to the target process. If NULL, the current process is used.
 * 
 * @param BaseAddress
 * Base address of the memory region to query.
 * 
 * @param AllocationBase
 * Pointer to receive the base address of the allocation region that contains the specified address.
 * 
 * @param AllocationProtect
 * Pointer to receive the memory protection of the allocation region.
 * 
 * @param BaseAddressRt
 * Pointer to receive the base address of the region that contains the specified address.
 * 
 * @param Protect
 * Pointer to receive the memory protection of the queried region.
 * 
 * @param RegionSize
 * Pointer to receive the size of the region, in bytes.
 * 
 * @param State
 * Pointer to receive the state of the pages in the region.
 * 
 * @param Type
 * Pointer to receive the type of pages in the region.
 * 
 * @return
 * Returns the last error code based on WinAPI or NTAPI, depending on the compilation.
 * 
 * @retval ERROR_SUCCESS if the memory information is retrieved successfully.
 * @retval ERROR_INVALID_PARAMETER if any provided parameter is invalid.
 * @retval ERROR_ACCESS_DENIED if access to the memory region is denied.
 * 
 * @note
 * Ensure that the process handle has sufficient rights to query the memory information.
 * 
 * @warning
 * Querying memory regions that do not belong to the specified process can lead to access violations.
 */
DWORD bkMemQuery(
    _In_opt_ HANDLE  ProcessHandle,
    _In_     PVOID   BaseAddress,
    _Out_    PVOID  *AllocationBase,
    _Out_    DWORD  *AllocationProtect,
    _Out_    PVOID  *BaseAddressRt,
    _Out_    DWORD  *Protect,
    _Out_    DWORD  *RegionSize,
    _Out_    DWORD  *State,
    _Out_    DWORD  *Type
);

DWORD bkMemFree(
    _In_opt_ HANDLE ProcessHandle,
    _In_     PVOID  MemAddress,
    _In_     UINT64 SizeToFree
);

/*=================================[ Token bkAPIs ]=================================*/

/*!
 * @brief
 * Opens an access token associated with a process or thread.
 * 
 * @param TargetHandle
 * Handle to the process or thread for which to open the access token.
 * 
 * @param AccessRights
 * Specifies the desired access rights for the token handle.
 * 
 * @param TokenHandle
 * Pointer to a handle that will receive the token handle.
 * 
 * @param ObjectType
 * Specifies the type of the target object. Use `0x01` for a process and `0x02` for a thread.
 * 
 * @return
 * Returns the last error code based on WinAPI or NTAPI, depending on the compilation.
 * 
 * @retval ERROR_SUCCESS if the token is opened successfully.
 * @retval ERROR_INVALID_PARAMETER if an invalid `ObjectType` is specified.
 * @retval ERROR_ACCESS_DENIED if the handle does not have the required access rights to open the token.
 * 
 * @note
 * Ensure that `TargetHandle` has the appropriate permissions for the specified access rights.
 * 
 * @warning
 * Use caution when opening a token with elevated privileges, as it can lead to privilege escalation vulnerabilities if not properly managed.
 */
DWORD bkTokenOpen(
    _In_ HANDLE  TargetHandle,
    _In_ DWORD   AccessRights,
    _In_ PHANDLE TokenHandle,
    _In_ UINT16  ObjectType
);

/*=================================[ Miscellaneous bkAPIs ]=================================*/

/*!
 * @brief
 * Closes a handle to the specified object.
 * 
 * @param hObject
 * Handle to the target object to close.
 * 
 * @return 
 * Returns a boolean value indicating the success of the handle closing operation.
 * 
 * @retval TRUE if the handle is closed successfully.
 * @retval FALSE if closing the handle fails.
 * 
 * @note
 * After closing, the handle becomes invalid. Ensure it is not used in any subsequent calls.
 * 
 * @warning
 * Closing an already closed or invalid handle may result in undefined behavior.
 */
BOOL bkHandleClose(
    _In_ HANDLE hObject
);
