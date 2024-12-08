#include <windows.h>

#define print( x ) printf( "[!] %s failed err: %d\n", x, GetLastError() ); return 1;

int main( 
    int argc, 
    char* argv[] 
) { 
    PVOID ( *BlackStart )( PVOID );

    BOOL   Success     = FALSE;
    HANDLE hFile       = NULL;
    UINT32 FileSize    = 0;
    UINT32 OldProt     = 0;

    hFile = CreateFileA( 
        argv[1], GENERIC_READ, FILE_SHARE_READ | 
        FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 
        FILE_ATTRIBUTE_NORMAL, NULL 
    );
    if ( !hFile || hFile == INVALID_HANDLE_VALUE ) { print( "file creation" ) };

    FileSize = GetFileSize( hFile, 0 );
    if ( !FileSize ) { print( "file size" ) }

    BlackStart = VirtualAlloc( NULL, FileSize, 0x3000, 0x40 );

    Success = ReadFile( hFile, BlackStart, FileSize, 0, 0 );

    BlackStart( 0 );
}