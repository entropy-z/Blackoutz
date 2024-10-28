# Blackoutz Implant
Blackoutz is a versatile, custom-built agent for the Havoc Command and Control (C2) framework, designed with extensive capabilities for stealth, resilience, and network flexibility in red team operations.

- **Multi-Architecture Compatibility**: Supports x86 and x64 architectures, deployable in shellcode, executable, service, and DLL formats.

- **Evasion and Obfuscation Techniques**: Equipped with advanced evasion features such as stack spoofing, APC-based sleep obfuscation, and a COFF loader for undetected loading of modules. Malleable profiles, direct/indirect syscalls, and optional anti-sandbox and anti-debugging features enhance detection evasion.

- **Injection and Process Management**: Offers robust process injection methods, including threadless injection, module stomping, module overloading, APC, RDI, and classic injection. Also features spawnto capabilities with PPID spoofing, argument spoofing, and a Block DLL policy for stealthy spawning.

- **Networking and Communication**: Facilitates covert communication over HTTP/S and SMB, supports SOCKS5 for network tunneling, and enables reverse port forwarding for flexible connectivity.

- **Token Management and Privilege Escalation**: Integrates with "spawnas" for pass-the-hash (PTH) attacks, a token vault, and a privilege escalation module for streamlined access elevation.

- **Persistence and Anti-Detection**: Offers configurable persistence options and is equipped with a kill date and working hours restriction for controlled execution. Bypasses ETW and AMSI using hardware breakpoints and can self-delete after prolonged communication failure.

- **Lateral Movement and Command Handling**: Enables lateral movement through SC Manager, DCOM, WMI, and WinRM, with a registry-based handler for remote command management.