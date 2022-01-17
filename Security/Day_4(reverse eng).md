
## CCTC Security Day 4
- agenda

exploit research = AORopen
## Admin Data

### CTFd info FOR UPDATED CTF
| Field | Value |
|-|-|
| Stack # | 10 |
| Username | JAMO-005-B |
| Password | YdY8vrRGOsRfhy6 |
| lin.internet | 10.50.21.133 |

## Day 4 Reverse Engineering

### X86_64 ASSEMBLY
- There are 16 general purpose 64 bit registers

| Field | Value |
|-|-|
|%rax|the first return register|
|%rbp|  the base pointer that keeps track of the base of the stack |
|%rsp | the stack pointer that points to the top of the stack|

You will see arguments passed to functions as something like

`[%ebp-0x8]`

- Common Terms

| Field | Value |
|-|-|
|Heap|Memory that can be allocated and deallocated|
|Stack|A contiguous section of memory used for passing arguments|
|General Register|A multipurpose register that can be used by either programmer or user to store data or a memory location address|
|Control Register|A processor register that changes or controls the behavior of a CPU|
|Flags Register|Contains the current state of the processor|

- Memory Offset

There is one instruction pointer register that points to the memory offset of the next instruction in the code segment

|64-bit| lower 32 bits|lower 16 bits|Descrition|
|-|-|-|-|
|RIP|EIP|IP|Instruction Pointer; holds address for next instruction to be executed|

- COMMON INSTRUCTION POINTERS1305 11th St #A, Augusta, GA 30901

| pointer | description|
|-|-|
MOV|move source to destination
PUSH| push source onto stack
POP|Pop top of stack to destination
INC|Increment source by 1
DEC|Decrement source by 1
ADD|Add source to destination
SUB|Subtract source from destination
CMP|Compare 2 values by subtracting them and setting the %RFLAGS register. ZeroFlag set means they are the same.
JMP|Jump to specified location
JLE|Jump if less than or equal
JE|Jump if equal

- REVERSE ENGINEERING WORKFLOW (SOFTWARE)

- Static

- Behavioral

- Dynamic

- Disassembly

- Document Findings

***
***
Objective: Intel has identified that the Donovian_Webserver (192.168.28.111) is hosting binaries via port 80 at the following URI /longTermStorage. We have been tasked with pulling the binaries back into blue space to conduct Reverse Enineering operations. Conduct Reverse Engineering (disassemble, debug) on collected files, determine functionality and methods to successfully execute files.

Tools/Techniques: Ghidra, IDA, and GDB.

Scenario Credentials: FLAG = R3V3R535t@rt0F@ct1v1ty

Prior Approvals:All files can be extracted from the known target "Donovian-Webserver". Only authorized to conduct task on Analyst Workstations.

T1
Hostname: web.site.donovia
IP: 192.168.28.111
OS: unknown
Creds: comrade::StudentWebExploitPassword
Last Known SSH Port: unknown
PSP: Unknown
Malware: Unknown
Action: Extract approved binaries under directory titled "longTermStorage".
