### *CCTC OS NOTES DAY 4*

## Windows Boot Process

start8633

windows boot process 
**You can only have one Boot Manager but multiple Boot Loaders**

### 1 Boot Process Overview 
The Boot process is a series of automated tasks that take a computer from pushing the power button to logging into the Desktop. It is a lengthy process, but only certain portions of it can be interacted with easily. The process is broken down into the following steps:

1. Hardware Initialization
2. Loading the Boot Sector or Boot Manager
3. Loading the Operating System from the Boot Sector

**But why do we care about the Boot Process?**

- **Rootkits** are a type of malware that hide themselves and other applications. They typically run in kernel mode, so they have the same privileges as the operating system and can sometimes start before it. Because traditionally, anti-malware software doesn’t load until after the kernel and boot drivers do, rootkits often exploit weaknesses in the startup process:

- **Firmware Rootkits** overwrite the PC’s BIOS or other hardware firmware so the rootkit can start before the OS even loads

- **Bootkits** replace the OS bootloader to load the bootkit before the OS

- **Kernel rootkits** replace a portion of the OS kernel so the rootkit can start when the OS loads

- **Driver rootkits** pretend to be a boot driver that the OS uses to communicate with PC

- **Avenues of Attack** An exposed operating system can be easily used to further Offensive goals such as pivots or compromised to steal data

#### Signifigance of all this:

This is important because you need to know what is on the box, so you can prepare to attack or defend it. If you're an advesary, you can find what exploits exists in the boot process and use them. If you're a defender, you need to know what your system is vulnerable to so you can check on those areas and prep them against attack

Familiarity with both the versions and process, will help you prepare. If you don't know something, LOOK IT UP!!! But don't be hard on yourself, this process takes time.

### 2 BIOS and UEFI
BIOS and UEFI are firmware that ensure critical hardware like SATA devices (Hard Drives), Display Adapters, and SDRAM(Synchronous dynamic random-access memory) are functional then, locates the MBR(Master Boot Record) or GPT(GUID Partition Tables).

Firmware is software coded non-volatile memory devices such as:

1. ROM (Read only memory)

2. EPROM (Electronically Programmable Read only memory)

3. EEPROM (Electronically Erasable Programmable read only memory)

4. Flash memory

BIOS and UEFI do the same thing, but minor differences make UEFI more popular than BIOS in the current day. Without getting into low level specifics some of the benefits of UEFI:

1. UEFI Boots much faster than BIOS systems, especially for Windows machines.

2. UEFI Firmware is usually loaded into flash memory or EEPROM, making it easier to update and patch.

3. UEFI offers SECURED BOOT mode which only allows verified drivers to load.

4. UEFI offers drive support of up to 9 zettabytes, while BIOS only works with 2 terabytes.

#### 2.1: BIOS Master Boot Record
Once the BIOS checks hardware, it finds the MBR (Master Boot Record). The MBR contains Disk Partitions like `/dev/sda1` or `DISK 1 C:\`

The partition contains code that starts the first stage of loading an Operating System, called a Boot Loader

- Boot Loaders

    - Windows 2003 and older used **NTLDR** or New Technology Loader

    - Windows 7 Service Pack 1 and newer uses **bootmgr** or New Technology Loader

From this point the **Boot Loader** takes over and starts the **Operating System**

**Command to remember** : bcdedit | findstr -i winload and should find winload.exe (for when booting up from off) or winload.??? or winresume (which is for when you're in sleep mode)

#### 2.2: UEFI Boot manager

**Detected BIOS or UEFI on Windows:**
```
A1: Type C:\Windows\Panther\Setupact.log | findstr /i "Detected boot environment"
Get-Content C:\Windows\Panther\Setupact.log | Select-String "Detected boot environment"

A2: bcdedit | findstr /i winload
```

### 3 Windows System Initilization 
This is a simplified version of the Windows Boot Process from the kernel (ntoskrnl.exe) to the execution of LogonUi.exe (the process that prompts for user interaction). It is broken into five steps.

1. Loading the Operating System Kernel
2. Initializing the Kernel
3. Starting Subsystems
4. Starting Session 0
5. Starting Session 1

**Kernel is the heart of the operating sysetem**

#### 3.1 Loading the OS Kernel
*On UEFI System*
bootmgfw.efi reads a BCD (Boot Configuration Data) located in the EFI system partition to load the file `winload.efi`

*On BIOS Systems*
bootmgr or NTLDR reads the file `\Boot\BCD` to locate `winload.exe`

The purpose of both `winload` programs is to load basic drivers and start the next part of the Windows Boot Process - loading the Kernel.

#### 3.2: initializing the Kernel
The kernel, as previously discussed, is the heart of the Operating System. Without it, the system cannot function.

In Windows, the kernel is named `Ntoskrnl.exe` and is a critical system file. It does the following tasks during the boot process:

- Loads the Windows Registry

- Loads device drivers

- Starts the system pagefile located at C:\pagefile.sys *This helps store things when need to offload RAM*

- Loads hal.dll

    - hal.dll provides abstraction between hardware interfaces and Ntoskrnl.exe

Once the kernel is done loading it spawns the session management processes `smss.exe` and `csrss.exe`

### 4 Starting Subsystems
**csrss cut time/ threads??**
`smss.exe` (Session Manager Subsystem) does the following tasks:

- Loads environmental variables like `%APPDATA%` and `%COMPUTERNAME%`

- Populates the pagefile located in `C:\pagefile.sys`

- Starts the kernel and user mode sub systems.

- Starts a `csrss.exe` to manage processes and threads for each User Subsystem.

#### 4.1 Kernel Subsystems
The kernel subsystem creates and manages every resource available to Windows by interacting with drivers on the system. It controls things like:

- System power state
- Process creation and threads
- Graphical rendering
- Access Control Lists via the Security Reference Monitor

It is important to understand - users cannot interact directly with any kernel-mode process or even see them

#### 4.2 User Subsystems
==**This is the first part of Windows that a user is able to manipulate.**==
The user subsystem manages all user applications like process creation, internet connectivity, and object access through API calls to `hal.dll`
### 5 Windows BCDEdit Demo 


