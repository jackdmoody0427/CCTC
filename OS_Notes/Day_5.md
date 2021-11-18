### *CCTC OS NOTES DAY 5*

| Challenge Name | Flag |
| -- | -- | 
| linux_boot_2| start3675  |

**Persistence in Linux one of teh go to is the configuraton provide and `/etc/profile`, `/etc/profile.d`, `/etc/bashrc`**
**KEY: First set of notes are from SFG, second from the slides**
## Linux Boot Process
Big Mike Got Killed In Russia: BIOS, MBR (master boot record), Kernel, Init, Runlevels 
### 1 Boot Process Overview

### 2 BIOS and UEFI
BIOS and UEFI are firmware that ensure critical hardware like SATA devices (Hard Drives), Display Adapters, and SDRAM(Synchronous dynamic random-access memory) are functional then, locates the MBR(Master Boot Record) or GPT(GUID Partition Tables).

**The BIOS runs and exits before the Linux system even starts. Flash memory on the motherboard contains the BIOS. Remember that firmware is different from software.**

Firmware is software coded non-volatile memory devices such as: . ROM (Read only memory) . EPROM (Electronically Programmable Read only memory) . EEPROM (Electronically Erasable Programmable read only memory) . Flash memory

**Non-volatile memory does not clear itself after a restart, while volatile memory does.** 

BIOS

- First program to run on startup (Flash or ROM)
    -If stored in flash memory → becomes a target for BIOS Rootkits
- Performs POST - Power On Self Test
- Performs system integrity checks
- Builds a device tree (mice, keyboard, hard drive, video cards, etc..)
- Reads and executes the first sector on the boot disk (MBR) to load bootloader to memory
#### 2.1 Difference Between BIOS and UEFI Firmare 
BIOS and UEFI do the same thing, but minor differences make UEFI more popular than BIOS in the current day. Without getting into low level specifics some of the benefits of UEFI:

1. UEFI Boots much faster than BIOS systems, especially for Windows machines.
2. UEFI Firmware is usually loaded into flash memory or EEPROM, making it easier to update and patch.
3. UEFI offers SECURED BOOT mode which only allows verified drivers to load.
4. UEFI offers drive support of up to 9 zettabytes', while BIOS only works with 2 terabytes.
### 3 1st Stage Bootloader 
1st Stage Bootloaders are the Master Boot Records(MBR) and the GUID Partition Tables (GPT) because they are the first part of loading an operating system. They locate and finish loading the 2nd stage bootloader known as GRUB

#### 3.1 Master Boot Record (MBR)
The Master Boot Record contains information on partitions locations on the hard drive. Partitions contain the 2nd stage bootloader known as the GRUB(Grand Unified Bootloader).
**MBR is a Boot Sector**
Once the BIOS loads the bootstrap in the MBR. The bootstrap is the initial section of code that contains a bootloader known as GRUB broken into two stages. The first stage is GRUB stage 1, which loads Grub Stage 2 from the selected active partition. Grub Stage 2 is not located in the MBR, but further in the hard drive.

MBR - Master Boot Record

- Located at the very beginning of the bootable disk (512 bytes) and contains the primary bootloader, partition table and MBR validity check
- Contains code for GRUB - Grand Unified Boot Loader
- (Note: Could also contain LILO - Linux Loader)
- First 512 bytes of the HD
- Hard disks utilizing a MBR can have a maximum of 4 primary partitions and a max size of 2 TB each.
    - Typically the MBR is located on /dev/hda or /dev/sda (/dev/vda)
    - It contains information about GRUB (or LILO or other Boot Loader system)

Other related commands:

- du - disk usage: summarize disk usage of the set of FILEs
- df - disk free : displays the amount of disk space available on the file system

 lsblk - lists information about all available - or specified - block devices

### 4 2nd Stage Bootloader (GRUB)
The MBR in Grub Stage 1 loads the 2nd stage bootloader, named Grub Stage 2 or GRUB. GRUB Stage 2 rests inside the selected active partition mounted in /boot or in a completely separate partition.
#### 4.1: GRUB
GRUB(Grand Unified Bootloader) has one purpose - to load the Linux Kernel a user choses from a location in the hard drive. The GRUB has two stages which load it from two separate locations.

On BIOS Systems using MBR
1. Stage 1 : `boot.img` located in the first 440 bytes of the MBR loads…​
2. Stage 1.5 : `core.img` located in the MBR between the bootstrap and first partition. It loads…​
3. Stage 2 : `/boot/grub/i386-pc/normal.mod` which loads the grub menu and then reads
    a. `/boot/grub/grub.cfg` Which displays a list of Linux kernels available to load on the system

On UEFI Systems using GPT
1. Stage 1 : `grubx64.efi` Located on an EFI partition or in /boot loads…​
2. Stage 2 : `/boot/grub/x86_64-efi/normal.mod`
    a. `/boot/grub/grub.cfg` Which displays a list of Linux kernels available to load on the system

GRUB - Grand Unified Bootloader

- Dynamically configurable with the capability to make changes during boot
    - Config File - /boot/grub/menu.lst
    - Altering boot entries, selecting different kernels, and modifying the initial RAM disk (initrd)
- OS Selection screen where if no choice is made, default kernel specified in the grub configuration file
- Bootloader (GRUB) passes text based kernel parameters (Ex. root=UUID=70cc6e89…,ro, splash). If not recognized, the option will be passed to init (i.e. ‘-s’ for single-user mode)
- Kernel options are sometimes configurable at the menu with the ‘e’ key
### 5 Linux Kernel
The Kernel is the heart of a Operating System. It has complete control on everything within it such as memory management, device management, Input/output Device request control, and managing process scheduling with the Central processing unit.

The Linux Kernel originated from the Unix kernel and is unique from Windows in that it is :
1. A Monolithic Kernel
System calls all functionality to the user such as CPU scheduling, memory management, and file management. A systemcall is a way in which a program requests services from the kernel. Everything that occurs on the system occurs through a systemcall
2.  Modular
Modules are extensions to base functionality of the Linux Operating System. This modularity allows for modifications baseline system functionality without rebuilding the kernel and failures will not stop the machine from starting.

Kernel

- Uncompresses itself into RAM
- Establishes memory management, detects CPU type, page tables
- Mounts the root ‘/ ’ filesystem
- kernel is process 0 [kthreadd]
- Executes /sbin/init or systemd daemon, the very first process started by the kernel with a process ID (PID) of 1
- `ls -l /sbin/init` to determine which Init system you are using

### 6 Init
The kernel, once loaded, is hard coded to reach out and execute /sbin/init. This starts the process of bringing the system to a desired level of functionality using Initialization Daemons. There are two main initialization daemons now : Systemd and SysV.

#### 6.1 SysV
SysV initialization is a legacy system initialization method, but it is still used today in many older systems Linux systems or Unix machines like Oracle’s Solaris. It starts with the kernel executing the first process on the machine, or the Initialization daemon. In SysV machines it is the `/etc/init` program. Then, init reads `/etc/inittab` to start creating processes in groups called Run Levels. The processes that each Run Level starts are defined in `/etc/rc.d/rc*.d`

#### 6.2 Systemd
Systemd is the modern initialization method. Its starts with the kernel spawning /sbin/init which is symbolically linked to `/usr/lib/systemd/system`. systemd interacts with flat configuration files called units. There are many types, but the target and service units determine system initialization.

Configures the environment for the system

- Looks at the /etc/inittab
- Available run levels 0 - 6
- Identifies the default 'init' run level from /etc/inittab and uses that to load all the appropriate programs
- The entire startup process is handled by scripts
    - `/etc/init.d/`
    - Scripts that run ‘S’tart and ‘K’ill scripts out of applicable rc folders
- 'service <service name> start | stop | restart | status | reload | …​''
- ‘service --status-all’

inittab line descriptions (rc = run commands)

- All lines in inittab take the following form, with four fields separated by colons in this order:
- A unique identifier (a short string, such as id in the previous example)
- The applicable runlevel number(s)
- The action that init should take (default runlevel to 5 in the previous example)
- Loads system in parallel and from binaries (faster and more secure)
- Instead of runlevels, uses 'targets' that point to other dependencies based on the features of the environment desired
    - ‘default.target’ is essentially the default runlevel (equivalent to id:5:initdefault in /etc/inittab). Use ‘systemctl get-default’ to find it, and ‘systemctl set-default’ to change it.
- ‘systemctl list-dependencies’ shows all the services running under default.target
- Uses 'systemctl’ to manage system (backwards compatible)
    - ‘systemctl status <application>.service’
    - ‘systemctl list-units’
- Config: /etc/systemd/ and /etc/systemd/system

**RUN LEVELS**
A runlevel is a software configuration where only a select group of processes exist

0 - halt (Do NOT set initdefault to this)
1 - Single user mode (switched from multi-user)
2 - Multiuser, without networking
3 - Full multiuser mode, with networking
4 - unused
5 - X11 (GUI)
6 - reboot (Do NOT set initdefault to this)

‘ls -l /etc/rc<1-6>.d’ to see different services run in each runlevel
    - If running something other than an init.d service, then probably malicious
### 7 Post Process 


## Challenges
05 Hex 4
0x31A - 0x21B
0xFF

06 Bits and Bytes 1
How many bits are in a nibble, and a byte?
4, 8

07 Bits and Bytes 2
how many bits does  asingle hedacimal character represent?
4

08 Bits and Bytes 3
Each hex digit contains a value of 8 bits when used to represent memory.
How many bytes could the range 0x00000000 - 0x00000010 contain
17

10 MBR 1
How large is the Master Boot Record and what directory is it located in?
Flag format: #InBytes,directory

512, /dev

15 SysV 1
Identify which of your Linux machines is using SysV Initialization.
Minas_Tirith

02 Hex 1
What are the maximum and minimum value a single Hexadecimal digit can contain?
Enter the values in Linux Hexadecimal Numerical Constant form.
Flag format: min-max

0x0 - 0xF

03 Hex 2
What are the maximum and minimum values, in decimal notation, that a single Hexadecimal digit can represent?
Flag format: min-max

0-15

04 Hex 3
Solve the following equation:
0x31A + 0x43
Enter the flag in Hexadecimal form.

0x35D

09 Bits and Bytes 4
Execute : sudo xxd -l 32 -c 0x10 -g 1 /dev/vda
What are the values contained in hex positions 0x00000001 through 0x00000008?
Flag format: Value,Value,Value
Machine: For this challenge: Minas_Tirith (ssh from Admin_Station)

63 90 8e d0 31 e4 8e d8

11 MBR 2
Locate the master boot record for one of the Linux machines and read it with xxd
What programming language is the MBR written in?
HINT: Look at the first three bytes

assembly 

12 MBR 4
The file /home/bombadil/mbroken is a copy of an MBR from another machine.
Hash the first partition of the file using md5sum. The flag is the hash.

dd if=/home/bombadil/mbroken bs=1 count=16 skip=446 of=/home/bombadil/out
md5sum /home/bombadil/out

14 MBR 3
The file /home/bombadil/mbroken is a copy of an MBR from another machine.
Hash only the Bootstrap section of the MBR using md5sum. The flag is the entire hash.

d59a68c7b6d62ecaa1376dfb73a3b7be

13 MBR 5
The file /home/bombadil/mbroken is a copy of an MBR from another machine.
Hash the hexidecminal representation of GRUB using md5sum.
The flag is the entire hash.

5fa690cb0f0789cbc57decfd096a503e

16 SysV 2
Identity the default run level on the SysV Init Linux machine.
Flag format: #

2

17 SysV 3
What is the last script to run when the command init 6 is executed?
Flag format: /absolute/path
NOTE: Use the machine identified in SysV 1 for this question.

/etc/init.d/reboot

18 SysV 4
What run levels start the daemon that allows remote connections over port 22?
Flag format: #,#,#
NOTE: Use the machine identified in SysV 1 for this question.

2,3,4,5

19 Systemd 1
Identify the file symbolically-linked to init on the SystemD init machine.
Flag format: /absolute/path
Reminder: Use your Terra machine for these SystemD challenges!

/lib/systemd/systemd

20 Systemd 2
What is the default target on the SystemD machine and where is it actually located?
Flag format: name.target,/absolute/path

graphical.target,/lib/systemd/system/graphical.target

21 Systemd 3
What unit does the graphical.target want to start, based solely on its configuration file?
HINT: Targets deal with which init system? Which machine should you be looking for this flag, on?

display-manager.service

22 Systemd 4
What dependency to graphical.target will stop it from executing if it fails to start, based solely on its static configuration file?

multi-user.target

24 Systemd 6
What is the full path to the binary used for standard message logging?
HINT: Standard message logging is standardized across UNIX systems.
NOTE: As the challenge name suggests, use the SystemD machine for this question.
Flag format: /absolute/path

$PATH
ls -l /usr/sbin |grep syslog
/usr/sbin/rsyslogd

01 Grub 1
Identify the Linux Kernel being loaded by the Grub, by examining its configuration.
Enter the command used by the Grub, and the full path to the Kernel, as the flag.
Flag Format: command,kernel location
HINT:
Click me for help understanding Grub commands
Machine: Minas_Tirith

