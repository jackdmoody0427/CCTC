### *CCTC OS NOTES DAY 7*

| Challenge Name | Flag |
| -- | -- | 
|linux_processes| start1640 |


## Linux Processes 

### 1 Process Listing
Each Linux system has numerous processes running. You may be familiar, or will become familiar, with most of these processes if you regularly use commands like "ps" or "top" to display them.

#### 1.2 ps
The `ps` command is a native Unix\linux utility for viewing information concerning a slection of running processes ona system. AKA: It reads this information from the virtual files in/ proc filesystem

#### 1.3 top
The `top` command is used to show the Linux processes. It provides a dynamic real-time view of the running system. Usually, this command shows the summary information of the system and the list of processes or threads which are currently managed by the Linux Kernel.

### 2 Startup Processes
The startup process follows the boot process and brings the Linux computer to an operational state in which it is usable for productive work. It is highly important that a demarcation is established in virtual memory to prevent programs running in user space to directly ineract with the kernel

Executing the `ps` command with `-elf` argument will do a full format listing of all running processes on the system in long format 

**NOTE** : The STIME column in a "ps" output displays the time the process started, or the starting date if it started more than 24 hours ago. The STIME changing to 0 is further evidence that a process is no longer running, as the start time is no longer being monitored, and was reset to 0.

Key points
- All kernel processes are fork()ed from `[kthreadd]` and all user processes are fork()ed from `/sbin/init` or direct ancestor 
- Kernel processes are typically used to manage hardware, are directly handled by the kernel,  have their own memory space, and have a high priority
- They can be identified by the name encloses in square brackets `[ ]` (using `ps -f` option). `kthreadd`-spawned processes will have a **PPID of 2**

Q: What are the primary parent processes of all running processes on the system?
A: There are two primary processes after startup:
- For user-space processes /sbin/init ( PID = 1 )
- For kernel-space processes [kthreadd] ( PID = 2 )

**Operational Value**
- The Linux OS is at it’s core the sum of all running processes.
- Understanding the difference between User and Kernel mode processes, as well as the Parent/Child relationship of processes, is fundamental to understanding how a Linux machine works.

### 3 Concepts of Virtual Memory
Virtual Memory is divided into kernel space and user space

#### 3.1 Kernel Space
Kernel space is that area of virtual memory where kernel processes will run. This division is required for memory access protections. Code running in kernel mode has unrestricted access to the processor and main memory. This is a powerful but dangerous privilege that allows a kernel process to easily crash the entire system. The kernel is the core of the operating system. It normally has full access to all memory and machine hardware (and everything else on the machine). To keep the machine as stable as possible, you normally want only the most trusted, well-tested code to run in kernel mode/kernel space.

Executing code in kernel space will give it unrestricted access to any of the memory address space and to any underlying hardware. Kernel space is reserved for the highest of trusted functions within a system. Kernel mode is generally reserved for the lowest-level (ring 0), most trusted functions of the operating system. Due to the amount of access the kernel have, any instability within the kernel’s executing code can result in complete system failure.

Kernel space can be accessed by user processes only through the use of system calls.

#### 3.2 User Space
**User mode**, in comparison, restricts access to a (usuallu quite small) **subset of memory** and safe CPU operations. User space refers to teh parts of main memory that the user processes can access. If a process can make a mistake and crashes, the consequences are limited and can be cleaned up by the kernel. This means that if your web browser crashes, it won't take down the whole system. Think of it as a form of sand-boxing — it restricts user programs so they can’t mess with memory (and other resources) owned by other programs or by the OS kernel. This limits (but usually doesn’t entirely eliminate) their ability to do bad things like crashing the machine. Because of the restricted access, malfunctions within user mode are limited only to the system space they are operating within.

*Important*: An API (Application Programming Interface - set of protocols, routines, and, functions that allow the exchange of data among various applications and devices) and/or System calls (method that allows a program to request services from the kernel) are made by user mode processes to the kernel to request memory and physical hardware access.

#### 3.3 OS Protection

Wikipedia Link: https://en.wikipedia.org/wiki/Protection_ring

In CS, the odered protection domains are reffered to as Protection Rings. These mechanisms help in improving fault tolerance and provide Computer Security. Operating Systems provide different levels to access resources. Rings are hierarchically arranged from most privileged to least privileged.

Use of Protection Rings provides logical space for the levels of permissions and execution. Two important uses of Protection Rings are:

1. Improving Fault Tolerance
2. Provide Computer Security

There are basically 4 levels ranging from 0 which is the most privileged to 3 which is least privileged. Most Operating Systems use level 0 as the kernel or executive and use level 3 for application programs.

- Rings 1-2 cannot run privileged instructions but this is the only real limit; otherwise they are as privileged as ring 0. The intent by Intel in having rings 1 and 2 is for the OS to put device drivers at that level, so they are privileged, but somewhat separated from the rest of the kernel code.

Operational Value

- The goal in most, if not all, exploitative exercises is to be able to manipulate kernel mode processes and memory.
- In doing so, an adversary can gain complete control over the OS and obfuscate their methodology.

### 4 Process Ownership, Effective User ID (EUID), Real User ID (RUID), User ID (UID)
The Linux kernel supports the traditional concept of a Unix user. A user is an entity that can run processes and own files. A user is also associated with a username.

#### 4.1 Process Ownership
A Linux process is nothing but running instance of a program. For example, when you start Firefox to browse Internet, you can create a new process. In Linux, each process is given a unique number called as a process identification (PID). Linux kernel makes sure that each process gets a unique PID. `/sbin/init` or `/lib/systemd/systemd` on modern Linux distros always has a PID of 1 because it is eternally the first process on the Linux based system.
- *A user is an entity that can run processes and own files.* Users exist primarily to support permissions and boundaries. Every user-space process has a user owner, and processes are said to run as the owner. A user may terminate or modify the behavior of its own processes (within certain limits), but it cannot interfere with other users’ processes. In addition, users may own files and choose whether they share them with other users.

- Users of the system may be:
    - Human Users = people who log into the system; or
    - System Users = used to start non-interactive background services such as databases

- From the perspective of the operating system, there is no distinction between human users and system users and all the information is stored in the same file. However, there is a range of user IDs reserved for human users and another range for system users. To view this range, execute the following command and point out that the system UID’s range from 100 - 999 and the user range is 1000 - 60000.

#### 4.2 Effective User ID (EUID)
EUID defines the access rights for a process. In Layman's term it describes the user whose fiel access permissions are used by the process. 

#### 4.3 Real User ID (RUID)
The real user ID is who you really are (the one who owns the process). It also defines the user that can interact with the running process—most significantly, which user can kill and send signals to a process.

- Users can only modify / interact with files /processes that they own or that have been shared with them

*Note*: The distinction between a real and an effective user id is made because you may have the need to temporarily take another user’s identity (most of the time, that would be root, but it could be any user).

**IMPORTANT**: EUID and RUID are mostly always the same. They can be different when special permissions (like SUID bits) are set on files.

*Operational Value*

- The "context" that a program runs in is something that is very important to keep track of. For Example:
    - The /usr/bin/passwd command runs with an EUID of root no matter who runs it.
        - ls -l /usr/bin/passwd
- This is done, because when a user updates their password, the /etc/shadow file is overwritten, which can only be done by root.
- However, the passwd command tracks the RUID ensuring that a normal user can’t change another user’s password

### 5 System Calls
                        --> shell <3>
shell <1> --> fork() <2> 
                        --> Copy of shell <4> --> Exec(ls) <5> --> ls <6>
1. original process
2. original process asking the kernel to create another process must perform a fork() system call
3. original process after fork() system call
4. identical copy of original process after fork() system call
5. identical copy of original process performs exec(ls) system call
6. kernel replaces identical copy of original process with that of the new process

Q: What exactly is a system call?

A: A system call is an interaction between a process and the kernel, a programmatic way in which a computer program requests a service from the kernel of the operating system it is executed on. For example, the acts of opening, reading, and writing files all involve system calls

#### 5.1 Fork() and Exex() System Calls
fork - creates a new process by duplicating the calling process. The new process is referred to as the child process. The calling process is referred to as the parent process.
    - The fork “processes” can be explained as the recreation of a process from system space and duplicated into user space in an attempt restrict user access to system processes/space.

exec - When a process calls exec, the kernel starts program, replacing the current process.

*Note*: Some popular system calls are open, read, write, close, wait, exec, fork and kill.

Plz refer to SFG for common system calls for both Windows and Unix 

**All Daemons are Orphans, but not all Orphans are Daemons**

Operational Value:

- An existing executables weakness is that system call instructions are easily identifiable, which makes them potentially vulnerable to scanning attacks. You can make system call instructions harder to identify by disguising them as other, less conspicuous, instructions (e.g., load, store, or div instructions).
- It’s beyond the scope of this course to get into all the types of system calls.
- Still, it’s important to understand what they are, and a lot of information can be gleaned from monitoring specific ones.


# There are many more notes, but let's start the challenges

1B Processes 2
How many child processes did SysV Init daemon spawn?
 
`ps --ppid 1 S` gives us 20


1C Processes 3
Identify all of the arguments given to the ntpd daemon (service) using ps.

ps -elf | grep ntpd
-p /var/run/ntpd.pid -g -u 105:109

1D Processes 4
What is the parent process to Bombadil’s Bash process?

`sshd`, looked up ps -elf and saw what PPID matched the PID then used the far right name 

1E Processes 5
Identify the file mapped to the third file descriptor (handle) of the cron process.
HINT: There might be multiple cron processes, but only one with the answer.
Flag format: /absolute/path

` sudo lsof -c cron` You're lookig for the FD (File Description)


1F Processes 6
Identify the permissions that cron has on the file identified in Processes 5.
HINT: Read the man page for lsof to understand permissions.
Flag format: permission,permission,permission

Read, write



1H Processes 8
Locate zombie processes on the SysV system.
Identify the zombie processes' parent process.
NOTE: Remember, zombie processes only live until the parent process shoots them in the head. Try monitoring the processes list with top or htop to find them.

Flag format: /absolute/path
zombie PID: 6871  --> /bin.funk

1I Processes 9
Locate the strange open port on the SysV system.
Identify the command line executable, and its arguments.
Flag format: /executable/path -arguments

```
sudo lsof -i -P -n
sudo lsof -n -i :9999
ps -eo pid,cmd
```
the PSID is 2184, so /bin/netcat -lp 9999 is the answer

2A Proc Dir 1
Examine the process list to find the ssh process. Then, identify the symbolic link to the absolute path for its executable in the /proc directory.
The flag is the absolute path to the symbolic link, and the file it is linked to.
Flag format: /absolute/path,/absolute/path

```
 lsof -c sshd
 sudo ls -l /proc/23551/exe
 /proc/23551/exe -> /usr/sbin/sshd
```

2B Proc Dir 2
Identify the file that contains udp connection information. Identify the process using port 123.
For the flag, enter:
Process name
File descriptor number for the udp socket
Its permissions as shown in lsof
Flag format: name,#,permission

`sudo lsof -n -i :123`

name = ntpd, # = 19, permissions = u


nazgul
