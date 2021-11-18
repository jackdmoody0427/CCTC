## Linux Notes and CTFs

odd days!

## Linux Essentials
### Flags
|name      |value|
|-----------|-----|
|linux_basics2|start5309|

## NOTES
### Linux Essentials
#### 1. Commands, Arguments, and Help
  - BASH (Bourne Again Shell) executes commands, parses text, redirects output, and accepts scripts
  - help for commands
    - `man`
    - `--help`
    - `whatis`
    - `curl cht.sh/{}` where `{}` is a command
  - variables
    - `a="100"`
    - `echo $a`
  - command substitution
    - `directories = $(ls /)`
    - `echo $directories`
  - redirection using `>`(overwrite) or `>>` (append)
    - stdin = 0
    - stdout = 1
    - stderr = 2
    - examples:
      - `echo 'hello there' 1> out.txt`
      - `ls directory-that-doesnt-exist 2> err.txt`
  - piping using `|`
    - piping redirects stdout (1) to stdin (0) of another function, as args to that function
    - `ls -Rlisa /etc | grep syslog`
    - `ls -Rlisa /etc 2> /dev/null | grep syslog`

#### 2. Automation and Logic
  - For Loops, using **command substitution** to iterate over a list of objects, `echo`-ing them
```
objects=$(ls -d /etc/*)

for item in $objects; \
do echo $item; \
done
```
  - While Loop
```
curtime=$(date +"%s")
exittime=$(expr $curtime + 3)

while [ $exittime -ge $curtime ]; \
do echo "hello" ; \
curtime=$(date +"%s") ; \
done
```
  - If/else: if an obj is a dir, else if it's a file
```
for object in $objects; \
do if [ -d $object ]; \
then echo "$object is a directory"; \
else echo "$object is file" ; \
fi ; \
done`
```

#### 3. Linux Filesystems
  - File systems follow the following format:
    - Physical media
      - Partition: formatted section of memory
        - File System: mounted on a drive
          - Heirarchical Format: Objects and their data/metadata
  - `man heir`
  - Linux system heirarchy
    - `/`: root
    - `proc`: pseudo fs that holds info of all running processes
    - `tmp`: temporary files that may be deleted at any time.
      - anyone can do what they want here
      - copy a file here to do stuff to it that you otherwise cannot
    - `bin`: essential user commands like `ls` and `echo`
    - `home`: directories for every non-root user on system
    - `etc`: everything configurable. network configs, system services, etc
    - `var`: system logs
  - Files and Folders
    - all objects are either files or folders
    - relative vs. absolute paths
    - Reading file signature:
```
cd /bin
cat ls | head -n 1
ELF>PX@▒@8      @@@▒888▒ ...

xxd ls | head -n 2
00000000: 7f45 4c46 0201 0100 0000 0000 0000 0000  .ELF............
00000010: 0300 3e00 0100 0000 5058 0000 0000 0000  ..>.....PX......

# 7f45 4c46 stands for **Linux Executable Linked file (ELF)** format unique to Linux

# other stuff wrt binaries
which ls -> /bin/ls
type ls -> ls is alieased to ls --color=auto
file ls -> gives even more info about ls than `type`
```
  - Linux Users
    - `/etc/passwd` will contain users and their `uid`
    - `/etc/shadow` will contain hashed passwords
      - `$6` = SHA-512 hashed password
    - `id` to determine your uid
    - `whoami` to determine your username
  - Linux Groups
    - collection of users, defined by `gid`
    - `/etc/group` will contain groups and their `gid`
      - `sudo:x:27:ubuntu, student` contains group `sudo` with members `ubuntu, student`
  - Permissions
    - file permissions are 3 octal numbers, representing perms for **user, group, other**
    - `U.G.O` -> `421.421.421` -> `rwx.rwx.rwx`
    - Examples
      - `chmod 777 file`
      - `chmod o+x file`
      - `chmod u+x file`
      - `chmod +x file`
  - Sticky bit
    - normally, if a user has access to a directory, they can delete files
    - setting the sticky bit only allows the owner of the file to delete it
    - `chmod +t file`
  - SUID and SGID
    - SUID and SGID force executable to be run as the owning user or group, rather than the original caller
    - `ls -l /bin/ping`
    - `-rwsr-xr-x` <- `s` is the SUID here, aka special permission

#### 4. String Manipulation
  - `grep` searches data for patterns of strings specified with regex
    - Examples
      - `ls -la /etc 2> /dev/null | grep password`
      - `grep -R 'network' /etc/` (recursive `grep`)
  - `awk` reformat/select test based on delimiters
```
student@linux-opstation-kspt:~$ ls -l /etc
drwxr-xr-x  7 root root       4096 Feb  4  2020 NetworkManager
drwxr-xr-x  2 root root       4096 Feb  4  2020 PackageKit
drwxr-xr-x  2 root root       4096 Feb  4  2020 UPower

# Sends output from ls -l to awk, sets delimiter (-F = field separator) to " ", print 3rd, 4th, 9th fields, redirect to csv file
student@linux-opstation-kspt:~$ ls -l /etc | awk -F " " '{print$3","$4","$9}' > files.csv
student@linux-opstation-kspt:~$ cat files.csv
root,root,NetworkManager
root,root,PackageKit
root,root,UPower
```
```
student@linux-opstation-kspt:~$ articles=$(curl -L https://www.dailymail.co.uk/ushome/index.html --output - | grep itemprop | grep href | awk -F "\"" '{print$4}'|  awk -F "/" '{print$4}')

student@linux-opstation-kspt:~$ for article in $articles; do echo $article; done
Rush-Limbaugh-dies-aged-70-lung-cancer-battle.html
Facebook-BANS-Australians-sharing-news-war-publishers.html
```
  - `sed` edits text as it is sent to stdout. known as stream editor.
    - Example 1 replaces all instances of `root` with `bacon`
    - Example 2 replaces all instnaces of `.html` with nothing, and `-` with space
```
student@linux-opstation-kspt:~$ cat /etc/passwd | grep root
root:x:0:0:root:/root:/bin/bash

student@linux-opstation-kspt:~$ cat /etc/passwd | grep root | sed s/root/bacon/g
bacon:x:0:0:bacon:/bacon:/bin/bash
```
```
student@linux-opstation-kspt:~$ for article in $articles; do echo $article; done
Rush-Limbaugh-dies-aged-70-lung-cancer-battle.html
Facebook-BANS-Australians-sharing-news-war-publishers.html
Congress-holds-hearing-reparations-slavery-time-BLM-protests-rocked-nation.html

for article in $articles; do echo $article |sed -e s/\.html//g -e s/\-/" "/g ; done  
Rush Limbaugh dies aged 70 lung cancer battle
Facebook BANS Australians sharing news war publishers
Police 7 shot near transit station north Philadelphia
```
--------
## CTF Responses

## 04_Linux_basics
- What command lists the contents of directories in Linux/Unix systems?
  - ls
- For the ls command, what arguments, or switch options, will allow you to print human-readable file sizes in a long-list format?
  - ls -lh
- What character will pipe the standard output from  echo "I’m a plumber" to another command, as standard input?
  - |
- What argument/switch option, when used with man, will search the short descriptions and man-page-names for a keyword that you provide?
  - man -k
- What is the absolute path to the root directory?
  - /
- What is the absolute path to the default location for configuration files?
  - /etc
- What is the directory that contains executable programs (binaries) which are needed in single user mode, to bring the system up or to repair it?
  - /bin
- The absolute path to the directory which contains non-essential binaries that are accessible by standard users as well as root.
  - /usr/bin
- An absolute path to a directory which contains binaries only accessible by the root user, or users in the root group.
  - /sbin
- The absolute path for the binary cat man-page.
  - `man --where --all cat`
  - /usr/share/man/man1/cat.1.gz
- Search the man pages for the keyword digest. Then, use one of the binaries listed, to hash the string OneWayBestWay using the largest sha hash available.
  - `man -wK digest`
  - `echo OneWayBestWay > some_file`
  - `sha512sum some_file`
  - a81bc463469ee1717fc9e388e3799c653f63a3de5e9496b5707b56488b046cbf75665235 \
  - d316c5c0053a597dc7d40c917a2d9006fe35e9cb47766c05ac71989b
- File: /home/garviel/Encrypted This file contains encrypted contents. Identify its file type, then decode its contents.
  - `file Encrypted`
  - `file cipher`
  - `openssl enc -d -aes-128-cbc -in cipher`
  - DeCrypt
- Search the user home directories to find the file with the second-most lines in it.
  - `wc -l *`
  - 20000
- Read the file that contains the user database for the machine. Identify a strange comment.
  - /etc/passwd
  - Traitor
- Identify all members of the Lodge group. List their names in alphabetical order with a comma in between each name.
  - /etc/group
  - aximand,erebus,ezekyle,garviel,sejanus,tarik
- Find the user with a unique login shell.
```
with open('/etc/passwd') as fp:
    lines = fp.readlines()
    res = {}
    for l in lines:
        sh = l.split(':')[6]
        if sh not in res:
            res[sh] = 1
        else:
            res[sh] += 1
    print(res)
```
  - nobody
- Identify the algorithm, the amount of salted characters added, and the length of the hashed password in the file that stores passwords.
  - `sudo cat /etc/shadow`
  - info on hashing [here](https://samsclass.info/123/proj10/p12-hashcat.htm#:~:text=The%20%246%24%20value%20indicates%20a,next%20%24%2C%20are%20the%20SALT.)
  - sha512,8,86
```
$6                  <----- sha512
$q/G3Lb5D           <----- salt
$PfpHXU7yBdXSTF5W1V9VAqQIOldD1zK2g/JlC9dityQYCymsY5v9MwmRHt5krEyQulbD.OaSCtL1bjtCeqjFX0 <-- pass
:18928:0:99999:7::: <----- ???
```
- Find the directory named Bibliotheca. Enter the absolute path to the directory.
  - `find / -type d -name "Bibliotheca" 2> /dev/null`
  - /media/Bibliotheca
- Identify the number of users with valid login shells, who can list the contents of the Bibliotheca directory.
  - `/etc/shells`
  - 14 bash + 1 sh = 15
- The permissions that user sejanus has on /media/Bibliotheca, in octal format.
  - `ls -l` says that the group is `chapter` and the owner is `mephiston`
  - `/etc/group` says that `sejanus` is in `chapter`, so only has read (4) and exec (1) perms.
  - 4+1 = 5
- Locate the file within /media/Bibliotheca that is modifiable by the only user that is part of the Chapter group, but not part of the Lodge group.
  - that user is `mephiston`
  - Codex_Astartes
- The file within /media/Bibliotheca where the owning group has more rights than the owning user.
  - Codex_Imperium
- Execute the file owned by the Guardsmen group in /media/Bibliotheca, as the owning user.
  - Tactica_Imperium is the executable
  - `sudo -u gaunt ./Tactica_Imperium`
- The user tyborc is unable to access the directory: /media/Bibliotheca/Bibliotheca_unus Why? Identify the permission missing, in standard verb form.
  - execute
  - .Secrets_of_the_Immaterium
- Read the concealed file within the Bibliotheca
  - Expand your mind
- Locate the file in /media/Bibliotheca that Inquisitor Quixos has sole modification rights on.
  - /media/Bibliotheca/Bibliotheca_duo/Codex_Hereticus
- Find the warp and read its secrets for the answer.
  - `find .warp1/2/3/4/5 -type f`
  - Ph'nglui mglw'nafh Cthulhu
- Using the commands ls and grep, identify the number of directories in /etc/ that end in .d
  - `ls -d * | grep '\.d$' | wc -l`
- Use regular expressions to match patterns similar to an IP address. The answer is the number/count of lines that match in the file.
  - note: `\d` does not work in grep
  - `cat numbers | grep -E '^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$' | wc -l`
- Use regular expressions to match valid IP addresses. The flag is the number of addresses.
  - `cat numbers | grep -P '^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$' | wc -l`
  - 78
- Use regular expressions to match patterns that look similar to a MAC Address
  - `cat numbers | grep -P '^(?:(?:[A-Z]|\d){2}-){5}(?:[A-Z]|\d){2}$' | wc -l`
  - 4877
- Use awk to print lines >= 420 AND <=1337 The flag is a SHA512 hash of the output.
  - `cat numbers | awk 'NR>=420&&NR<=1337' numbers > out.txt`
  - `sha512sum out.txt`
  - e62ff70d772ef0977f4f8fe1751fda5689ce1daf1fabc6d0cc49da234d0271998 \
  - 6c0acb97f582166170a5a1f418e854602a5eb98c773655906a3f85440c37d39
- Use awk to create a separate CSV (comma separated value) file that contains columns 1-6. The flag is an MD5 hash of the new file
  - `cat connections | awk -F "\t" '{print$1","$2","$3","$4","$5","$6}' > files.csv`
  - note: edit first line to match their problem statement (probably wrong)
  - `md5 files.csv`
  - 6cebf155e9c8f49d76ae1268214ff0b5
- Interpret the Titan Controls to navigate the minefield and annihilate the target.
  - AAAAA3AAA3AAAABAABAAAA

- The flag resides in $HOME/paths... you just need to determine which flag it is. It sits next to a string matching the name of a $PATH binary on your system.

```
import subprocess
# set of all possible flags
with open('/home/garviel/paths') as fp:
  lines = fp.readlines()
  for l in lines:
    flag = l.split()[0]
    cmds = subprocess.run(['whereis', flag], stdout=subprocess.PIPE).stdout.decode().split(':')[1]
    if cmds != '\n':
      print(l)
```  
  - Vrc0vw7ZUaLBpQp
 - Use regular expressions to find Locally Administered or Universally Administered Unicast MAC addresses. Give the count of Locally and Universally Administersed MAC addresses as the answer.
  - `cat numbers | grep -P '^(?:(?:[A-F]|\d)[048C26AE]-)(?:(?:[A-F]|\d){2}-){4}(?:[A-F]|\d){2}$' | wc -l`
- Identify heresy by comparing the Inquisition_Targets file to members of the Guardsmen group.
```
with open('/home/garviel/Inquisition_Targets') as fp, open('/etc/group') as gp:
    targets = [x.strip().lower() for x in fp.readlines()[4:]]
    guards = [g.strip().lower() for g in gp.readlines()[63].split(',')]
    for g in guards:
        if g in targets:
            print(g)
```

-------------
## Linux Boot Process
### Flags
|name      |value|
|-----------|-----|
|linux_boot_process|start3675|

## NOTES
### Linux Boot Process
#### 1. Boot Process Overview
#### 2. BIOS and UEFI
  - BIOS and UEFI are firmware, which is software coded into non-volatile memory (not cleared on reboot).
  - BIOS runs and exits before Linux system even starts.
#### 3. 1st Stage Bootloaders
  - MBR and GPT
  - Master Boot Record: contains info on partitions, which contain the 2nd stage bootloader (GRUB)
    - 512 bytes, contains
      - Bootstrap Code (446 bytes)
      - Partition Entires 1-4 (16 bytes each, 64 bytes total)
      - Boot Signature (2 bytes)

    - `lsblk` lists info of all block devices
    - `sudo xxd -l 512 -g 1 /dev/vda` to examine `vda` MBR
      - start of the hard drive `eb 63` identifies it as an MBR
      - `80` represents used partitions
      - last 2 bytes are `55 aa` (Big Endian) or `aa 55` (Little Endian)
    - to make a copy of MBR:
      - `dd if=/dev/vda of=MBRcopy bs=512 count=1`
      - `sudo !!` <- run previous command as sudo
  - GUID Partition Tables (GPT): newer version of MBR. Does the same thing, but has advantages such as more and larger partitions.

#### 4. 2nd Stage Bootloader (GRUB)
  - MBR loads 2nd stage bootloader, aka GRUB. GRUB lives inside `/boot` or a separate partition.
  - Grand Unified Bootloader (GRUB): singular purpose is to load user-selected Linux Kernel from hard drive.
    - GRUB config file is at `/boot/grub/menu.lst`
    - BIOS using MBR:
      - Stage 1: `boot.img` from first 440 bytes of MBR loads
      - Stage 1.5: `core.img` between `boot.img` and first partition loads
      - Stage 2: `core.img` loads `/boot/grub/i386-pc/normal.mod`. This loads GRUB menu and displays available Linux Kernels to load by reading `/boot/grub/grub.cfg`
    - UEFI using GPT
      - Stage 1: `grubx64.efi` from EFI partition or `/boot` loads
      - Stage 2: `/boot/grub/x86_64-efi/normal.mod` loads, `/boot/grub/grub/cfg` loads, displays available Linux Kernels to boot
  - Viewing Linux Kernel via GRUB configuration
    - `cat /boot/grub/grub.cfg` (around line 107)
  - `du` and `df` gives you file usage`

#### 5. Linux Kernel
  - Linux Kernel came from the Unix Kernel
  - **Monolothic:** System calls all functionality (CPU, memory, file mgmt) to user.
    - `systemcall` is a way a program requests services from the kernel
    - All things on a system occur through `systemcalls`
    - Example: `ltrace -S cat /etc/passwd` tracks all `systemcalls` occurring during `cat /etc/passwd`
  - **Modular:** Extensions to base OS.
    - use `lsmod` to view Linux modules
    - if modules fail, the system will not fail

#### 6. Init
  - The kernel is hard-coded to execute `/sbin/init` once loaded
    - Brings system to desired level of functionality using _Initialization Daemons_
      - 2 types are `Systemd` and `SysV`
    - There are 6 different **Run Levels**, 1-6, and 0 (Halt)

  - `SysV`: Legacy system initialization
    - starts with kernel executing Initialization Daemon, which is `/etc/init`. This, in turn, reads `/etc/inittab` to start creating processes at different Run Levels.
      - Run Levels are defined in `/etc/rc.d/rc*.d`
    - `SysV` Init Daemon: `/etc/init`, which is the first process to start in SysV Linux
      - `/etc/init` initializes system to target run level specified in `/etc/inittab`
      - `inittab` has run level entries that specify directories with scripts to start at certain levels. Tries to start at `initdefault` at first - if fail, starts at 0 (halt).
      - Run levels are series of scripts that start/kill daemons, depending on the level and naming scheme.
        - `S` vs. `K` (start vs. kill)
        - `ls -l /etc/rc3.d/`
        - `ls -l /etc/rc1.d/`
      - `init` spawns a login, `getty` displays the login. when given a name, `getty` invokes `bin/login` which prompts for a password, and then authenticates a user.

  - `Systemd`: Modern initialization method
    - Starts by spawning `/sbin/init` (symlinked to `/usr/lib/systend/system`), which interacts with flat config files called **units**. **Target** and **Service** units determine system initialization
    - `systemd` executes config files to bring system to the desired run state, which is specified in `/lib/systemd/system/default.target`
      - `default.target` is usually symlinked to `graphical.target` (run state 5)
        - `cat /lib/systemd/system/default.target | tail -n 8`
    - Target units are set of `value=data` pairs, which can include `wants` and `requires`. `wants` and `requires` can also be found in other locations in the FS (11 other locations)
    - Service units create processes when called by target units. They also have `value=data` pairs.
      - `cat /etc/systemd/system/display-manager.service | tail -n 13`
      - `ExecStart` runs every time system starts up. Can be used maliciously
    - use `systemctl` to query `systemd` dependencies.
      - `systemctl`: shows every unit file visible by `systemd`
      - `systemctl list-dependencies graphical.target`: unit dependencies in tree form
      - `systemctl show -p Wants graphical.target`: wants
  - `-service --status-all` lists all running/not-running services

#### 7. Post Boot
  - `/etc/environment` sets global variables, which are accessible by all users and processes. Read once when machine completes init, and changes require a reboot to become effective.
  - `/etc/profile` is a script that executes when a user logs on to an interactive shell.
    - Ubuntu uses `/etc/profile` to set BASH shell prompt by:
      - executing `/etc/bash.bashrc`
      - executing all `*.sh` in `/etc/profile.d`
    - executes every time user logs in, so restarting shell will apply changes to `/etc/profile`
  - `~.bash_profile`: user bash configs that execute when invoking an interactive login shell that prompts for a password
  - `~.bashrc`: similar to `.bash_profile`, but executes when non-login shells are invoked (no password prompt)

------------
## CTF Responses

## 08_linux_boot_process
- Each hex digit contains a value of 8 bits when used to represent memory. How many bytes could the range 0x00000000 - 0x00000010 contain?
  - 17
- How large is the Master Boot Record and what directory is it located in?
  - 512,/dev
- Identify which of your Linux machines is using SysV Initialization.
  - Minas_Tirith
- What are the maximum and minimum value a single Hexadecimal digit can contain? Enter the values in Linux Hexadecimal Numerical Constant form.
  - 0x0-0xF
- What are the maximum and minimum values, in decimal notation, that a single Hexadecimal digit can represent?
  - 0-15
- Solve the following equation: 0x31A + 0x43
  - 35D
- Execute : sudo xxd -l 32 -c 0x10 -g 1 /dev/vda. What are the values contained in hex positions 0x00000001 through 0x00000008?
  - 63,90,8e,d0,31,e4,8e,d8
- Locate the master boot record for one of the Linux machines and read it with xxd. What programming language is the MBR written in?
  - assembly
- The file /home/bombadil/mbroken is a copy of an MBR from another machine. Hash the first partition of the file using md5sum. The flag is the hash.
  - `dd if=mbroken of=out bs=1 skip=446 count=16`
  - 2a5948fad4ec68170b23faaa2a16cef8
- The file /home/bombadil/mbroken is a copy of an MBR from another machine. Hash the hexidecminal representation of GRUB using md5sum.
  - `dd if=mbroken of=out bs=1 skip=392 count=4`
  - 5fa690cb0f0789cbc57decfd096a503e
- The file /home/bombadil/mbroken is a copy of an MBR from another machine. Hash only the Bootstrap section of the MBR using md5sum. The flag is the entire hash.
  - `dd if=mbroken of=out bs=1 skip=0 count=446`
  - d59a68c7b6d62ecaa1376dfb73a3b7be
- Identity the default run level on the SysV Init Linux machine.
  - `cat /etc/inittab`
  - 2
- What is the last script to run when the command init 6 is executed? Flag format: /absolute/path
  - `cd /etc/rc6.d`
  - `/etc/init.d/reboot`
- What run levels start the daemon that allows remote connections over port 22?
  - inspect commands within `/etc/rc*.d`
  - 2,3,4,5

- Identify the Linux Kernel being loaded by the Grub, by examining its configuration. Enter the command used by the Grub, and the full path to the Kernel, as the flag.
  - `cat /boot/grub/grub.cfg`
  - linux,/boot/vmlinuz-4.9.0-12-amd64
- Identify the file symbolically-linked to init on the SystemD init machine. Flag format: /absolute/path
  - `/lib/systemd/systemd`
- What is the default target on the SystemD machine and where is it actually located?
  - graphical.target,/lib/systemd/system/graphical.target
- What unit does the graphical.target want to start, based solely on its configuration file?
  - display-manager.service
- What dependency to graphical.target will stop it from executing if it fails to start, based solely on its static configuration file?
  - multi-user.target
- How many wants dependencies does SystemD actually recognize for the default.target
  - `systemctl show -p Wants graphical.target`
  - 7
- What is the full path to the binary used for standard message logging?
  - grepped all paths in `$PATH` for `syslog`
  - `/usr/sbin/rsyslogd`

-------------

## Linux Processes

### Flags
|name      |value|
|-----------|-----|
|12_linux_processes|start1640|

#### 1. Process Listing
  - `ps` to report a snapshot of current processes
    - `ps -elf`
    - kernel processes are surrounded in `[brackets]`
  - `top` reports dynamic real-time view of the running system. Lists processes/threads in use by the kernel

#### 2. Startup Process
  - `ps -elf` reports a more detailed snapshot of current processes
  - kernel processes are all forked from `kthreadd` (PPID 2)
    - usually manage hardware, have own memory, have high priority
  - user processes are all forked from `sbin/init` or direct ancestor (PPID 1)
  - at its core, Linux OS is the sum of all running processes

#### 3. Concepts of Virtual Memory
  - **Kernel space**: code running in kernel mode has unrestricted access to CPU and main memory, which is powerful and dangerous at the same time.
    - Only lowest level (ring 0) functions of the OS can run here.
    - Kernel space is generally only accessed by user via system calls
  - **User space**: Limited "sandbox" type environment that can crash without taking down the system. The kernel can help clean up the mess.
  - **OS Protection**: ordered protection domains referred to as "protection rings," which are ranked from most->least privileged.
    - Rings improve fault tolerance and provide computer security.
      - usually, there are 4 rings
    - Ring 0 = kernel/executive
    - Ring 3 = application programs
    - Ring 1/2 = device drivers
    - If an adversary can get access to the kernel, they get complete control over the OS

#### 4. Process Ownership, EUID, RUID, UID
  - Process Ownership
    - processes are simply running instances of programs
    - processes have unique PIDs
    - users (either human or system) can run processes and own files
      - user processes have user owners and run as the owner
    - `grep UID /etc/login.defs` defines min and max `UID`s for human and system users
  - Effective User ID (EUID)
    - EUID defines access rights for a process
    - aka, which user's permissions are used by this process?
  - Real User ID (RUID)
    - the user who owns the process, and who can kill/send signals to it
    - EUID and RUID can differ when SUID bits are set
    - **Refresher**
      >SUID and SGID force executable to be run as the owning user or group, rather than the original caller (ex. ping, passwd)

      - `passwd` can be called by a normal user (RUID) but its EUID would be root

#### 5. System Calls
  - an interaction between the process and kernel in which the process requests a service from the kernel
    - ex. opening, reading, writing files
  - examples of syscalls
    - `fork`: create new process by duplicating the calling process (called the "child process")
    - `exec`: kernel starts program, replacing the current process
    - `read`, `write`, `close`, `wait`, `exec`, `kill`
    - system calls are easily identifiable, makes the executable vulnerable to scanning attacks
  - Signals: software interrupts to a process to indicate an important event
    - `kill -l` to list possible signals
    - SIGSTOP(19): pause signal, doesn't kill process
    - SIGTERM(15): termination signal, ends the process the right way
    - SIGKILL(9): kills the process, no cleanup, only use if 15 doesn't work
  - Process Enumeration
    - `ps --ppid 2 -lf`:  Displays only kthreadd processes (so, only kernel-space processes)
    - `ps --ppid 2 -Nlf`: Displays anything except kthreadd processes
    - `ps -elf --forest`: Displays processes in an ASCII tree
    - `ps -eo pid,cmd`

#### 6. Foreground/Background Processes
  - Foreground process: default, requires a user to start/interact
  - Background process: run independently of the user
  - Orphan processes: parent process has ended, has been adopted by `sbin/init`, therefore its PPID = 1
    - `disown -a && exit` to close terminal, force all children to be adopted
    - `echo $$` gets you PID of current shell
      - type `bash`, note a new PID
      - this is because the OG process was forked, and gets a new memory space and operates independently.
  - Zombie processes: completed process but hasn't been closed by parent.
    - doesn't use resources, but does take up a PID
    - can only kill by killing its parent
  - Daemons: intentionally orphaned process in order to have a background process
    - ex. syslogd, sshd, cron
    - their purspose is to manage/monitor sevices
    - persist: they are made to run for duration of system operation
      - malicious processes can be orphaned to imitate daemons
  - Interacting with linux services:
    - SysV: `service <servicename> status/start/stop/restart`
    - SystemD:
      - `systemctl list-units --all`
      - `systemctl status <name or PID>`
      - `systemctl start/stop/restart <name>`
  - Job Control: ability to stop/suspend/continue/resume processes
    - `jobs` displays status of jobs in current terminal, numbered from 1 onwards
      - job IDs used as opposed to PIDs by some programs, such as `fg` and `bg`
  - Cron jobs: run programs on a fixed schedule
    - `cron` daemon checks `/var/spool/cron`, `/etc/cron.d` and the file `/etc/crontab` every minute to execute appropriate commands based on time
    - either system (controlled by `/etc/crontab`) or user jobs (controlled by `/var/spool/cron/crontabs`)
    - `crontab` command to interact with cron jobs
#### 7. Proccesses and Proc Dir

-----------------
## CTF Responses 

## 12_linux_processes
- What is the process ID (PID) of the SysV Init daemon?
  - `ps -e`
  - 1
- How many child processes did SysV Init daemon spawn?
  - 20
- Identify all of the arguments given to the ntpd daemon (service) using ps.
  - `ps -eo pid,cmd`
  - -p /var/run/ntpd.pid -g -u 105:109
- What is the parent process to Bombadil’s Bash process?
  - sshd
- Identify the file mapped to the third file descriptor (handle) of the cron process.
  - `sudo lsof  -c cron`
    - `cron    1329 root    3u   REG               0,19        5   11220 /run/crond.pid`
  - `/run/crond.pid`
- Identify the permissions that cron has on the file identified in Processes 5.
  - `sudo lsof -c cron` -> `3u` -> u = read, write
  - read,write
- Identify the names of the orphan processes on the SysV system.
  - htop
  - aragorn,brucewayne,eowyn,tolkien
- Locate zombie processes on the SysV system. Identify the zombie processes' parent process.
  - `/bin/funk`
  -  sudo lsof -n -i :1234
- Locate the strange open port on the SysV system. Identify the command line executable, and its arguments.
  - strange port is 9999
  - `sudo lsof -n -i :9999` to find pid of listening process
  - `ps -eo  pid,cmd` to find cmd
  - /bin/netcat -lp 9999
- Examine the process list to find the ssh process. Then, identify the symbolic link to the absolute path for its executable in the /proc directory. The flag is the absolute path to the symbolic link, and the file it is linked to.
  - `lsof -c sshd`
  - `/proc/15085/exe,/usr/sbin/sshd`
- Identify the file that contains udp connection information. Identify the process using port 123.
  - `/proc/net/udp`
  - `sudo lsof -n -i :123`
  - ntpd,19,u
- Locate the strange open port on the SysV system. Identify how the process persists between reboots.
  - find the port (9999)
  - find the command that opens 9999 (`ps -eo pid,cmd | grep 9999`)
  - find the file that has that command (`cd /etc; grep -r /bin/netcat`)
  - `/etc/inittab,91:2345:respawn:/bin/netcat -lp 9999`

- Identify one of the human-readable file handles by the other program that creates a zombie process.
  - `sudo lsof -p <pid>` using parent process of `thenine`
  - `cat /opt/mysoul`
  - and in the darkness bind them

- Scenario: The Villains group has been chanting offerings to their new leader at regular intervals over a TCP connection. Task: Identify their method of communication and how it is occurring. Locate the following artifacts: ** The chant/text used by each villain (include spaces) ** The new Lord receiving the offering ** The IP address and port that the offering is received over
  - Mausan ukoul for avhe mubullat goth,witch_king,127.0.0.1:1234

- Scenario: Someone or something is stealing files with a .txt extension from user directories. Determine how these thefts are occurring. Task: Identify the command being ran and how it occurs.
  - `find /home -name \*.txt -exec cp {} /tmp \;,vestrisecreta.service`

- Scenario: Text files are being exfiltrated from the machine using a network connection. The connections still occur post-reboot, according to network analysts. The junior analysts are having a hard time with attribution because no strange programs or ports are running, and the connection seems to only occur in 60-second intervals, every 15 minutes.
  - `systemctl` -> `whatischaos`
  - `netcat -lp 3389 < /tmp/NMAP_all_hosts.txt,whatischaos.timer`

- Scenario: The web server has been modified by an unknown hacktivist group. Users accessing the web server are reporting crashes and insane disk usage. Task: Identify the Cyber Attack Method used by the group, and the command running.
  - `systemctl` -> `apache3.service`
  - `dos,/bin/apache3 -lp 443 < /dev/urandom`

- Scenario: Analysts have found a dump of commands on the Internet that refer to the Terra machine. The command history for one of the users with an interactive login is being stolen via unknown means. The network analysts can’t find any persistent connections, but notice a spike in traffic on logon and logoff. Task: Identify how the command history is stolen from the machine.
  - `/home/garviel/.bash_logout,12.54.37.8:12000`

------------------
## Linux Logging

### Flags
|name      |value|
|-----------|-----|
|14_linux_logging|start2021|


#### 1. What is Logging?
  - Logging is what loggers do for work

#### 2. Linux Logging Daemons
  - Linux logging is controlled by `syslogd` (defined by RFC 5424, not unique to Linux) or `journald` (unique to Linux).
  - Services store their logs in `/var/log`

#### 3. Syslog Daemon
  - `Syslog` logs in `/var/log`, configured via `/etc/rsyslog`
    - `cat /etc/rsyslog.d/50-default.conf`: view default `syslog` configs
    - it's human-readable
  - configuration standard:
    - `Facility`: source/event that generated log (kernel, mail, systemd, etc.)
    - `Severity`: how urgent (Emergency -> Debug, 0 - 7)
    - `path/to/log/location`: where the log is and any actions on the event before storage
  - severity statements are heirarchical
    - `mail.info` matches severity >= 6
    - `mail.!info` matches severity < 6
    - severities are `emerg, crit, alert, err, warning, ntoice, info, debug`
  - to filter logs, use `grep` since logs are in plaintext
  - `logrotate` (config is `/etc/logrotate.conf`) is a daily cron job that defines how often logs are rotated
    - force log rotations by `sudo /usr/sbin/logrotate /etc/logrotate.conf`
  - essential syslog types/locations (3 main types of logging)
    - **Authentication**: `var/log/[auth.log|utmp|wtmp]`: use `last -f` to view `utmp/btmp`
      - ex. `last -f /var/log/utmp`
      - `ls -l | exec last -f /var/log/wtmp`
    - **Application**: Apache, apt, MySql
    - **System**:
      - `/var/log/messages`
      - `/var/log/syslog`
      - `dmesg`

#### 4. Journald Logs
  - `systemd.journald.service` is logging daemon for `systemd`
    - logs everything wrt `*.units` and stores them in binary form
  - use `journalctl -e` to view logs
    - `journalctl --list-boots`
    - `journalctl -b <boot id>`
    - `journalctl -u ssh.service`
    - `journalctl -u ssh.service --since "2 days ago"`

#### 5. Log Formats
  - Syslog Message Format: Regular text
  - Markup Languages like XML: use XML formatter, Xpath
  - JSON: use json query, pretty print

-----------------
## CTF Responses

## 14_linux_logging
- Identify the XML element name in the output below
  - `<scaninfo/>`
- Identify one of the XML attributes in the output below
 - type="syn"
- What RFC is Syslog?
  - 5424
- What is the numerical code assigned to the facility dealing with authorization?
  - 4
- How many severity codes are defined in the standard that defines syslog?  
  - 8
- What severity is assigned to system instability messages?
  - 0
- Download the attached rsyslog configuration file for the Syslog # challenges. In the legacy rules section of the file, what facility is logged to 0.log?
  - kern
- In the legacy rules section of the file, how many severities are logged to 0.log?
  - 8
- In the legacy rules section of the file, how many severities are logged to 4min.log?
  - emergency,alert,critical,error,warning
- In the legacy rules section of the file, how many severities are logged to 4sig.log?
  - notice,informational,debug
- what is being logged in not.log? Provide the facilities from highest to lowest facility, and the severity being logged. (List only the first word for each.)
  - mail,clock,ntp,notice
- What facilities and what severities are being sent to a remote server over a reliable connection using port 514? Provide the facility names, number of severities, and the correct destination IP address.
  - auth,authpriv,8,10.30.0.1
- Use the answer from Syslog 6 for this question. Do logs that match this filter ever get saved on the local machine?
  - Yes
- What messages are being sent to 10.84.0.1? Provide the facility number, the number of severity codes, and Layer 4 connection type as the answer.
  - 0,7,UDP
- File: /home/garviel/output.xml Parse all of the IP addresses from the file using XPATH queries
  - `xpath -q -e '//@addr' output.xml  | md5sum`
  - 0e850f14fc192c5105955ec094287bd2
- File: /home/garviel/output.xml Select all of the IP addresses and ports using a single XPATH Union Statement Pipe the result to md5sum for the flag
  - `xpath -q -e '//@portid|//@addr' output.xml | md5sum`
  - ff7990139b6d09aa65afb6e069db0dec
- Use jq to pretty print the JSON file conn.log. Hash the pretty-printed file with md5sum for the flag.
  - `jq . conn.log  | md5sum`
  - 25ebedf7442e470eaaa48b5f7d5b96f4
- This file is a conn.log made in Zeek (Bro) with data about TCP/IP connections. Use jq to locate and count the unique originating endpoint IP addresses in the file.
  - `jq '."id.orig_h"' conn.log  | sort | uniq | wc -l`
- This file is a conn.log made in Zeek (Bro) with data about TCP/IP connections. Use jq to locate and count connections where the destination IP sent more than 40 bytes to the source IP.
  - `jq 'select(.resp_bytes > 40) | .resp_bytes' conn.log  | wc -l`
- Which cron log severity code is saved only to the local machine?
  - 7
- The emergency messages (only) on the system are sent to what IP Address?
  - 10.24.0.1
- Use the log file attached to this for all Whut questions. How many unique users logged into this machine?
  - 3
- Identify the Cyber Attack Technique that Balrog is trying on the machine.
  - credential stuffing
- Select every IP address with open (in use) ports using XPATH queries and XPATH axes. Pipe the result to md5sum for the flag
  - `xpath -q -e '//host/address[../ports/port/state/@state='open']/@addr|//host/ports/port[./state/@state='open']/@portid' output.xml | md5sum`
  - ef0acbb3e9a376395d35c4ad9e9418ba
- What user successfully executed commands?
  - saruman
- Analyze the file to determine when a shell was spawned as a different user and how long it was maintained for.
Provide the:
duration the shell was maintained
the command used to create it
number of times they [successfully] escalated
  - `2h,30m,find /etc/passwd -exec /bin/sh \;,2`