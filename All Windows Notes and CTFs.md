## *All Windows Notes and CTFs*

## Windows Registry
### 1: Windows Registry Introduction
- The Windows Registry is a central hieracrchil database used in Windows to store infomration that is necessary to configure the system for one or more users, applications, and hardware devices. 
- An easy analogy, is to think of it as a giant rolodex
    - everything in windows has a card/place with all it's info
    - Includes location, information, settings, options, and other values for programs and hardware installed 
**The run key is an essential place for malware, because it runs everytime the system is booted up**

**Why is it important?**
- Anyone can hides all sorts of data including passwords, malicious code, and executable/binary files in the Registry.
- They can effectively hide data in registry keys’ value entries.
- By using different encoding techniques, they could obfuscate or hide data from forensic examiners.
- It is important to know what right looks like and the places that are most likely to be compromised by a malicious actor.

### 2: Windows Registry Structure 
The registry is comprised of **Registry Hives** which contain **Keys, Subkeys, and Values**
#### 2.1 Registry Keys and Values
1. **Keys** - are known as **Registry Hives** and can contain subkeys and values.
2. **Subkeys** - can contain subkeys and values
3. **Values** - contain data in specific formats.

Example Registry Layout (pulled from Microsoft documentation)
```
HKEY_Local_Machine (HIVE)
              ├──SOFTWARE (Key)
              ├──BCD00000 (Key)DeepTime Python,
```
Contains configuration information for the entire computer. Its values are read every time the machine is started regardless of the user who logs in. Its subkeys are :
- HARDWARE - contains a database of installed devices along with their drivers
- SAM - Security Account Manager stores user and group accounts along with NTLM hashes of passwords
- Security - Local Security policy accessed by lsass.exe used to determine rights and permissions for users on the machine
- System - Contains keys pertaining to system startup such as programs started on boot or driver load order.
2. HKEY_USERS (HKU)
Contains all all user profiles on the system. Contains one key per user on the system. Each key is named after the SID(Security Identifier) of the user.

HKEY_USERS contains some of the following information:
- User Environment settings for the desktop
- Shortcuts
- File associations

Some HKEY_USERS are called Well Known SIDs.. They identify default accounts in Windows used for various purposes. Examples include:

- **S-1-5-18** refers to LocalSystem account.
- **S-1-5-19** refers to LocalService account. It is used to run local services that do not require LocalSystem account.
- **S-1-5-20** refers to NetworkService account. It is used to run network services that do not require LocalSystem account.
- **S-1-5-21-domain-500** Refers to the built in local administrator account.
3. HKEY_CURRENT_USERS (HKCU)
HKEY_CURRENT_USER is the copy of the logged in user’s registry key based on thier SID from HKEY_USERS.
```
HKEY_USERS (HIVE)
              └──SID (S-1-5-21-3939661428-3032410992-3449649886-XXXX) (Key)
```
4. HKEY_CURRENT_CONFIG
5. HKEY_CLASSES_ROOT
#### 2.3 Registry Structure and Data Types
| Registry Path Hive | Supporting Files | 
| -- | -- | 
| HKLM\SAM | SAM, SAM.LOG|
| HKLM\SECURITY | SECURITY, SECURITY.LOG |
| HKLM\SOFTWARE | software, software.LOG, system.sav | 
| HKLM\HARDWARE | (Dynamic, volatile hive) |
| HKU\.DEFAULT | default, default.LOG, default.sav |
| HKU\SID | NTUSER.DAT | 
| HKU\SID_CLASSES | UsrClass.dat, UsrClass.dat.LOG |

| Types of extensions | what they mean (might be hidden) | 
| -- | -- | 
| No extension | Actual Hive File |
|.alt extension | Backup copy of hive, used in Windows 2000 | 
| .log extension | Transaction log of changes to a hive | 
| .sav extension | Backup copy of hive created at the end of text-mode (console) | 


### 3: Registry Manipulation
**sysinternals** = set of tools from Microsoft available to all
Turn off anti-virus and turn off hotkeys
```
Get-MpPreference
Set-MpPreference -DisableRealtimeMonitoring $True
new-item "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe"
New-ItemProperty -path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe" -Name Debugger -Type String -Value C:\Windows\System32\cmd.exe
```
#### 3.1 View/manipulate the registry with a GUI
I'd recommend just looking ath the SFG for this
#### 3.2 View/manipulate the registry via CMDLINE
- CLI
- Located at C:\Windows\System32\reg.exe
- Can connect to a remote registry, using the PC’s NetBios Name or IP address
    - Does not have to be in workgroup/domain. Only need username/password
    - Needs the RemoteRegistry Service (svchost.exe / regsvc.dll) to be running to work
- Can load hives files from disk to the active registry
- Available in XP and beyond
- Can only export text .reg files
- Can only query HKLM and HKU remotely

Reg.exe help
```
reg /?                    #Displays help for all of the reg.exe commands
reg query /?              #Displays help for the `reg query`
reg add /?                #Displays help for `reg add`
reg delete /?             #Displays help for `reg delete`
``` 
Reg query - Reads keys from specific registry locations 
` reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run `
Reg add = Adds keys to specific registry locations
` reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run /v testme /t REG_SZ /d C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe `
- The /v stands for Value; In this case the name of this Key Value.
- The /t stands for Type; Types can be any of the Data Types that we went over earlier.
- The /d stands for Data; Is what is the actual Data or in this case a command to open a file every time the system is ran.
Reg delete - Deletes keys
` reg delete HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run /v testme `

#### 3.3 Registry Manipulation w/ PowerShell 
**Minimum Commands to Know**
- Query
    - **Get-ChildItem** cmdlet gets the items in one or more specified locations.
    - **Get-ItemProperty** cmdlet gets the items in one or more specified locations.
    - **Get-Item** cmdlet gets the item at the specified location. It doesn’t get the contents of the item at the location unless you use a wildcard character (*) to request all the contents of the item.

- Modify
    - **Set-ItemProperty** cmdlet changes the value of the property of the specified item. example, changing setting to :true or :false.
    - **Remove-ItemProperty** cmdlet to delete registry values and the data that they store.

- Create
    - **New-Item** cmdlet creates a new item and sets its value. In the registry, New-Item creates registry keys and entries.
    - **New-Itemproperty** cmdlet creates a new property for a specified item and sets its value. Typically, this cmdlet is used to create new registry values, because registry values are properties of a registry key item.

#### 3.4 - 6
Not covered in class, but helpful material 

## Alternate Data Streams

### 1

**`gci -recurse | % {gi $_.FullName -stream *} | where stream -ne ':$Data'`**

## 01_windows_powershell

CimClasses2
To complete this challenge, find the description of the Lego Land service.
`Get-WmiObject win32_service | where-object {$_.Name -eq 'LegoLand'} | format-list Description`

Logic4
Count the number of files in the Videos folder in the CTF user's home directory.
` (Get-ChildItem Videos/ | measure-object).count`

Logic5
Find the only line that makes the two files in the CTF user's Downloads folder different.
`Compare-Object (get-content new.txt) (Get-Content old.txt)`

Logic6
The password is the 21st line from the top, in ASCII alphabetically-sorted, descending order of the words.txt file
`Get-Content .\words.txt | sort-object -Descending | select -Index 20`

Logic7
Count the number of unique words in words.txt, found on the CTF user's desktop, in the CTF folder
` (Get-Content .\words.txt | sort-object -Unique).count`

basics8
How many methods are available for the get-process cmdlet?
`(Get-Process | get-member -membertype method).count`

Logic9
Count the number of folders in the Music folder in the CTF user’s profile.
`(Get-ChildItem .\Music\ -recurse | Where-Object {$_.PSIsContainer }).count`

regex_2
Count the number of times, case-insensitive, gaab is listed in words.txt in the CTF folder on the CTF user's desktop
`(gc .\words.txt | Select-String -allmatches "gaab").count`

regex_3
Count the number of words, case-insensitive, with either a or z in a word, in the words.txt file on the CTF user's desktop
` ($content | Where-Object {$_ -match "[a,z]"}).count`

regex_4
Count the number of times az appears in the words.txt file on the CTF user's desktop.
`($content | Where-Object {$_ -match "az"}).count`


## 02_widows_powershell_profiles
Profiles1
Which PowerShell profile has the lowest precedence?
`current user, current host`

Profiles2
Which PowerShell profile has the highest precedence?
`all users, all hosts`

Profiles3
Which PowerShell variable stores the current user’s home directory
`$Home`

Profiles4
Which PowerShell variable stores the installation directory for PowerShell?
`$PSHOME`

Profiles5
Which PowerShell variable stores the path to the "Current User, Current Host" profile?
`$PROFILE`

Profiles6
What command would you run to view the help for PowerShell Profiles?

Profiles7
What command would tell you if there was a profile loaded for All Users All Hosts
`Test-Path -Path $PROFILE.AllUsersAllHosts`

# Day 2

## 05_windows_registry

basics_1
What registry hive contains all machine settings?
HKLM

basics_2
What registry hive contains all user settings?
HKU

basics_4
hkey_current_user\hkey_users

## 06_windows_file_system
basics_7

```
C:\Windows\System32\drivers\etc> get-acl hosts |format-list
builtin\users
```

basics_9
Find the last five characters of the MD5 hash of the hosts file
`PS C:\Users\CTF\Favorites> cat .\README`

basics_10
There is a hidden directory in the CTF user's home directory. The directory contains a file. Read the file.

`ls -force` shows hidden files/ directories depending

basics_12
Find the ADS in CTF user's home, and read it

```
gci -recurse | % {gi $_.FullName -stream *} | where stream -ne ':$Data'
cat .\Documents\nothing_here:hidden
```
basics_13

`cat Microsoft.Powershell.Core\FileSystem::C:\Windows\PLA\not_anihc\"The Fortune Cookie:none"
Password: fortune_cookie` 

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

## Windows Process Validity

## ADD SYSINTERNALS TO YOUR WINDOWS BOX ON TEST DAY 
use `netuse` to connect to the internet to grab it
use `winget` too 

access it with: 
`net use * https://live.sysinternals.com/tools`

switch into z drive with `z:`
download what you want with `z:*process*.exe`
run with: `\.*process*.exe`

**use `.\procmon.exe` to check process monitors** 
# of characters in salt: 8, 86, sha-512

## Windows Process Validity 
Big Mike Got Killed In Russia: BIOS, MBR (master boot record), Kernel, Init, Runlevels 
### 1 what is process validity and why it matters 

#### 1.1 What is Process Validity 
- Being able to distinguish a Process as a known good from a possible bad from its attributes and characteristics.
- Today’s Malware typically use their stealth and obfuscation abilities in order to hide in various artifacts such as:
    - processes
    - files
    - registry keys
    - drivers
- They try to leave as little evidence of their presence as possible by mimicking or by hooking onto legitimate processes or services.

#### 1.2 Why is PV important
- OCO - Offensive Operations
    - We need to protect our toolset (malware we’ve created).
    - Find any other types of malware on the box that could compromise our tools.

- DCO - Defensive Operations
    - Find malware and defend our networks
    - Make sure we are not compromised or have sensitive information stolen from us.
        - Could be the difference between life and death for soldiers on mission.

### 2 Processes, DLLs, and Services

#### 2.1 What are they? 

Process
- A program running on your computer, whether executed by the user of running in the background
    -Backgroudn tasks like spell checker
    - Executables like Chrome and Notepad

DLL
- Data Link Layer
- A non-standalone prgrame that can be run by (linked to) multiple programs at the same time
- allows developers to make minor chagnes without affecting other parts of the program
    - cComdlg32, performs common dialog box related functions
    - Device drivers
    - ActiveX controls

Service
- Long-running executables that run in their own Windows sessions (i.e. in the background)
    - Can be set to auto start when the computer boots or a user logs on
    - can be paused and restarted
    - do not interact with/ show any user interface

#### 2.2 How to view Processes and DLLs
- PS: `Get-Process`
- CMD: `tasklist`

##### 2.2.1 View Processes in PS
view all: `Get-Process`
View all sorted by PID: `Get-Process | Sort -Property Id | more`
View all Headers: `Get-Process | Get-member`
View all processes, but sort by PID and only show the properties I define: `Get-Process | Select Name, Id, Description | Sort -Property Id | more`
View only the processes I define and sort by PID: `Get-Process SMSS,CSRSS,LSASS | Sort -Property Id`
View only modules/DLLs used by Chrome with "chrome" in the name and their file locations.
`Get-Process chrome | foreach {$a} {$_.modules} | Where-Object ModuleName -like '*chrome*' | more`
`Get-Process -Name "*chrome*" | Select-Object -ExpandProperty Modules | Where-Object ModuleName -like '*chrome*' | more`
Pipe in a `ft -wrap` to see full file name/path.

**Command he gave in class**
`get-process | select name,id,path | where {($_.Path -notmatch "system32" -and $_.Path -notmach "Program Files")} | ft -wrap`

##### 2.2.2 View Processes in CMD
View all processes `tasklist`
Display verbose task information in the output `tasklist /v`
Display service information for each process without truncation `tasklist /svc`
Display modules/dlls associated to all processes `tasklist /m | more`
Display modules/dlls associated to a specific process. `tasklist /m /fi "IMAGENAME eq chrome.exe"`
Formating options `tasklist /fo:{table|list|csv}`
Filtering for specific string/process `tasklist /fi "IMAGENAME eq lsass.exe"`

#### 2.3 How to View Services
In Powershell:

`Get-Ciminstance `
`Get-Service `

In Command Prompt:

`net start` - Shows currently running services
`sc query `

**Use `netstat` in CMD to see network activitty**

### 3 Scheduled Tasks

#### 3.1 What are schedules tasks?
Schedule the launch of programs or scripts when defined conditions are met, such as:
- Pre-set time (ex. 0900 on Sundays)
- When the local machine boots up.
- When a user logs on.
Easy way to hide Malware and have itself set to execute at set times.
- Separate files can be run from schedule tasks that calls the malware, like a script
Good way to establish Persistence.

#### 3.2 How to view scheduled tasks
PS: `Get-ScheduledTask | Select * | select -First 1`
CMD: `schtasks /query /tn "IchBinBosh" /v /fo list`

##### 3.2.4 Autorun Registry Locations
Q: What are some Registry keys that can be used for autoruns?

Registry Keys Locations, Locations connected with Services.

HKLM\Software\Microsoft\Windows\CurrentVerstion\Run - Local Machine

HKLM\Software\Microsoft\Windows\CurrentVerstion\RunOnce

HKLM\System\CurrentControlSet\Services

Remember that the Users have individual Hives with autoruns as well as the Current User.

HKCU\Software\Microsoft\Windows\CurrentVerstion\Run - Current User

HKCU\Software\Microsoft\Windows\CurrentVerstion\RunOnce

HKU\<sid>\Software\Microsoft\Windows\CurrentVerstion\Run - Specific User

HKU\<sid>\Software\Microsoft\Windows\CurrentVerstion\RunOnce

The order in which services are loaded can be adjusted.

HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\ServiceGroupOrder

HKEY_LOCAL_MACHINE\CurrentControlSet\Control\GroupOrderList

### 4 Network Connections

#### 4.1 View Network Connections in Powershell
Show all Connections in the "Established" state. `Get-NetTCPConnection -State Established`

#### 4.2 View Network Connections in CMD
`netstat /?`
`netstat -anob | more` 

### 5 Identifying Abnormalities/ Suspicious Activity 

## Sysinternals for Windows

1. Sysinternals Introduction
2. Procmon
3. Autoruns
4. Procexp
5. TCPView
6. PsExec
7. PsLoggedon
8. LogonSessiosn
9. PsList
10. PsInfo
11. Strings
12. Handle

## Windows Artifacts, Auditing, and Logging 

### 1 Windows Artifacts

#### 1.1 What is an artifact?
- Artifacts are objets or areas within a computer system that contain important information relevant to the activities performed on the system by the user 
- These artifacts must be identified, processed, and analyzed in order to prove or disprove any observations made during forensic analysis
- It should be noted that absence of information in an artifact does not indicate that na activity did not occur within the computer system
- There are multple artifacts in the Windows environment that serve as important evidence in the forensic examination process

#### 1.2 Why are they relevant?Aragon,BruceWayne,Eowyn,Nazgul,Tolkein
- Understanding artifacts in Windows is curical for forensic examiners 
- Examiners will most likley encouter Windows and will have to collect evidence from it in almost all cyber-crime cases
- There are several places where evidence can be gathered and ways to collect info from Windows
- Windows provides and abundance of artifacts. Being aware of tese artifacts is helpful for examiners trying to permanently and irrevocably erase sensitive information or perofrm informal investigations
- Collecting evidence is not the sole challenge to examiners, the challenge is to locate and identify, collect, perserve, and inerpret information, *whereas collecting is only one piece of the puzzle*

#### 1.3 Artifacts Covered
At the end of this lesson, you will be able to describe and pull information from the following artifacts
1. UserAssist
```
 #CEBFF5CD: Executable File Execution
Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count"
 #F4E57C4B: Shortcut File Execution
Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{F4E57C4B-2036-45F0-A9AB-443BCFE33D9F}\Count"
```
2. Windows Background Activity Moderator (BAM)
```
#Every User on the System
Get-Item HKLM:\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\*

#Be careful, we may not need State for 1803 and older for the subdirectory
#so it looks like:
Get-Item HKLM:\SYSTEM\CurrentControlSet\Services\bam\UserSettings\*
#Single User on the System
Get-Item HKLM:\SYSTEM\CurrentControlSet\Services\bam\state\UserSettings\S-1-5-21-3385255940-4185786428-2400321831-1005
```
3. Prefetch
`Get-Childitem -Path 'C:\Windows\Prefetch' -ErrorAction Continue | select -First 50`
This will show the hashes of all executables which will show you the location on the hard drive
Look up Prefetch location hash calculator 
4. Jump Lists
```
#Programs/Items that were recently used
Get-Childitem -Recurse C:\Users\*\AppData\Roaming\Microsoft\Windows\Recent -ErrorAction silentlyContinue | select FullName, LastAccessTime
Get-Childitem -Recurse C:\Users\andy.dwyer\AppData\Roaming\Microsoft\Windows\Recent -ErrorAction SilentlyContinue | select FullName, CreationTime |ft -wrap
Get-Childitem -Recurse C:\Users\andy.dwyer\AppData\Roaming\Microsoft\Windows\Recent -ErrorAction SilentlyContinue | select FullName, LastAccessTime |ft -wrap
#or
Get-Childitem -Recurse $env:USERPROFILE\AppData\Roaming\Microsoft\Windows\Recent -ErrorAction SilentlyContinue | select FullName,LastAccessTime | ft -wrap
```
They're essentially a list of things they think will be used commonly by a user. It's kinda the same as a start menu. It will give defaults but then be populated by other things the user uses often. It will contain both executables and routine taskings
5. Recycle Bin
Get-Childitem 'C:\$RECYCLE.BIN' -Recurse -Verbose -Force | select FullName

```
Be aware, the location and contents of a file are seperated. Look for the $I.... for the file location/ name and the $R.... for the contents 

for example $IA950GM.txt is the location/ name and $RA950GM.txt is the contents
6. Recent Files
```
#RECENT FILES
Get-childItem 'Registry::\HKEY_USERS\*\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs\.txt'
Get-childItem 'Registry::\HKEY_USERS\*\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs\.*'
#Converting a Single Value from Hex to Unicode
```

7. Browser Artifacts
```
#https://www.exploit-db.com/Exploit

# User Names
strings.exe  'C:\users\andy.dwyer\AppData\Local\Google\Chrome\User Data\Default\Login Data'
strings.exe  'C:\users\andy.dwyer\AppData\Local\Google\Chrome\User Data\Default\Login Data' | findstr -i "https*"



### 2 Windows Auditing & Logging and PowerShell Artifacts 

#### 2.1 Auditing
Windows auditing is a mechanics for tracking events. Knowing when and where these events occured and who triggered them can help when doing Windows network forensics. It can also be very helpful with detecting certain types of problems like improper rights assignments in the file system. Events fall into several categories:
1. Account logon events
2. Account Management
3. Directory service access
4. Logon events
5. Object access
6. Policy change
7. Privilege use
8. Process Tracking
9. System events

Please look at the FG for exampes

#### 2.2 Events Logs
Logs are records of events that happen in your computer, such as when a user logs on to the computer or when a program encounters an error. Users might find the details in event logs helpful when troubleshooting problems with Windows and other programs. They also help you track what happened.

Early windows editions, starting with Windows NT, came with three Windows logs: Application event log, System event log and Security event log. Modern versions of Windows come with more than a hundred of Windows eventlogs, and third party applications can create and integrate into Windows logging their own event logs.

##### Locations
*.evtx files accessed by:

1. Windows Event View Application
2. Get-Eventlog or Get-WinEvent in Powershell
3. wevtutil in Command Prompt


## windows_articats CTFs
browser artifacts_1
What Sysinternals tool will allow you to read the SQLite3 database containing the web history of chrome?

`strings`

recent_files_1
What is the registry location of recent docs?
`HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs`

prefetch_1
What is the literal path of the prefetch directory?
`C:\Windows\Prefetch`

recycle_bin_1
In the Recycle Bin, there is a file that contains the actual contents of the recycled file. What are the first two characters of this filename?

$R

recycle_bin_2
In the Recycle Bin, there is a file that contains the original filename, path, file size, and when the file was deleted. What are the first two characters of this filename?

$I

userassist_1
What are the first 8 characters of the Globally Unique Identifier (GUID) used to list applications found in the UserAssist registry key (Windows 7 and later)?

`CEBFF5CD` from SFG

userassist_2
What cipher method are UserAssist files encoded in?

ROT13

logs_1
What main Windows log would show invalid login attempts?

Security

logs_2
What main Windows log will show whether Windows updates were applied recently?

system

logs_3
When reading logs, you may notice ... at the end of the line where the message is truncated. What format-table switch/argument will display the entire output?
Flag format: -argument

-wrap

browser_artifacts_2
Find the questionable website that the user browsed to (using Chrome), that appears to be malicious.

`x:.\strings.exe 'C:\Users\student\AppData\Local\Google\Chrome\User Data\Default\History' -accepteula`

`https://www.exploit-db.com/`

prefetch_2
Enter the name of the questionable file in the prefetch folder.

`GCI -Path C:\Windows\Prefetch\`
 DARK_THOTS-8F2869FC.pf

prefetch_3
What is the creation time of the questionable file in the prefetch folder?
Flag format: mm/dd/yyyy

10/28/2021

recycle_bin_3
Recover the flag from the Recycle Bin. Enter the name of the recycle bin file that contained the contents of the flag, and the contents of the deleted file.
Flag format: filename,contents


`$R1X7NFH.txt, DontTrashMeyo`

logs_4
Check event logs for a flag string.
Machine: file-server

`get-eventlog -LogName System | where {$_.Message -match ".*flag.*"}|Format-Table -wrap`

last_access
Figure out the last access time of the hosts fill
Flag format: mm/dd/yyyy

`gi c:\Windows\System32\Drivers\etc\hosts`

```
Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\bam\UserSettings\S-1-5-21-4025152481-2360450962-471945012-1003'
```

recent_files_2
There is a file that was recently opened that may contain PII. Get the flag from the contents of the file.
Hint: We're not interested in numbers.

```
Get-Item "REGISTRY::HKEY_USERS\*\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs\.txt" | select -Expand property | ForEach-Object {                                              >>     [System.Text.Encoding]::Default.GetString((Get-ItemProperty -Path "REGISTRY::HKEY_USERS\*\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs\.txt" -Name $_).$_)  

cd ..\student\Documents\
cat .\3-14-24.txt
Flag, Found A.
```

bam_2
Enter the full path of the program that was run on this computer from an abnormal location.
```
Get-Item HKLM:\SYSTEM\CurrentControlSet\Services\bam\UserSettings\*
C:\Windows\Temp\bad_intentions.exe
```