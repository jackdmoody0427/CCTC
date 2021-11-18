## Windows Notes and CTFs

## Windows_Powershell
## 1. Basic Powershell Concepts
### Flags
|name      |value|
|-----------|-----|
|windows_powershell|start2347|
|windows_powershell_profiles|start85678|

#### RDP access (get into windows box using Remme)
1. remme --> put in IP Address
2. Login using credentials from Antora 
3. get into windows box
4. in cortana look up command line
4. use settings to enter as admin
5. ssh andy.dwyer@10.10.0.3
6. enter password 

#### Getting started
- powershell app, use as admin
- PS C:\windows>  --> powershell
- cmd --> moves you to command line
  - C:windows
     ---> this helps you run cmd line while in PS if CMD L isn't available  

#### 1.1 Commands and Arguments

basic commands: based on verb/ noun constructs "cmdlets" are used. 
Written in C, so similar style to python

#### 1.2 PowerShell Help (notes and instructor input)
1. **{cmd} | format-List**, format-Table, etc can help you display info that is cut off 
2. Get-Alias, shows known aliases for shortcuts. You can also make you're own shortcuts to cut down on cmdlet typing
3. Get-Help, shows description of cmdlets Get
4. **copy paste: highlight area then right click twice**
5. cmdlets can get complicated fast, so start small then add on to create robustness
6. **-Path** is how you get the path to a file (ex: ~/usr/desktop/folder/file is -Path ~/usr/...)
7. sometimes you have to do '' and sometimes you have to do "", so just be careful. 
8. -ErrorAction will give you options of what to do when errors occur

#### 1.3: Powershell Object Properties
9. Use | {pipe} to group commands together
10. Get-History shows you the history of all commands you've entered so far 
11. Get-Process

    anatomy of a command:
    - (cmdlet).property
        example (get-process) Name 
    - ex: Get-Process |Select-Object name, ID, path


#### 1.4: Using Methods of Objects
- Get-Process | Get-Member | Where-Object {$_.Membertype -match "Method"}       # Displays all objects with Method in their name from the results from Get-Member of the Get-Process cmdlet

#### 1.5: Pipelined Variables
- PowerShell allows for properties and methods to be called within a pipe using `$_.(The Pipelined Variable)`
- The variable will always be of the same type as the object coming from the previous command
    - `Get-Process | Select-Object Name, ID, path | Where-object {$_.ID -lt '1000'}`            # List all the processes with a PID lower than 1000
    - `(Get-Process | Select-Object Name, ID, path | Where-object {$_.ID -lt '1000'}).count`    # List all the processes with a PID lower than 1000

#### 1.6: Pipelining
- Objects in PS are passed along in pipes (|) based off their inputed cmdlets 

#### 1.7: CIM Classes
- CIM: Common Information Model
- they are classes, but think of them as objects designed to control a specific windows subsystem like the hard drive or BIOS.
    - CIM Classes are the parent classes upon which WMI (Windows Management Instrumentation) classes are built
    - While there are CIM classes of all sorts, there may only be a few CIM instances actually being used
    - **Think of CIM classes as place holders and CIM instances as an actual event**

``` Get-Cimclass *                                                                  # Lists all CIM Classes
Get-CimInstance –Namespace root\securitycenter2 –ClassName antispywareproduct   # Lists the antispywareproduct class from the root/security instance
Get-CimInstance -ClassName Win32_LogicalDisk -Filter “DriveType=3” | gm         # Shows properties and methods for this Instance
Get-WmiObject -Class Win32_LogicalDisk -Filter “DriveType=3”                    # Using the Windows Management Instrumentation method
```
## 2. PowerShell Scripts
Not necessarily critical, but please do on your own time
## 3. PowerShell Profiles
#### Intro
- Not created by default
- Persistent
- **Important when thinking about adversaries**
- They don't kick off unless you start PS, so keep that in mind
- They're essentially just scripts that have configurations set 
- So, think about what you want to do, break it down, make it piece by piece, trouble shoot piece by piece individually, then paste into script until you have everything you want. If you want to get fancier, refer to section 2
- They are designed to make basic things faster such as loops or routine checking of things 
- Find them using `$Profile` 
#### 3.1: PS Profile Paths
```
$PsHome         # Stores the installation directory for PowerShell
$Home           # Stores the current user’s home directory
```
**SUPER IMPORTANT PATH CHECKS** 
```
Test-Path -Path $profile.AllUsersAllHosts
Test-Path -Path $profile.AllUsersCurrentHost
Test-Path -Path $profile.CurrentUserAllHosts
Test-Path -Path $profile.currentUsercurrentHost
```
- Testing these return false for all of them because they are testing the 4 powershell profiles, adn they are not created by default. therefore, if one exsists, someone made it. then you need to think about whether they were made for nefarious purposes or with good intent.
- They can be nefarious because they are just a script. it could be listening, cating to a port, then pushing/ exfiling out of listening port to spy on you. 
- Whenever you start PS, it's goin gto loook for these scripts and run them without checkig first, so you must be careful. 
#### 3.2: Creating a PowerShell Profile
```
New-Item -ItemType File -Path $profile -Force                 # Creates a $Profile for the CurrentUser. Force is used to ignore any errors.
ISE $profile                                                  # Opens your newly created $Profile, which is empty
```
- By default, PowerShell Aliases are not saved if you close a PowerShell window session.
    -For example, if you create a few Aliases and close the PowerShell window, you will be required to recreate the same PowerShell aliases.
    -This would obviously present a problem if you have Aliases set up for use in PowerShell scripts.
Functions:
```
function Color-Console {
  $Host.ui.rawui.backgroundcolor = "black"
  $Host.ui.rawui.foregroundcolor = "green"
  $hosttime = (Get-ChildItem -Path $PSHOME\PowerShell.exe).CreationTime
  $hostversion="$($Host.Version.Major)`.$($Host.Version.Minor)"
  $Host.UI.RawUI.WindowTitle = "PowerShell $hostversion ($hosttime)"
  Clear-Host
}
Color-Console
```
Transcripts:
```
start-transcript
start-transcript | out-null                       # Pipe to out-null so users don't see that commands are being recorded

Start-Transcript C:\MyWork.txt                    # Starts to log commands into the c:\mywork.txt file
Get-Service                                       # Run get-service command and inputs that and the results into the transcript.
Stop-Transcript                                   # End the transcript
notepad c:\MyWork.txt                             # View the contents of the created transcript
```

#### Sudo 3.3: Malicious Attack Thoughts
`Start-Transcript| Out-Null command`: Essentially a key logger, you can also push it to a file too to save everything you wrote. It will die when you kill the PS session though. The `Out-Null` makes it so the notifications for the start and end of the function from popping up on the Command Line. 
```
Start-Transcript C:\MyWork.txt                    # Starts to log commands into the c:\mywork.txt file
Get-Service                                       # Run get-service command and inputs that and the results into the transcript.
Stop-Transcript                                   # End the transcript
notepad c:\MyWork.txt                             # View the contents of the created transcript
```

#### 4. Windows Remoting
  - Uses WinRM and WS-Man for simplified network config.
  - Only 1 port needed through firewall. WinRM's comms are encrypted.
  - If there is a version difference between 2 systems, lower version is used.
  - Initiating user must be in *administrators* or *remote management* group.
    - Check session parameters via `Get-PSSessionConfiguration`
  - Clients must enable PowerShell Remoting (enabled by default on servers > 2012)
    - Clients with public network profile enabled must use `SkipNetworkProfileCheck` parameter or `Enable-PSRemoting` will fail
      - This allows remote connections from hosts in local subnet through client firewall
  - Querying current network profiles
    - `Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles`
  - Network Profile Registry Values
    - Public -> 0
    - Private -> 1
    - Domain -> 2
##### 4.1 PowerShell Remoting Security
  - Uses Kerberos for auth. Using HTTPS encrypts headers too.

-------
## CTF Responses 

## 01_windows_powershell

CimClasses2: To complete this challenge, find the description of the Lego Land service.
- `Get-WmiObject win32_service | where-object {$_.Name -eq 'LegoLand'} | format-list Description`

Logic4: Count the number of files in the Videos folder in the CTF user's home directory.
- ` (Get-ChildItem Videos/ | measure-object).count`

Logic5: Find the only line that makes the two files in the CTF user's Downloads folder different.
- `Compare-Object (get-content new.txt) (Get-Content old.txt)`

Logic6: The password is the 21st line from the top, in ASCII alphabetically-sorted, descending order of the words.txt file
- `Get-Content .\words.txt | sort-object -Descending | select -Index 20`

Logic7: Count the number of unique words in words.txt, found on the CTF user's desktop, in the CTF folder
- ` (Get-Content .\words.txt | sort-object -Unique).count`

basics8: How many methods are available for the get-process cmdlet?
- `(Get-Process | get-member -membertype method).count`

Logic9: Count the number of folders in the Music folder in the CTF user’s profile.
- `(Get-ChildItem .\Music\ -recurse | Where-Object {$_.PSIsContainer }).count`

regex_2: Count the number of times, case-insensitive, gaab is listed in words.txt in the CTF folder on the CTF user's desktop
- `(gc .\words.txt | Select-String -allmatches "gaab").count`

regex_3: Count the number of words, case-insensitive, with either a or z in a word, in the words.txt file on the CTF user's desktop
- ` ($content | Where-Object {$_ -match "[a,z]"}).count`

regex_4: Count the number of times az appears in the words.txt file on the CTF user's desktop.
- `($content | Where-Object {$_ -match "az"}).count`

regex_5: On the CTF user's desktop, count the number of words in words.txt that meet the following criteria:
a appears at least twice consecutively
and is followed immediately by any of the letters a through g
Example: aac...aaa...

- `cd C:\Users\CTC\Desktop\CTF\words.txt`
- `(gc .\words.txt | Select-String -pattern "aaa|aab|aac|aad|aae|aaf|aag").length`
- 357

## 02_widows_powershell_profiles
Profiles1: Which PowerShell profile has the lowest precedence?
- `current user, current host`

Profiles2: Which PowerShell profile has the highest precedence?
- `all users, all hosts`

Profiles3: Which PowerShell variable stores the current user’s home directory
- `$Home`

Profiles4: Which PowerShell variable stores the installation directory for PowerShell?
- `$PSHOME`

Profiles5: Which PowerShell variable stores the path to the "Current User, Current Host" profile?
- `$PROFILE`

Profiles6: What command would you run to view the help for PowerShell Profiles?

Profiles7: What command would tell you if there was a profile loaded for All Users All Hosts
- `Test-Path -Path $PROFILE.AllUsersAllHosts`

-----------
## Windows_Registry

### Flags
|name      |value|
|-----------|-----|
|windows_registry|start357|
|windows_file_system|start3486|

#### 2.1 Windows Registry Introduction
  - Central heirarchical database in Windows
  - Can house malicious code, passwords, binaries
  - Combination of multiple directories in Linux
    - ex. `/dev`, `/etc`
#### 2.2 Registry Structure
  - Registry is composed of **keys (registry hives), subkeys, and values**
  - `HKEY_CURRENT_USER` is also found in `HKEY_USERS` (it's a symlink)
    - These are examples of **keys (registry hives)**
  - 5 Registry Hives:
    - `HKEY_LOCAL_MACHINE`: Configuration for entire computer. Values read every time regardless of user. Contains:
      - `HARDWARE`: db of installed devices/drivers
      - `SAM`: Security Acc Manager: stores users/NTLM hashes of passwords
      - `Security`: Security policy determining user perms
      - `System`: Keys pertaining to system startup, i.e. boot/driver programs
    - `HKEY_USERS`: Contains all user profiles. 1 key per user. Key is named after **SID (Security Identifier)** of the user.
      - Also includes _Well Known SIDs_
      - to correlate SID with userID:
        - `get-wmiobject win32_useraccount | select name, sid`
        - `get-Localuser | select name, sid`
        - `wmic useraccount get name, sid`
    - `HKEY_CURRENT_USERS`: copy of current user's registry key based on SID from `HKEY_USERS`
    - `HKEY_CURRENT_CONFIG`: symlink to `HKLM/SYSTEM/CurrentControlSet/HardwareProfiles/Current`
    - `HKEY_CLASSES_ROOT`: symlink to `HKLM/Software/Classes`
#### 2.3 Registry Manipulation
  - Manipulate remote registry via GUI
    - File -> Connect Network Registry -> `file-server`
  - Create copy of registry
    - File -> Import/Export
  - `regedit` to manipulate via GUI
    - commonly disabled using group policy
  - `reg` to manipulate via cmd/PS
    - `reg /?`
    - `reg query/add/delete`
      - `reg query  HKLM\...\Run`
      - `reg add    HKLM\...\Run /v value /t type /d data`
      - `reg delete HKLM\...\Run /v value`
  - commands to manipulate via PS
    - Query:
      - `Get-ChildItem`: only shows subkeys in the specified directory
        - `Get-ChildItem HKLM:\SOFTWARE\...\Run` -> nothing
        - `Get-ChildItem HKLM:\SOFTWARE\...\CurrentVersion` -> many subkeys
      - `Get-ItemProperty`: gets value of key + other shit
      - `Get-Item`: gets actual value of the key
        - `Get-Item HKLM:\SOFTWARE\...\Run` -> gets value of `Run`
    - Modify
      - `Set-ItemProperty`
      - `Rename-ItemProperty`
      - `Remove-ItemProperty`
    - Create
      - `New-Item`: creates new subkey
        - `New-Item HKLM:\SOFTWARE\...\trustedrecords -force`
      - `NewItemProperty`
  - Sethc.exe demonstration (manipulating sticky keys function)
    - We will bind sticky keys (pressing shift 5 times) to open admin terminal, rather than applying sticky keys. Antivirus must be turned off for this to work.
      - `GetMpPreference`: gets status of antivirus (and other things)
        - `DisableRealTimeMonitoring` = `True` implies antivirus is off
          - if `False`, to turn it off (change it to `True`), run:
            - `Set-MpPreference -DisableRealTimeMonitoring $TRUE`
      - `New-Item "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe"`
      - `New-ItemProperty -path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe" -Name Debugger -Type String -Value C:\Windows\System32\cmd.exe`
    - move this exploit to a thumb drive
      - sysinternals provides technical utilities remotely
        - `net use * https://live.sysinternals.com/tools`
        - `net use`
      - `Z:\autoruns.exe -accepteula`
        - Image Hijacks -> Jump To Entry -> Image File Execution Options -> sethc.exe -> export

#### 2.4 PowerShell PSDrives
  - PSDrive is a data store that's accessible similar to a file system
  - Creates a temp/permanent way for PS to navigate registry like a file system
  - `Get-PSDrive` fetches list of drives
  - `New-PSDrive -Name Demo -PSProvider FileSystem -Root C:\Demo` creates a new PSDrive
    - access it via `cd Demo:`
  - `Remove-PSDrive Demo` to remove a PSDrive
  - Creating more PSDrives:
    - `New-PSDrive -Name Desktop -PSProvider FileSystem -Root C:\users\student\Desktop`
    - `New-PSDrive -Name HKLM-Run -PSProvider Registry -Root HKEY_Local_Machine\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
    - `New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS`
    - `New-PSDrive -Name FileServer -PSProvider FileSystem -Root "\\file-server\warrior share"`
#### 2.5 Registry Locations of Interest
  - Some changes take effect on reboot. Some take effect immediately.
  - Significant keys are ones that affect persistence and privilege escalation.
#### 2.6 Security
  - Keys in the registry can contain Security Descriptors.
  - Security Descriptors can contain ACLs/ACEs.

---

### 3. Alternate Data Streams
#### 3.1 Overview
  - Introduced to NTFS in Windows NT 3.1 in order to maintain backwards compatibility with HFS+, NWFS, NSS, etc.
  - ADS is used to store metadata, and can be used to hide data using NTFS
  - ADS cannot be disabled, and doesn't change MD5 hash of a file (checks if it's been modified)
#### 3.2 Usage in CMD
  - File Example
    - `echo Always try your best > reminder.txt`
    - `echo ssn > reminder.txt:secret.info`
      - after execution, `dir` and `type` show no difference, indicating that there has supposedly been no change
      - to view changes, use `dir \R reminder.txt` and `more < reminder.txt:secret.info`
        - `type` will not show you contents - must use `more`
  - Can be used the same for a directory instead of a file

#### 3.3 (Malicious) Usage in PowerShell
  - Create innoccuous-looking file
    - `Write-Output "nothing to see here" > test.txt`
    - `Get-ChildItem`
  - Add secret shit
    - `Add-Content -Path .\test.txt -Value 'Dim oShell' -Stream 'secret.vbs'`
    - `Add-Content -Path .\test.txt -Value 'Set oShell = Wscript.CreateObject("Wscript.Shell")' -Stream "secret.vbs"'`
    - `Add-Content -Path .\test.txt -Value 'oShell.run "cmd /k cd C:\Program Files & ping 8.8.8.8", 1, true' -Stream 'secret.vbs'`
  - View secret shit, maybe edit it further
    - `Get-Content .\test.txt -Stream secret.vbs`
    - `notepad .\test.txt:secret.vbs`
  - Run secret shit
    - `wscript .\test.txt:secret.vbs`
  - View list of alternate data streams
    - `Get-Item test.txt -Stream * | select FileName,Stream`
    - `gci -recurse | % {gi $_.FullName -stream *} | where stream -ne ':$Data'`

HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS\CURRENTVERSION\RUNONCE
cd C:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.195.1.1\amd64_microsoft-windows-microsoftedge_31bf3856ad364e35_10.0.17763.195_none_85ca37ee75f1f6bd

----
## CTF Responses

#### 5_windows_registry 

basics 1: What registry hive contains all machine settings?
- HKLM

basics 2: What registry hive contains all user settings?
- HKU

basics 3: What registry hive contains only the currently logged-in user's settings?
- HKCU

basics 4: The HKEY_CURRENT_USER registry hive is a symbolic link to another registry subkey. What is the subkey that it is linked to?
basics 5:

basics 6:

basics 7:

basics 8:

basics 9: What registry sub-key runs a single time, then deletes its value once the machine reboots? The flag is the full path, using PowerShell.
Flag format: FULL\PATH\ALL\CAPS
- `HKLM\SOFTWARE\MICROSOFT\WINDOWS\CURRENTVERSION\RUNONCE`

basics 10:

basics 11:

basics 12: What is the value inside of the registry key that loads every time the "Student" user logs on?
- `Get-ItemProperty '.\S-1-5-21-4025152481-2360450962-471945012-1003\Software\Microsoft\Windows\CurrentVersion\Run\'`
- C:\botnet.exe

basics 13: What is the value inside of the registry sub-key from Basics_9?
- `reg query HKLM\SOFTWARE\MICROSOFT\WINDOWS\CURRENTVERSION\RUNONCE`
- HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS\CURRENTVERSION\RUNONCE
    McAfee    REG_SZ    C:\virus.exe
- c:\virus.exe

basics 14: What is the value inside of the registry key that loads a single time when the "Student" user logs on?
- `Get-ItemProperty '.\S-1-5-21-4025152481-2360450962-471945012-1003\Software\Microsoft\Windows\CurrentVersion\RunOnce\'`
- C:\worm.exe

basics 15: Figure out the manufacturer's name of the only USB drive that was plugged into this server.
- `gi "HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR\"`
- SanDisk

basics 16: What suspicious user profile, found in the registry, has connected to this machine?
- `Get-ChildItem "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\ProfileList"`
- Hacker_McHackerson

basics 17: What suspicious wireless network, found in the registry, has this system connected to?
- `Get-ChildItem "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles"`
- Terror_cafe_network

#### 6_Windows_File_System
basics 1: Every file on a Windows system has attributes. What does the d attribute mean?
- Directory

basics 2: Every file on a Windows system has attributes. What does the h attribute mean?
- hidden

basics 3: What PowerShell command will list all files in the current directory, regardless of their attributes?
- `Get-ChildItem -Force`

basics 4: What PowerShell command will give you the sha512 hash of a file? Flag format: command -argument
- `Get-FileHash -Algorithm SHA512`

basics 5: What PowerShell command will list permissions of a file?
- `Get-Acl`

basics 6: What Windows file maps hostnames to IP addresses?
- Hosts

basics 7: Which group has ReadandExecute (RX) permissions to the file listed in the previous challenge, basics_6?
- `(Get-Acl -Path hosts).Access`
- BUILTIN\Users

basics 8: Find the last five characters of the MD5 hash of the hosts file.
- `Get-FileHash hosts -Algorithm MD5 | Format-list`
- 7566D

basics 9: Examine the readme file somewhere in the CTF user’s home directory.
- `Get-ChildItem -Path . -Filter readme -Recurse -ErrorAction SilentlyContinue -Force`
- 123456

basics 10: There is a hidden directory in the CTF user's home directory. The directory contains a file. Read the file.
- `Get-ChildItem -Force`
- ketchup

basics 11: Find a file in a directory on the desktop with spaces in it.
- 987654321

basics 12: Find the Alternate Data Stream in the CTF user's home, and read it.
- `gci -recurse | % {gi $_.FullName -stream *} | where stream -ne ':$Data'`
- `Get-Content .\nothing_here -Stream hidden`
- P455W0RD

basics 13: "Fortune cookies" have been left around the system so that you won't find the hidden password...
- `gci -recurse | % {gi $_.FullName -stream *} | where stream -ne ':$Data'`
- `cd C:\Windows\PLA\not_anihc`
- `Get-Content '.\The Fortune Cookie' -Stream none`
- fortune_cookie  

basics 14: There are plenty of phish in the C:, but sometimes they're hidden in plain site.
- `cd C:\Users\CTF\Documents\WWW`
- `Get-ChildItem -Force`
- `cat 200`
- phi5hy

---------------------
## Windows Boot Process

### Flags
|name      |value|
|-----------|-----|
|windows_boot_process|start8633|

#### 1. Boot Process Overview
  - Lengthy process that is difficult to interact with
  - Steps are:
    - Hardware Initialization
      - POST
    - Loading the Boot Sector/Manager
    - Loading the OS from the Boot Sector
  - Significance:
    - **Rootkits:** execute before the OS/antivirus, and can exploit weaknesses in startup
    - **Firmware Rootkits:** overrwite PC BIOS so the rootkit can start before the OS loads
    - **Kernel Rootkits:** replace a portion of the OS kernel so root kit loads with OS
    - **Driver Rootkits:** pretend to be a boot driver that OS uses to talk to PC
    - **Bootkits:** replace OS bootloader to load bootkits before the OS
    - **Avenues of Attack:** exposed OS is vulnerable to compromise
#### 2. BIOS and UEFI
  - **Basic Input Output System (BIOS older version)** and **Unified Extensible Firmware Interface (UEFI, newer)**
    - BIOS and UEFI are _firmware_ that ensure critical hardware (hard drives, SDRAM) are functional, and then locates **Master Boot Record (MBR)** or **GUID Partition Tables (GPT)**
      - _Firmware_ is software-coded non-volatile memory such as ROM, EPROM, EEPROM, Flash memory
    - UEFI is more popular than BIOS, because:
      - UEFI boots faster
      - UEFI loaded into flash memory, faster to update/patch
      - UEFI offers secured boot (only verified drivers can load)
      - UEFI offers drive support up to 9 zettabytes (BIOS only loads 2 TB)
  - BIOS Master Boot Record
    - 3 ways to check if machine is running BIOS or UEFI
      - `bcdedit` is Boot Configuration Data Edit
    ```
    > type C:\Windows\Panther\setupact.log | findstr -i "detected boot environment"
      Callback_BootEnvironmentDetect: Detected boot environment: BIOS
    > bcdedit | findstr -i winload    # note, should only have ONE boot manager
                                      # allowed to have multiple boot loaders
      path                    \windows\system32\winload.exe
    > MSinfo32.exe
    ```
    - After BIOS checks hardware, it finds MBR which contains disk partitions such as `DISK 1 C:` or `/dev/sda1`
      - that partition contains code for the **Boot Loader** that starts loading OS
        - Windows 2003 and older uses NTLDR (New Technology Loader)
        - Windows 7 and newer uses bootmgr
      - Boot Loader takes over from here, and starts the OS
  - UEFI Boot Manager
    - instead of reading MBR, it reads an EFI Partition which contains UEFI Boot Managers
      - Windows `bootmgfw.efi`
      - Boot manager takes over and starts the OS
#### 3. Windows System Initialization
  - Windows Boot Process from kernel (`ntoskrnl.exe`) to `LogonUi.exe` in 5 steps:
    1. Loading OS Kernel
      - BIOS: bootmgr or NTLDR reads `\Boot\BCD` to locate `winload.exe`
        - loads basic drivers and starts to load kernel
      - UEFI: `bootmgfw.efi` reads BCD in EFI system partition to load `winload.efi`
    2. Init Kernel
      - named `ntoskrnl.exe`, critical system file
        - loads windows registry
        - loads device drivers
        - starts system pagefile at `C:\pagefile.sys`
          - **TODO**: what is a pagefile?
        - loads `hal.dll`, which provides abstraction between hardware interfaces and kernel
      - completion of kernel loading prompts spawning of session management processes
        - `smss.exe`
        - `csrss.exe`
    3. Starting Subsystems
      - `smss.exe`: Session Manager Subsystem
        - loads env variables such as `%APPDATA%` and `%COMPUTERNAME%`
        - populates pagefile
        - starts kernel/user subsystems
          - kernel subsystems create/manage every resource by interacting with drivers
            - manages stuff like system power, process/thread creation, graphical rendering, ACLs
            - **users cannot interact with kernel subsystems**
          - user subsystems manipulable
            - manages user applications like process creation, internet, object access
              - via API calls to `hal.dll`
            - run in Session 0 and Session 1
              - **Session 0**: for security and high privilege processes. run in separate session IOT isolate them from user processes
                - `smss.exe`: installs kernel/user mode components, such as `csrss.exe`
                - `crsrss.exe`: supports process/thread creation and mgmt
                - `wininit.exe`: inits temp dir, loads rest of registry, user mode scheduling, programs that require reboot to finish install, and the following things. It also undos everything on shutdown
                  - `lsm.exe`: local session mgr, handles all sessions (incl. remote desktop)
                  - `lsass.exe`: local security auth subsystem, handles user auth, security policy, access tokens
                  - `services.exe`: services control mgr, loads autostart services and uses `lsass.exe` to auth them
                - Processes in session 0 are created with `SYSTEM` permissions, which can be tricked into executing malicious commands via `services`
                  - ex. `Spooler`
              - **Session 1**:
                - session for 1st interactive user (each session will get its own `csrss.exe`)
                - session 1+ are all standard user session, including `Administrator` and everybody else. involves the full desktop experience
                - Does the following:
                  - starts session 1 (or whichever number user) `csrss.exe`
                  - starts `Winlogon.exe` which prompts `logonui.exe` (login screen)
                  - starts `userinit.exe`, creates acc token and creates custom env
                  - starts `explorer.exe` as customized graphical env
        - starts `csrss.exe`, which manages processes and threads for each user subsystem

#### 4. Windows BCDEdit
```
PS C:\Users> bcdedit /?

# before any changes are made =================================================
PS C:\Users> bcdedit

Windows Boot Manager
--------------------
identifier              {bootmgr}
device                  partition=C:
description             Windows Boot Manager
locale                  en-US
inherit                 {globalsettings}
default                 {current}
resumeobject            {2bd08882-0f8f-11e9-94b6-0002c9550dce}
displayorder            {current}
toolsdisplayorder       {memdiag}
timeout                 30

Windows Boot Loader
-------------------
identifier              {current}
device                  partition=C:
path                    \windows\system32\winload.exe
description             Windows 10
locale                  en-US
inherit                 {bootloadersettings}
recoverysequence        {91061b50-0fa8-11e9-aa6e-00155d49334a}
displaymessageoverride  Recovery
recoveryenabled         Yes
allowedinmemorysettings 0x15000075
osdevice                partition=C:
systemroot              \windows
resumeobject            {2bd08882-0f8f-11e9-94b6-0002c9550dce}
nx                      OptIn
bootmenupolicy          Standard
```
  - to make changes to either the boot loader or manager, use the identifier (`bootmgr`, `current`)
  - before making changes, first make a **BACKUP**
```
# Run this in cmd (NOT POWERSHELL)

bcdedit /export C:\Lion_BCD

bcdedit /set {current} description "Windows 7 - Lion Den"

bcdedit /create {ntldr} /d "Windows XP Pro SP2 - Tiger Paw"
bcdedit /set {ntldr} device partition=C:
bcdedit /set {ntldr} path \ntldr
bcdedit /displayorder {ntldr} /addfirst

# after changes ===============================================================
bcdedit

Windows Boot Manager
--------------------
identifier              {bootmgr}
device                  partition=C:
description             Windows Boot Manager
locale                  en-US
inherit                 {globalsettings}
default                 {current}
resumeobject            {2bd08882-0f8f-11e9-94b6-0002c9550dce}
displayorder            {ntldr}
                        {current}
toolsdisplayorder       {memdiag}
timeout                 30

Windows Legacy OS Loader
------------------------
identifier              {ntldr}
device                  partition=C:
description             Windows XP Pro SP2 - Tiger Paw

Windows Boot Loader
-------------------
identifier              {current}
device                  partition=C:
path                    \windows\system32\winload.exe
description             Windows 7 - Lion Den
locale                  en-US
inherit                 {bootloadersettings}
recoverysequence        {91061b50-0fa8-11e9-aa6e-00155d49334a}
displaymessageoverride  Recovery
recoveryenabled         Yes
allowedinmemorysettings 0x15000075
osdevice                partition=C:
systemroot              \windows
resumeobject            {2bd08882-0f8f-11e9-94b6-0002c9550dce}
nx                      OptIn
bootmenupolicy          Standard

bcdedit /delete {ntldr} /f

bcdedit /set {default} safeboot minimal
bcdedit /set {bootmgr} timeout 25

bcdedit /deletevalue {current} safeboot

bcdedit /import C:\Lion_BCD
```

-------------------
## CTF Responses

#### 7_windows_boot_process
What is the first process to spawn on Windows systems after the kernel loads?
- system

What is the Process ID (PID) of the first Windows process?
- 4

What is the second boot process to spawn, that then spawns csrss in both user space and kernel space?
- smss

What session ID do kernel space processes operate in?
- 0

What process handles credentials?
- lsass

What is the parent process to all svchosts?
 - services

What process is waiting with high priority for the Secure Attention Sequence (SAS)?
- winlogon

What user space process spawns explorer, then dies?
- userinit

What is the name of the bootloader we are using on all of the Windows machines in this environment?
- winload

Based on the boot loader from Init_9, which firmware are we using (BIOS or UEFI) in our environment?
- BIOS

What file saves the memory state to the hard drive when going into hibernation?
- hiberfil.sys

What bootloader is responsible for restoring the system to its original state after hibernation?
- winresume.exe

The system is booting into safe mode. Identify the flag from the command-line output.
- `bcdedit`
- 1RF5Zgf9P

The system is booting into safe mode. Correct that, and reboot into the desktop. The flag is on the desktop.
- `bcdedit /deletevalue {current} safeboot`
- 76Drp6hB

Prevent the system restart using the command line, and then identify persistence mechanisms that are reverting the OS and boot loader configurations. The flag is in the same folder as the persistence mechanism.
- Run -> msconfig -> Services -> Hide all Microsoft Services
- AlsKdJfhG

Run PowerShell... if you can. Resolve PowerShell dependencies. HINT: Search the entire file system for the PowerShell .dll and copy it back to where it needs to go. It is hidden in China. The flag is a file in the directory with the .dll
- run powershell, find note, look for dll
- rfVBgtYHn

Once you fix and launch PowerShell, the console is changed to a custom layout. Figure out what file is causing this, read the file, and inspect the file that it is referencing.
- look at PS profiles
- C:\Users\Yin\AppData\Local\Temp\7f7....pdf
- 8B7da4v6Y

----------
## Windows Processes and Sysinternals

### Flags
|name      |value|
|-----------|-----|
|09_windows_processes|start|
|10_windows_uac|start0864|
|11_windows_services|start4597|

## NOTES
### Windows Processes
#### 1. What is Process Validity, Why does it Matter
  - Process Validity: distinguishing good vs. bad processes
    - Malware can hide in
      - Processes
      - Files
      - Registry Keys
      - Drivers
  - Importance: OCO and DCO

#### 2. Processes, DLLs, Services
  - Process: program running on computer, such as Chrome, Notepad, spellchecker
    - Viewing all processes
      - `Get-Process`
      - `Get-Process | Sort -Property Id | more`
      - `Get-Process | Select Name, Id, Description | Sort -Property Id | more`
    - View my processes
      - `Get-Process SMSS,CSRSS,LSASS | Sort -Property Id`
    - View modules/DLLs used
      - `Get-Process chrome | foreach {$a} {$_.modules} | more`
      - `Get-Process -Name "*chrome*" | Select-Object -ExpandProperty Modules | more`
      - `Get-Process chrome | foreach {$a} {$_.modules} | Where-Object ModuleName -like '*chrome*' | more`
      - `Get-Process -Name "*chrome*" | Select-Object -ExpandProperty Modules | Where-Object ModuleName -like '*chrome*' | more`
    - View all Win32 Services
      - `Get-Ciminstance Win32_service | Select Name, Processid, Pathname | more`
    - See FG for viewing in CMD
      - `tasklist`
    - To view processes in GUI, use Task Manager or `Procexp.exe`
  - Dynamic Linked Library (DLL): Non-standalone library that is linked to by other programs
    - Can't be directly executed
  - Service: A type of process that run in the background (in their own Windows Session)
    - PowerShell
      - Viewing all services
        - `Get-Service | more`
      - Viewing system services
        - `Get-Ciminstance Win32_service | Select Name, Processid, Pathname | more`
      - View properties of a certain service
        - `Get-Service <service> | format-list *`
      - View running services
        - `Get-Service | Where-Object {$_.Status -eq "Running"}`
    - CMD
      - `sc query`: view services
      - `sc queryex type=service state=inactive`: view extended info for inactive services
      - `net start`
    - GUI
      - services.msc
      - Sysinternals
        - `net use * https://live.sysinternals.com/tools`
        - `tcpview.exe -accepteula`
        - `autoruns.exe`

#### 3. Scheduled Tasks
  - Schedule launch of programs at startup, login, or at certain time of day
  - Can be used to hide malware to execute at certain time
  - Good way to establish **persistence**
  - View in PowerShell
    - `Get-ScheduledTask | Select * | select -First 1`
  - View in CMD
    - `schtasks /query /tn "IchBinBosh" /v /fo list`
  - View in GUI
    - Task Scheduler, Autoruns
  - Autorun Registry Locations
```
# Registry Keys Locations, Locations connected with Services.
HKLM\Software\Microsoft\Windows\CurrentVerstion\Run - Local Machine
HKLM\Software\Microsoft\Windows\CurrentVerstion\RunOnce
HKLM\System\CurrentControlSet\Services

# Remember that the Users have individual Hives with autoruns as well as the Current User.
HKCU\Software\Microsoft\Windows\CurrentVerstion\Run - Current User
HKCU\Software\Microsoft\Windows\CurrentVerstion\RunOnce
HKU\<sid>\Software\Microsoft\Windows\CurrentVerstion\Run - Specific User
HKU\<sid>\Software\Microsoft\Windows\CurrentVerstion\RunOnce

# The order in which services are loaded can be adjusted.
HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\ServiceGroupOrder
HKEY_LOCAL_MACHINE\CurrentControlSet\Control\GroupOrderList
```
#### 4. Network Connections
  - Viewing network connections in PS
    - `Get-NetTCPConnection -State Established`
  - in CMD
    - `netstat /?`
    - all TCP/UDP connections with port in numerical form with PID/executable associated
      - `netstat -anob | more`
  - in GUI
    - Sysinternals

#### 5. Identifying Abnormalities/Suspcious Activity
  - Suspicious things:
    - Misspellings
    - Strange directory
      - System processes run from `C:\Windows\System32`
      - 3rd Party run from `C:\Program Files`
    - Non-standard listening ports, or ports with SYN/SENT
      - Ex. HTTP being run from any port other than 80
    - Multiple processes with same name that should be unique
      - Ex. LSASS,SMSS
      - Or system process with high PID
    - Suspicious usage of DLLs

### User Access Control (UAC)
  - Protects users from themselves (if they don't create an account other than administrator)
  - UAC overview:
    - limits privilege of user programs
    - requires explicit acknowledgement from user to elevate privileges
    - equivalent to Linux's `sudo`
    - Registry key at `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`
  - UAC Prompts
    - Red: App/Publisher blocked by group policy
    - Blue/Gold: Admin application
    - Blue: Trusted and Authenticode signed
    - Yellow: Untrusted application (regardless if signed)
  - When an app is run, UAC checks the file's manifest for instructions
    - file manifest holds metadata, tells windows how the file should be executed
    - 3 types of execution levels
      1. `asinvoker`: run with same perms as process that started it (ex. `cmd`)
      2. `requireAdministrator`: must be admin, will prompt for creds if starter is not admin
      3. `highestAvailable`: run with highest perms possible (ex. `regedit`)
    - some files can "autoelevate" which elevate perms without a UAC prompt
  - Viewing file manifest settings
    - `sigcheck` from `sysinternals`:
      - viewing autoelevate setting of `slui`
        - `/sigcheck -m C:\Windows\System32\slui.exe`
      - view all windows executables that have autoelevate in the manifest
        - `/strings –s c:\windows\system32\*.exe | findstr /i autoelevate`
### Sysinternals
#### 1. Sysinternals Intro
  - Sysinternals
    - `net use * https://live.sysinternals.com/tools`
    - `tcpview.exe -accepteula`
    - `autoruns.exe`
#### 2. Applications
  - `Procmon`
    - right click process, `jump to` to go to its location
    - From CMD:
  - `Autoruns`
  - `Procexp`
    - helpful for suspending processes in order to kill "buddy processes"
  - `TCPView`
  - `PSExec`
    - `psexec -i -s regedit` <- `-s` allows us to run `regedit` as System
    - `psexec -i -s \\file-server cmd.exe`
  - `PSLoggedOn`
    - tells you who's logged on
    - `psloggedon.exe \\file-server`
  - `LogonSessions`
    - more info about logon info
    - `logonsessions.exe -p`
  - `PSList`
    - process list on local or remote systems
  - `PSInfo`
    - gathers key info about system on local/remote systems
  - `Strings`
    - analyze windows files using strings
    - `.\strings -a C:\users\andy.dwyer\Desktop\<doc>.txt`
  - `Handle`

--------------------
### CTF Responses 

### 09_windows_process
- What Sysinternals tool shows malware persistence locations in tabs within its GUI?
  - autoruns
- What Sysinternals tool is used to investigate processes?
  - procexp
- What Sysinternals tool can be used to investigate network connection attempts?
  - tcpview
- What Sysinternals tool can view permissions?
  - accesschk
- What Sysinternals tool allows us to view and modify handles?
  - handle
- What is the default Windows user directory for files downloaded from the internet? The flag is the folder name only.
  - downloads

- What is the default Windows download directory that everyone has access to? The flag is the absolute path to the directory.
  - `C:\Users\Public\Downloads`

- What Sysinternals tool shows service load order?
  - LoadOrd

- What is the service name of Windows Defender Firewall?
  - MpsSvc

- What SysInternals tool reports .dlls loaded into processes?
  - listdlls

- There is malware on the system that is named similarly to a legitimate Windows executable. There is a .dll in the folder that the malware runs from. The flag is the name of the .dll.
    - `Get-Item HKCU:\Software\Microsoft\Windows\CurrentVersion\Run`
    - There is a file path that's "C:\Users\Public\Downloads\scvhost.exe'
    - cd to that path and ls 
    - libmingwex-0.dll

- You notice that there is an annoying pop up happening regularly. Investigate the process causing it. The flag is the name of the executable.
  - McAfeeFireTray.exe

- Determine what is sending out a SYN_SENT message. The flag is the name of the executable.
  - McAfeeFireTray.exe

- Malware uses names of legit processes to obfuscate itself. Give the flag located in Kerberos’ registry sub-key.
    - `.\autoruns.exe`
    - navigate to services
    - click Kerberos
    - parameters
    - you'll see the flag (76aGreX5)
    OR
    - `gci "registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kerberos\"`

- There is malware named TotallyLegit. Find its binary location and there will be a file in that directory. Read the file.
    - `gi "registry::HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\"`
    - `cd C:\Users\Public\Downloads\`
    - `cat .\Hmmmm.txt`
    - GwlkK3sa

- Find the McAfeeFireTray.exe. There is a file in that directory. The flag is inside.
    - search autoruns.exe for McaFeeFireTray.exe
    - find it's directory
    - `gci "C:\Program Files\Windows Defender Advanced Threat Protection"`
    - cd there
    - cat the file 
    - StrongBad

- What are the permissions for NT SERVICE\TrustedInstaller on spoolsv.exe? Copy the permissions from your shell.
    - `gci "C:\windows\System32\" -Filter *.exe -recurse | % {$_.spoolsv}`
    - `Z:.\accesschk.exe -accepteula`
    - `Z:.\accesschk "C:\Windows\System32\spoolsv.exe"`
    - RW NT SERVICE\TrustedInstaller

- What is the PATH listed in the output when we find the handle for spoolsv.exe?
    - `Z:.\Pslist -accepteula`
    - PID of spoolsv = 2236
    - ` z:.\handle.exe -p 2236`
    - C:\Windows\System32\en-US\spoolsv.exe.mui

- In what Load Order Group is the Windows Firewall service?
    - .\LoadOrd.exe, look for the mpssvc service
    - NetworkProvider

- What is the first .dll associated with winlogon.exe? (Provide the name of the .dll only, not the /absolute/path)
  - .\ListDlls.exe winlogon.exe
  - ntdll.dll

- While examining the Windows Defender Firewall, what is the LogAllowedConnections setting set to, for the Public profile?
  - Get-NetFirewallProfile
  - False

- A nonstandard port has been opened by possible malware on the system. Identify the port. (You will not find the connection so find what started it)
  - 6666

- Determine what mechanism opened the port from hidden_processes_7. The flag is the name of the file.
  - recursively search for *legit* from root
  - legit_script.ps1

- Identify the flag from the file in hidden_processes_8.
  - N0t_L3g1T_Ammiright

### 10_windows_UAC
- What Sysinternals tool will allow you to view a file's manifest?
  - sigcheck

- What is the RequestedExecutionLevel for an application to run with the same permissions as the process that started it?
  - asinvoker

- What RequestedExecutionLevel will prompt the user for Administrator credentials if they're not a member of the Administrator's group?
  - requireAdministrator

- What registry key holds UAC values?
  - `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`

- The flag is the RequestedExecutionLevel of the schtasks.exe file.
  - `.\sigcheck.exe -m C:\Windows\System32\schtasks.exe -accepteula`
  - asinvoker

- Determine which UAC sub-key property shows whether UAC is enabled or not. The flag is the data value in that property.
  - `Get-Item HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`
  - 4919

- Provide the name of the UAC [Registry key] property that determines what level UAC is set to (Example UAC levels: Default, Always, Notify).
  - ConsentPromptBehaviorAdmin

- Query the registry key where UAC settings are stored, and provide the flag.
  - NiceJob

### 11_windows_services
- What command-line (cmd) command will show service information?
  - `sc`

- What command-line (cmd) command will show all services, running or not running?
  - `sc queryex type=service state=all`

- What PowerShell command will list all services?
  - `Get-Service`

- What registry location holds all service data?
  - `HKLM\System\CurrentControlSet\Services`

- What registry sub-key holds a service's .dll location?
  - parameters

- Services have a name and display name, which could be different. What is the service name of the only Totally-Legit service?
  - `Get-Service`
  - Legit

- Figure out the SID of the only Totally-Legit service
  - `sc showsid legit`
  - S-1-5-80-159957745-2084983471-2137709666-960844832-**1182961511**

---------

## Windows Artifacts and Logging 
### Flags
|name      |value|
|-----------|-----|
|13_windows_artifacts|start3567|

## NOTES
### Windows Artifacts/Auditing and Logging
#### 1. Windows Artifacts
  - SID -> username
```
get-wmiobject win32_useraccount | select name,sid
get-localuser | select Name,SID
wmic useraccount get name,sid
```
  - artifacts are objects that contain info relevant to activities performed on the system
  - many artifacts require use of SID to dig into user-specific registry location for artifact info
#### 2. UserAssist
  - annotate when an executable is run, and who is running it
  - 2 ways to run an exe: the shortcut, and the main executable (desktop chrome vs. chrome.exe)

```
# CEBFF5CD: Executable File Execution
Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count"

# F4E57C4B: Shortcut File Execution
Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{F4E57C4B-2036-45F0-A9AB-443BCFE33D9F}\Count"
```

  - That input is encoded with ROT13
  - In order to look at **all** users' User Assist Artifacts:

```
Get-ItemProperty "Registry::Hkey_Users\*\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count"
```

#### 3. Windows Background Activity Moderator (BAM)
  - Keeps track of stuff happening in background
  - Provides full path of executable and last execution time
  - Requires knowing the Windows version (run `winver`)
    - Admin Station `winver` is Version 1809 (Sep 2018)
  - To show BAM in registry:
    - 1809+: `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings`
    - 1809-: `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\bam\UserSettings`
```
# Every User on the System
Get-Item HKLM:\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\*
# Single User on the System
Get-Item HKLM:\SYSTEM\CurrentControlSet\Services\bam\state\UserSettings\S-1-5-21-3385255940-4185786428-2400321831-1005
```

#### 4. Recycle Bin
  - data is recoverable, content is identifiable by SID, timestop, content, OG path/name
  - located at `C:\$Recycle.bin`
```
# Find the Contents of the Recycle Bin
Get-Childitem 'C:\$RECYCLE.BIN' -Recurse -Verbose -Force | select FullName
```

  - the output files are prepended by **I** and **R**
    - **I** files are the file locations
    - **R** files are the actual file contents

```
# Find who the SIDS belong to
wmic useraccount where 'sid="S-1-5-21-1584283910-3275287195-1754958050-1005"' get name
# Get content of a particular file
Get-Content 'C:\$Recycle.Bin\S-1-5-21-1584283910-3275287195-1754958050-1005\$R8QZ1U8.txt'
```

#### 5. Prefetch
  - Prefetch files are created by the Windows OS when an app is run from a specific location for the first time
  - used to speed up the app startup process
  - prefetch file name have the application name, hashed location, `.pf` file extension
    - prefetch files are located at `C:\Windows\Prefetch`
  - `Get-Childitem -Path 'C:\Windows\Prefetch' -ErrorAction Continue | select -First 50`

#### 6. Jump Lists
  - Windows 7-10 taskbar stores frequently accessed items
  - Data about these items include:
    - first execution time
    - creation time
    - last time of execution
    - modification time
  - reg location of jump lists: `C:\%USERPROFILE%\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations`
```
Get-Childitem -Recurse C:\Users\*\AppData\Roaming\Microsoft\Windows\Recent -ErrorAction silentlyContinue | select FullName, LastAccessTime
Get-Childitem -Recurse C:\Users\andy.dwyer\AppData\Roaming\Microsoft\Windows\Recent -ErrorAction SilentlyContinue | select FullName, CreationTime |ft -wrap
Get-Childitem -Recurse C:\Users\andy.dwyer\AppData\Roaming\Microsoft\Windows\Recent -ErrorAction SilentlyContinue | select FullName, LastAccessTime |ft -wrap
#or
Get-Childitem -Recurse $env:USERPROFILE\AppData\Roaming\Microsoft\Windows\Recent -ErrorAction SilentlyContinue | select FullName,LastAccessTime | ft -wrap
```

#### 7. Recent Files
  - Last 150 files/folders opened
  - entry/modification time of this key = time/loc of last file of a specific extension was opened
```
Get-childItem 'Registry::\HKEY_USERS\*\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs\.txt'
Get-childItem 'Registry::\HKEY_USERS\*\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs\.*'
#Converting a Single Value from Hex to Unicode
[System.Text.Encoding]::Unicode.GetString((gp "REGISTRY::HKEY_USERS\*\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs\.txt")."1")
Get-Item "REGISTRY::HKEY_USERS\*\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs\*.txt" | select -Expand property | ForEach-Object {
    [System.Text.Encoding]::Default.GetString((Get-ItemProperty -Path "REGISTRY::HKEY_USERS\*\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs\*.txt" -Name $_).$_)
}
```

#### 8. Browser Artifacts
  - view browser history
    - `%USERPROFILE%\AppData\Local\Google\Chrome\User Data\Default\history`
```
# Frequency
strings.exe 'C:\users\andy.dwyer\AppData\Local\Google\Chrome\User Data\Default\History' -accepteula
strings.exe 'C:\users\andy.dwyer\AppData\Local\Google\Chrome\User Data\Default\History' | findstr -i "www.espn.com*"

# Most Visited
strings.exe 'C:\users\andy.dwyer\AppData\Local\Google\Chrome\User Data\Default\Top Sites'

# User Names
strings.exe  'C:\users\andy.dwyer\AppData\Local\Google\Chrome\User Data\Default\Login Data'
strings.exe  'C:\users\andy.dwyer\AppData\Local\Google\Chrome\User Data\Default\Login Data' | findstr -i "https*"

#Find FQDNs in Sqlite Text files
$History = (Get-Content 'C:\users\andy.dwyer\AppData\Local\Google\Chrome\User Data\Default\History') -replace "[^a-zA-Z0-9\.\:\/]",""
$History | Select-String -Pattern "(https|http):\/\/[a-zA-Z_0-9]+\.\w+[\.]?\w+[\.]?\w+" -AllMatches|foreach {$_.Matches.Groups[0].Value}| ft
```

#### 9. Auditing
  - important to audit systems to analyze artifacts using cmd, powershell, or EventViewer
  - view fg for instructions to enable logging/auditing
#### 10. Event Logs

#### 11. PowerShell Artifacts

---------
## CTF Responses

### 13_windows_artficats

- What Sysinternals tool will allow you to read the SQLite3 database containing the web history of chrome?
  - strings

- What is the registry location of recent docs?
  - HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs

- BAM settings are stored in different registry locations based on the version of Windows 10. What version of Windows 10 is workstation2 running? The answer is the 4 digit release number
  - (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name ReleaseId).ReleaseId
  - 1803

- Figure out the last access time of the hosts file.
  - 10/28/2021

- What is the literal path of the prefetch directory?
  - `C:\Windows\Prefetch`

- In the Recycle Bin, there is a file that contains the actual contents of the recycled file. What are the first two characters of this filename?
  - $R

- In the Recycle Bin, there is a file that contains the original filename, path, file size, and when the file was deleted. What are the first two characters of this filename?
  - $I

- What are the first 8 characters of the Globally Unique Identifier (GUID) used to list applications found in the UserAssist registry key (Windows 7 and later)?
  - CEBFF5CD

- What cipher method are UserAssist files encoded in?
  - ROT13

- What main Windows log would show invalid login attempts?
  - security

- What main Windows log will show whether Windows updates were applied recently?
  - system

- When reading logs, you may notice ... at the end of the line where the message is truncated. What format-table switch/argument will display the entire output?
  - `-wrap`

- Find the questionable website that the user browsed to (using Chrome), that appears to be malicious.
  - `.\strings.exe 'C:\users\student\AppData\Local\Google\Chrome\User Data\Default\History' -accepteula`
  - https://www.exploit-db.com/

- There is a file that was recently opened that may contain PII. Get the flag from the contents of the file.
  - `Get-Item "REGISTRY::HKEY_USERS\*\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs\.txt" | select -Expand property | ForEach-Object {
    [System.Text.Encoding]::Default.GetString((Get-ItemProperty -Path "REGISTRY::HKEY_USERS\*\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs\.txt" -Name $_).$_)}`
  - Flag, Found A.

- Enter the full path of the program that was run on this computer from an abnormal location.
  - `Get-Item 'HKLM:\SYSTEM\CurrentControlSet\Services\bam\UserSettings\S-1-5-21-859305355-4188213059-989812370-1003'`
  - `\Device\HarddiskVolume1\Windows\Temp\bad_intentions.exe`

- Enter the name of the questionable file in the prefetch folder.
  - BAD_INTENTIONS.EXE-8F2806FC.pf

- What is the creation time of the questionable file in the prefetch folder?
  - 10/28/2021

- Recover the flag from the Recycle Bin. Enter the name of the recycle bin file that contained the contents of the flag, and the contents of the deleted file.
  - cd'd into the recycle bin
  - `cat '$R*'`
  - $R9FCDPW.txt,DontTrashMeyo

- Find the file in the jump list that might allow privilege escalation.
  - `Get-Childitem -Recurse C:\Users\*\AppData\Roaming\Microsoft\Windows\Recent -ErrorAction Continue | % {.\strings.exe -accepteula $_}`
  - UIDPWD.txt
  
- Check event logs for a flag string.
  - `get-eventlog -logname system | ft -wrap > test.txt`
  - `Select-String -path test.txt -pattern "flag"`
  - `Get-Content test.txt | select -index 2193`
  - 3v3nt_L0g
