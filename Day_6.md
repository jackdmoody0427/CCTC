### *CCTC OS NOTES DAY 6*

| Challenge Name | Flag |
| -- | -- | 
| windows_process| start |
| windows_uac | start0864 |
| windows_services | start4597

zqDX0eqt$ilbFYAHES9wKFHaNNApMmzEQTQsxaRvkCFHb01fxMNoJZePnfwiCwhpA/2KZ4LB3RdEyiGnDMIsZTehKIsA860

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
# 
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