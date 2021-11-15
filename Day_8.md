### *CCTC OS NOTES DAY 7*

| Challenge Name | Flag |
| -- | -- | 
|windows_artifacts | start3567  |

Aragorn,BruceWayne,Eowyn,Tolkien

```
#powershell
get-wmiobject win32_useraccount | select name,sid
get-localUser | select Name.SID
#Command Prompt
wmic useraccount get name,sid
```
`net use * https://live.sysinternals.com/tools` 

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


## CTFs
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