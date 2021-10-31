## *CCTC OS NOTES DAY 1*

### Problem Questions:
windows_powershell              : start2347
windows_powershell_profiles     : start85678
5: google
10: dig
15: hard
Need at least a 70 over all CCTC (OS, network, security) to pass 
#### General get started help:
- Markdown guide: https://www.markdownguide.org/getting-started/
- Add to Bashrc; unset TMOUT (gets terminal to not close out after 10 min)
- Type in hostname in the shell to make sure you're in the right box as the right person
### Links and Account Info
| | | 
|-|-|
| **Antora (main site)** | https://os.cybbh.io/public/os/latest/index.html |
| **CTFD** | http://10.50.24.186:8000/ |
| *Username* | JAMO-005-B |
| Pass | dog |
| IP Address| 10.50.32.218 |
| Stack ID | 10|
| **GitLab** | https://git.cybbh.space/users/sign_in |
| *Username* | jack.d.moody93 | 
| **VTA** | https://vta.cybbh.space/ | 
| **VPN Instructions** | https://cctc.cybbh.io/students/students/latest/openvpn-guide.html | 

## 1. Basic Powershell Concepts

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

#### 4-6
**Please read on your own time**
Not what we do in CCTC, but important for SA (Situational Awareness) when out in the CY world 