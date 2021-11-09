## *CCTC OS NOTES DAY 2*

| Challenge Name | Flag |
| -- | -- | 
| windows_registry | start357 |
|windows_file_system | start3486 | 
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

```
#Powershell
Get-wmiobject win32_useraccount | select name,sid
Get-LocalUser | select Name, SID

#command prompt
wmic useraccount get name, sid 
```