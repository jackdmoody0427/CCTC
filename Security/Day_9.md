## CCTC Security Day 9
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

***
[linpeas](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS)
[gtfobins](https://gtfobins.github.io/)- list of binaries, that gives functions to get more things out of the binary than intended
### Linux Privilege Escalation, Persistence, and Covering Tracks

- Enumeration for privilege escalation

    - What are your techniques and processes?
        - Any particular order?
        - Anything else you should be doing while on the box?


### On linux op station

sudo 

`sudo cat /etc/sudoers`

`sudo -l`

cat multiple files --> `cat /etc/hosts* /etc/shadow` (the wildcard [*] can read spaces)

SUID/SGID (stands for Set owner User ID)

list suid binaries

- `find / -type f -perm /4000 -ls 2>/dev/null` - pulls up suid stuff 

make find a suid binary

    - `which find  --> chmod u+s /usr/bin/find`

list SGID libraries

- `find / -type f -perm /2000 -ls 2>/dev/null` - look for if nay of these things are in gtfobins, then possibly look for other binaries 

Cron (scheudled tasks runing on the system)

cat /etc/crontab (look for cronjob that you could potentially change)

revshell.com 

var last log ascii files, cat auth.log /var/log directory 
`  cat /etc/rsyslog.d/50-default.conf `

[the art of web rsyslog] (https://www.the-art-of-web.com/system/rsyslog-config/_)
***
***
## Dan Notes
- enumeration for privilege escalation
  - `/etc/sudoers`
  - `sudo -l` to see what my user can do
- https://gtfobins.github.io/
  - ex. search find, select sudo, copy command
  - `sudo find . -exec /bin/sh \; -quit` gets you root shell
- list suid (set user id) binaries
  - `find / -type f -perm /4000 -ls 2> /dev/null`
- make find a suid binary
  - `chmod u+s /usr/bin/find`
- list sgid (set group id) binaries
  - `find / -type f -perm /2000 -ls 2> /dev/null`
- netstat_natpu stuff
  - `strings /bin/netstat_natpu | grep netstat`
  - note that this binary calls `netstat -antpu`
    - does not use the full binary path, which is a vulnerability
    - to exploit: add `.` to `$PATH`, make my own `netstat` binary
- world writable dirs
  - `find / -type d -perm /2 -ls 2> /dev/null`
- cron
  - `cat /etc/crontab`
- reverse shell, using gtfobins, https://www.revshells.com/
  - add to a script that's being run by cron
  - on another computer, listen for that connection, and then you're able to get root shell


***
rsyslog --> enumerate --> escalate --> cron last --> 2nd box root access 
***
### CTF Flags
Password craker, list, and something to crack against it 

john --wordlist=10mil.txt shadow.txt
john --show shadow.txt 

Donovian Linux Privilege Escalation, and Persistence (DLP)
XX Feb 2027
Start Time: 1300
Duration: 4 hours

Type of Operation: Cyberspace Exploitation (C-E)

Objective: Maneuver into the Donovian internal network, gain privileged access to discovered Linux hosts.

Tools/Techniques: SSH masquerade into internal network with provided credentials. Ports in use will be dependent on target location and are subject to change. Linux techniques to gain privileged access and persist are limited to host misconfigurations, open suid/sgid, weak permissions, and path. Network scanning tools/technique usage is at the discretion of student.

Scenario Credentials: FLAG = H@RDl1nux5t@rt0F@ct1v1ty

Prior Approvals: Privilege escalation, persistence, and restarting of services through host reboot. Host survey and log sanitation utilizing native command shells, which shell is at discretion of student. NOT authorized is uploading of tools or altering account information.

Scheme of Maneuver:
>internet_grey_host
->Pivot:192.168.28.105
--->T1: 192.168.28.27
--->T2: 192.168.28.12

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
Hostname: unknown
IP: 192.168.28.27
OS: Linux ver: Unknown
Creds: comrade :: StudentPrivPassword
Last Known Ports: unknown
PSP: unknown
Malware: unknown
Action: Test supplied credentials, if possible gain access to host. Conduct host survey and gain privileged access.

T2
Hostname: unknown
IP: 192.168.28.12
OS: Linux ver: Unknown
Creds: comrade :: StudentPrivPassword
Last Known Ports: unknown
PSP: unknown
Malware: unknown
Action: Test supplied credentials, if possible gain access to host. Conduct host survey and gain privileged access.

***

1. Rsyslog 1

Using the contents of the "rsyslog2.conf" file as an example:

Which rule will send a message to any logged in user?

To answer challenge successfully provide the facility.priority of the rule.

Example: mail.debug

*.emerg

2. 

T

3. 
local7.alert 

4. 
5. 
Y

6. 
192.0.2.1 193.0.12.1 193.0.42.1

7. 

TCP

8. 
auth, authpriv, cron, ftp, kern, lpr

9. Priv 1  - Escalate 

A command this user is able to sudo can be abused to obtain access as another user. This may take some research and effort to obtain root access with it.

It is possible that your initial user does not have sudo privileges and that you will need to move laterally to another account.

The flag can be found under the root profile directory

hint: 192.68.x.127

hint: You may want to Enumerate 1 first

10. Log Sanitization 1

A member of your team has accessed a Linux system within the 192.168.0.0/16 network as a regular user under the name billybob of that system and has left residual information of their activity on the system. Although the user name is a regular user of the system, the IPv4 address from where you are authenticating is not a typical IPv4 address used to authenticate to the system.

In order to prevent discovery of your teams actions on the system you must manipulate the authentication log.

There are log entries from the network your team pivoted from, however during a data transfer the OP notes where lost. The team is sure that the pivots occurred from the 172 net.
In order to receive credit for this challenge you must provide the md5sum of the auth.log after it has been cleaned.

There are log entries from the network you pivoted from.
The user name is 'billybob'
You don’t know the exact IP address but you know the network is a 172.16.0.0/16
It has been decided that the first authentication event will be deleted, and the second authentication event will be modified to make it look as though the user came from the IPv4 address 192.168.1.103.

In order to receive credit for this challenge you must provide the md5sum of the auth.log after it has been cleaned.
