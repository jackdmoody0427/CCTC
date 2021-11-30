## CCTC Networking Day 4

- agenda


## Admin Data 

### CTFd info
| Field | Value | 
|-|-|
| Flag |  | 
| Name |  | 

## Day 4: Recon

**Critical to OCO and DCO**

### Types of Reconnaissance
- Active
- Passive
  - Definition: 
    - Gathering information about targets without direct interaction
    - Not as straight forward and requires more time than active reconnaissance
    - Lower risk of discovery
  - Involved Identiftying:
    - IP addresses and sub-domains
    - Exernal and 3d party sites
    - People and tech
    - content of interest
    - Vulnerabilities
  - Possible tools for gathering:
    - WHOIS queries
    - Job site listings
    - Phone Numbers
    - Google searches
    - Passive OS fingerprinting
- Internal 
- External 

### Passive External Network Reconnaissance
- Information gathered outside of the networkk using passive methods
- Allows for more efficient attacks and plans
- **Tools**:
  - DNS
    - Resolves Hostnames to IP addresses
    - RFC 3912
    - WHOIS queries
  - DIG
    - Typically between primary and secondary DNS servers
    - If allowed to transfer externally hostnames, IPs, and IP blocks can be determined 
  - Zone Transfers
    - Returns DNS information 
    - Supplements base queries
  - Host History
    - Netcraft
    - Wayback Machine
  - Google Searches
    - Subdomains
    - Technologies
  - Shodan
    - Reveals information about technologies, remote access services, improperly configured services, and network infrastructure
    - When selected can give additional information and applicable vulnerabilities 

### Network Scanning
- Scanning Strategy
  - Remote to local
  - Local to remote
  - Local to local
  - Remote to remote 
- Scanning Approach
  - Aim
    - Wide range target scan
    - Target specific scan
  - Method
    - Single source scan
    - Distributed scan

#### Types of Scans
- Broadcast Ping and Ping sweep
- ARP scan
- SYN scan
- Full connect scan
- Null scan
- FIN scan
- XMAS tree scan
- UDP scan
- Idle scan
- ACK/Window scan
- RPC scan
- FTP scan
- decoy scan
- OS fingerprinting scan
- version scan
- Protocol ping
- Discovery probes
- SCTP INIT scan

#### Network scanning code
```
nmap [Options] [Target IP/ Subnet]
nc [Options] [Target IP] [Target Port]
```
***
Examples
- whoami
```
whois harpoonbrewery.com
dig @8.8.8.8 harpoonbrewery.com SOA
netstat -antp | grep -i listen        #looks for listening ports
nc localhost 80
uname -a                              #list OS
```
### How to build your network map
Host enumeration needs:
  - hostname
  - username/ passowrd
  - ip address and subnet
  - mac address
  - OS w/ version
  - open ports w/ service and version
  - any files of interest (local and share) [optional]
  - any process of interest [optional]

How do we see those things on a new device:
| Field | Command | 
|-|-|
| Hostname | `cat /etc/hostname` | 
| Usrname, pass | should already have. It'll be usrname password |
| Ip address & mac addr | `ip addr `|
| OS | `uname -a` |
| Open ports | tcp ports:  `netstat -antp \| grep -i listen` or `nc localhost 23` or `telnet localhost 23`|


**Scan.sh**
```
#!/bin/bash

echo "Enter network address (e.g. 192.168.0): "

read net

echo "Enter starting host range (e.g. 1): "

read start

echo "Enter ending host range (e.g. 254): "

read end

echo "Enter ports space-delimited (e.g. 21-23 80): "

read ports

for ((i=$start; $i<=$end; i++))

do

    nc -nvzw1 $net.$i $ports 2>&1 | grep -E 'succ|open'

done

# (-v) running verbosely (-v on Linux, -vv on Windows),

# (-n) not resolving names. numeric only IP(no D.S)

# (-z) without sending any data. zero-I/O mode(used for scanning)

#(-w1) waiting no more than 1second for a connection to occur

# (2>&1) redirect STDERR to STDOUT. Results of scan are errors and need to redirect to output to grep

# (-E) Interpret PATTERN as an extended regular expression

# ( | grep open) for Debian to display only open connections

# ( | grep succeeded) for Ubuntu to display only the open connections
```
### Now let's try it out!
1. Run your scan script
```
student@internet-host-student-11:~/socket.d$ ./scan.sh
Enter  network address (e.g. 192.168.0): 
172.16.120
Enter starting host range (e.g. 1): 
1
Enter ending rost range (e.g 254): 
1
Enter ports spcae delimited (e.g 21-23 80): 
21-23 80
(UNKNOWN) [172.16.120.1] 22 (ssh) open
```
2. Get into that open port (it's vyos)
- `ssh vyos@172.16.120.1`
3. See whats going on
- `ip a`
4. try again
- `show int`

***
RED-SCR

vyos/ password
3.13.11-1-amd64-vyos

| Field | Command | 
|-|-|
|172.16.120.1 /30 | internet
| 172.16.120.6 /30 | rednet
| 172.16.101.0 /27 | DMZ |


***
CTF Challenges
-----------------------------------

1. Donovian Boundary: 
what's the hostname of their boundary router?
- RED-SCR

2. DMZ Discorvery: How many hosts did you discover on the DMZ net (excluding the router)?
- `show int`
- shows the DMZ description
- use the IP address 172.16.101.30/27  and use the useable ips (1-29) on your scan script to find open ports
- 1 usable host `172.16.101.2` has port 22 open

3. DMZ Ip Address: What is the ip address of the host devices in the DMZ network
- 172.16.101.2
4. DMZ Well Known Ports: How many well-known open TCP ports did you discover on the devices
- 1 
5. Port number?
- 22
6. DMZ Hostname: Whats the hostname of the system?
- ssh 172.16.101.2 --> red-dmz-host-1
7. Donovian man in the Middle
- red-ips
8. Donovian Inner Boundary: What is the hostname of the device directly connected to teh system discovered in Donovian Man in the Middle, on eth1?
- show int and loook at ip address for eth1 
- look up subnet mask
- realize the only other available address is a .9 because its a /30
- `ssh vyos@172.16.120.9`
- RED-POP

9. HOSTS Discovery: How many host(s) did you discover on the HOSTS Net? (Excluding the router)
-  `show int` on 172.16.120.9
- eth1 has ip address 172.16.182.126/27 
- run ./scan.sh and enter:
  -172.16.182, 97,125, 21-23 80 (remember to use subnet calculator)
- 4 unique hosts found (look at ip's some may have multiple ports open)

10. Hosts discovery IP: What are the host IP Address(s) on the HOSTS network?
- 106,110,114,118 (from the ./scan.sh)

11. HOSTS Discovery T2 Ports: What ports are open?
- 22,80
12. HOSTS Discovery T2 Recon: Interface with the web service on the 172.16.182.110 host. The hint provides a suggestion on the ports above the well-known that you will need to recon. What is the range?
- nc 172.16.182.110
- GET
- wget then move file, open with gimp 
- 1980-1989

13. Hosts Discover t2 ports 2: What UDP ports did you find that were open? (List them in in order and separate the ports with a comma and no space.) NOTE: Look in the same port range mentioned in your hint for this target.
```
student@internet-host-student-11:~/socket.d$ ./scan_UDP.sh 
Enter  network address (e.g. 192.168.0): 
172.16.182
Enter starting host range (e.g. 1): 
110 
Enter ending rost range (e.g 254): 
110
Enter ports spcae delimited (e.g 21-23 80): 
1980-1989
(UNKNOWN) [172.16.182.110] 1989 (?) open
(UNKNOWN) [172.16.182.110] 1984 (?) open
```
14. what insturment is being played on port 1984?
- `nc 172.16.182.110 1984 -u`
- saxophone_8eb7c126deb7b515e3a65cafae26e21c

15. what color socks is the person wearig on port 1989
- `nc 172.16.182.110 1989 -u`
- blue_daa5960a123ff55e594be19f9ddc940d 

16. What TCP ports in the range did you find that were open? (List them in order and separate the ports with a comma and no space)
```
student@internet-host-student-11:~/socket.d$ ./scan.sh
Enter  network address (e.g. 192.168.0): 
172.16.182
Enter starting host range (e.g. 1): 
110
Enter ending rost range (e.g 254): 
110
Enter ports spcae delimited (e.g 21-23 80): 
1980-1989
(UNKNOWN) [172.16.182.110] 1989 (?) open
(UNKNOWN) [172.16.182.110] 1988 (?) open
(UNKNOWN) [172.16.182.110] 1982 (?) open
(UNKNOWN) [172.16.182.110] 1980 (?) open
```
17. license plate on port 1980
- `nc 172.16.182.110 1980`
- 5JB-738_091ab8f5f708d13ebba6b6cb10943b8f

18. 
- africa_fd4418ccc8adfc6319a0136110f5a515

19. 1000_905f2bb7e8852fb96cb9aeff9568a839
20. elvis_fcf80c31c18deae15e950a526ae6481e
21. what well known ports on are T4? Look at mission set 
```
student@internet-host-student-11:~/socket.d$ ./scan.sh
Enter  network address (e.g. 192.168.0): 
172.16.182
Enter starting host range (e.g. 1): 
106
Enter ending rost range (e.g 254): 
106
Enter ports spcae delimited (e.g 21-23 80): 
21-23 80
(UNKNOWN) [172.16.182.106] 22 (ssh) open
```http://www.youtube.com/watch?v=EF8GhC-T_Mo&t=0m39ssystem?
- `ssh 172.16.182.106` 
- red-host-1
```
23. open ports on t5
```
student@internet-host-student-11:~/socket.d$ ./scan.sh
Enter  network address (e.g. 192.168.0): 
172.16.182
Enter starting host range (e.g. 1): 
114
Enter ending rost range (e.g 254): 
114
Enter ports spcae delimited (e.g 21-23 80): 
21-23 80
(UNKNOWN) [172.16.182.114] 22 (ssh) open
```
24. Host discovery T5 hostname
- red-host-3

25. 
- 22
26. 
- red-host-4
27. 
- `ssh vyos@127.16.140.5`
- red-pop2

28. 

```
student@internet-host-student-11:~/socket.d$ ./scan.sh 
Enter  network address (e.g. 192.168.0): 
172.16.140
Enter starting host range (e.g. 1): 
33
Enter ending rost range (e.g 254): 
61
Enter ports spcae delimited (e.g 21-23 80): 
21-23 80
(UNKNOWN) [172.16.140.33] 22 (ssh) open
(UNKNOWN) [172.16.140.33] 80 (http) open
(UNKNOWN) [172.16.140.35] 22 (ssh) open
```

29. 
- 22,80
30. 
- 1999-2999

32. 

```
student@internet-host-student-11:~/socket.d$ sudo nmap -sUF -p 1999-2999 --min-rate 5000 172.16.140.33 
[sudo] password for student: 

Starting Nmap 7.40 ( https://nmap.org ) at 2021-11-30 21:10 UTC
Nmap scan report for 172.16.140.33
Host is up (0.0026s latency).
Not shown: 1004 closed ports, 993 open|filtered ports
PORT     STATE SERVICE
2000/udp open  cisco-sccp
2011/udp open  servserv
2200/udp open  ici
2250/udp open  remote-collab
2999/udp open  remoteware-un

Nmap done: 1 IP address (1 host up) scanned in 1.71 seconds
```

33. 
- wednesday
34. 
- `nc 172.16.140.33 2800`
- profanity

35. 
- target
36. 
- look at this
37. 
- fresh avocado
38. 
- 2
39. 
- graph
40. 
- chickens
41. 
- 22
42. 
- red-int-dmz2-host-2
------------------------------
## Start of tunneling
- SCP (what to where)
  - `scp student@10.50.27.21:/home/student/demo/message.txt .`
- netact
  - `nc -lp 4444 < lastname.txt `
  - `nc localhost 4444`
- client client relay 
  - bob `nc -lp 4444 < las.txt`
  - tom `nc -lp 5555 < ls.txt`
  - jerry `mknod mypipe p `
  - jerry `nc localhost 4444 0<mypipe | nc localhost  55555 1>mypipe`
  - frank `ls` he can see the file 

### Good hint, > overwrites a file, >> appends to a file 
- 