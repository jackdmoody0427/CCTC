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
Host enumeration:
  - hostname
  - username/ passowrd
  - ip address and subnet
  - mac address
  - OS w/ version
  - open ports w/ service and version
  - any files of interest (local and share) [optional]
  - any process of interest [optional]

You're on a brand new device, how do i see the hostname?
- `cat /etc/hostname`
- On a bash shell, its usually after the @ symbol

Username and password:
- student, password (or if router, bios, password)

IP address, mac address:
- `ip addr`

OS:
-`uname -a`

open ports:
- tcp ports: `netstat -antp |grep -i listen`
- `nc loclahost 23`
- `telnet localhost 23`

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

***
CTF Challenges
-----------------------------------

