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
CTF Challenges
--------------------
