## CCTC Networking Day 7 (Network Traffic Filtering)

- agenda


## Admin Data 

### CTFd info
| Field | Value | 
|-|-|
| Flag | i_am_filtering_your_noise | 
| IP/NFTables | T@bl3sth@tF1lt3r | 

## Day 7: Network Traffic Filtering

### **Filtering Devices & Mechanisms**

- What are some practical applications of filtering? 
    - For example, we can filter website access on a network via a web proxy server to ensure only approved websites and content are allowed in and out of a network.

- Practical Applications for Filtering
    - Email addresses - to block unwanted email and increase productivity

    - Computer applications in an organization environment - for security from vulnerable software

   - MAC filtering - also for security to allow only specific computers access to a network

    - Network Traffic

- Why does network traffic get filtered? 
    - Decrease load on network infrastructure

    - Ensure data flows in an efficient manner

    - Ensure data gets to intended recipients and only intended recipients

    - Block malicious traffic

    - Obfuscate network internals

### **What devices are used to filter traffic?**

- **We filter at layers 7, 3, and 2**

- *Filtering devices, mechanisms, & layers table*

| Devices| Filtering mechanism | Operates at OSI Layer |  
|-|-| - |
| Switch | PACL & VACL, ACL  | Layer 2, 3 |
| Router| ACL | Layer 3 & 4|
| Proxies | Content based such as: URL&DNS blacklists, MIME Filtering, Content keyword filtering | Layers 3-7 |
|IDPS (Intrusion detection and prevention sytems) | Signatures | Layers 3-7 |
|Host Based Firewall | Rules | Layers 3-7|
| Network Firewal | Rules, Packet filtering (stateless), stateful (connection based), application level FW, Next gen FW | Layers 3&4, 3&4, 3-7, 3-7 respectively  |

### **Filtering Concepts**
- Whitelist vs Blacklist
- Default policies and implicit and explicit rules
- Network device operation modes
    - routed
    - transparent 
- Intrusion Defense
    - Intrusion Detection Systems
    - Intrusion Prevention Systems
- FIltering Device Placement
- Firewall Filtering Methods
    - Stateless (Packet) filter (L3+4)
    - Stateful Inspection (L4)
    - Application Layer (L7) 
********************
        **THIS IS CRITICAL TO UNDERSTAND**
- Traffic Directions
    - Traffic originating from the localhost to the remote-host
    - Return traffic from that remote-host back to the localhost
    - Traffic originating from the remote-host to the localhost
    - Return traffic from the localhost back to the remote-host 
***************************************

### **Host Based Filtering**
- Netfilter framework is made to provide:
    - packet filtering
    - stateless/stateful firewalls
    - network address and port translation (NAT and PAT)
    - Other packet manipulation

- Netfilter hooks
    - NF_IP_PRE_ROUTING → PREROUTING
    - NF_IP_LOCAL_IN → INPUT
    - NF_IP_FORWARD → FORWARD
    - NF_IP_LOCAL_OUT → OUTPUT
    - NF_IP_POST_ROUTING → POSTROUTING

- Netfilter Paradigm
    1. tables- contain chains
    2. chains- contain rules
    3. rules - dictate what to match and what actions to perform on packets when packets match a rule 

### **Configuring IP Tables**
- Seperate applications
    - Netfilter created several (separate) applications to filter on different layer 2 or layer 3+ protocols.

       - iptables - IPv4 packet administration
       - ip6tables - IPv6 packet administration
       - ebtables - Ethernet Bridge frame table administration
       - arptables - arp packet administration

- Each application had several tables and chains: 
    - filter - default table. Provides packet filtering.

        INPUT, FORWARD, and OUTPUT

    - nat - used to translate private ←→ public address and ports.

        PREROUTING, POSTROUTING, and OUTPUT

    - mangle - provides special packet alteration. Can modify various fields header fields.

        All Chains: PREROUTING, POSTROUTING, INPUT, FORWARD and OUTPUT.

    - raw - used to configure exemptions from connection tracking.

        PREROUTING and OUTPUT

    - security - used for Mandatory Access Control (MAC) networking rules.

***Be sure to google IP Tables Flow Diagram, Common IP Table Options***

- IP Table Syntax
```
iptables -t [table] -A [chain] [rules] -j [action]

Rules:
-i or -o [iface]
-s or -d [ip.add | network/mask]
-p [protocol (in ipv4 header)]

-m is used with:
    state --state [state]
    mac [-- mac-source | -- mac-destinatino] [mac]
    tcp | udp [ --dport | --sport] [port | port1:port2]
    multiport [--sports | --dports | --ports]
                                    [PORT1,[PORT2,[PORTS3:PORT15]]]
    bpf --bytecode ['bytecode']

[actions] - ACCEPT, REJECT, DROP    
```

### **Configuring NFTABLES**

- NFTABLE Families
    - ip - IPv4 packets
    - ip6 - IPv6 packets
    - inet - IPv4 and IPv6 packets
    - arp - layer 2
    - bridge - processing traffic/packets traversing bridges.
    - netdev - allows for user classification of packets - nftables passes up to the networking stack (no counterpart in iptables)

- Introduces chain-types

    3 kinds of chain types: 
    - **filter** - to filter packets - can be used with arp, bridge, ip, ip6, and inet families
    - **route** - to reroute packets - can be used with ip and ipv6 families only
    - **nat** - used for Network Address Translation - used with ip and ip6 table families only

- Creation of hooks
    - PREROUTING
    - POSTROUTING
    - INPUT
    - OUTPUT
    - FORWARD
    - INGRESS - used with NETDEV family only


## recall that if you use terminator for these exercises, we need to allow in 6010, 6011, 6012

```
student@internet-host-student-11:~$ sudo iptables -L
[sudo] password for student: 
Chain INPUT (policy ACCEPT)
target     prot opt source               destination         

Chain FORWARD (policy ACCEPT)
target     prot opt source               destination         

Chain OUTPUT (policy ACCEPT)
target     prot opt source               destination         
student@internet-host-student-11:~$ sudo iptables -t nat -F
student@internet-host-student-11:~$ sudo iptables -t nat -L
Chain PREROUTING (policy ACCEPT)
target     prot opt source               destination         

Chain INPUT (policy ACCEPT)
target     prot opt source               destination         

Chain OUTPUT (policy ACCEPT)
target     prot opt source               destination         

Chain POSTROUTING (policy ACCEPT)
student@internet-host-student-11:~$ sudo iptables -A INPUT -p tcp --dport 22 -j ACCEPT
student@internet-host-student-11:~$ sudo iptables -L
Chain INPUT (policy ACCEPT)
target     prot opt source               destination         
ACCEPT     tcp  --  anywhere             anywhere             tcp dpt:ssh

Chain FORWARD (policy ACCEPT)
target     prot opt source               destination         

Chain OUTPUT (policy ACCEPT)
target     prot opt source               destination         
student@internet-host-student-11:~$ sudo iptables -A INPUT -p tcp -m multiport --ports 6010,6011,6012 -j ACCEPT
student@internet-host-student-11:~$ sudo iptables -L
Chain INPUT (policy ACCEPT)
target     prot opt source               destination         
ACCEPT     tcp  --  anywhere             anywhere             tcp dpt:ssh
ACCEPT     tcp  --  anywhere             anywhere             multiport ports 6010,6011,6012

Chain FORWARD (policy ACCEPT)
target     prot opt source               destination         

Chain OUTPUT (policy ACCEPT)
target     prot opt source               destination         
student@internet-host-student-11:~$ sudo iptables -A INPUT -p tcp --sport 22 -j ACCEPT
student@internet-host-student-11:~$ sudo iptables -L
Chain INPUT (policy ACCEPT)
target     prot opt source               destination         
ACCEPT     tcp  --  anywhere             anywhere             tcp dpt:ssh
ACCEPT     tcp  --  anywhere             anywhere             multiport ports 6010,6011,6012
ACCEPT     tcp  --  anywhere             anywhere             tcp spt:ssh

Chain FORWARD (policy ACCEPT)
target     prot opt source               destination         

Chain OUTPUT (policy ACCEPT)
target     prot opt source               destination         
student@internet-host-student-11:~$ sudo iptables -A OUTPUT -p tcp -m multiport --ports 22,6010,6011,6012 -j ACCEPT
student@internet-host-student-11:~$ sudo iptables -L
Chain INPUT (policy ACCEPT)
target     prot opt source               destination         
ACCEPT     tcp  --  anywhere             anywhere             tcp dpt:ssh
ACCEPT     tcp  --  anywhere             anywhere             multiport ports 6010,6011,6012
ACCEPT     tcp  --  anywhere             anywhere             tcp spt:ssh

Chain FORWARD (policy ACCEPT)
target     prot opt source               destination         

Chain OUTPUT (policy ACCEPT)
target     prot opt source               destination         
ACCEPT     tcp  --  anywhere             anywhere             multiport ports ssh,6010,6011,6012
student@internet-host-student-11:~$ sudo iptables -L --line-numbers
Chain INPUT (policy ACCEPT)
num  target     prot opt source               destination         
1    ACCEPT     tcp  --  anywhere             anywhere             tcp dpt:ssh
2    ACCEPT     tcp  --  anywhere             anywhere             multiport ports 6010,6011,6012
3    ACCEPT     tcp  --  anywhere             anywhere             tcp spt:ssh

Chain FORWARD (policy ACCEPT)
num  target     prot opt source               destination         

Chain OUTPUT (policy ACCEPT)
num  target     prot opt source               destination         
1    ACCEPT     tcp  --  anywhere             anywhere             multiport ports ssh,6010,6011,6012
student@internet-host-student-11:~$ sudo iptables -P INPUT DROP
student@internet-host-student-11:~$ sudo iptables -P OUTPUT DROP
student@internet-host-student-11:~$ sudo iptables -P FORWARD DROP
student@internet-host-student-11:~$ sudo iptables -L
Chain INPUT (policy DROP)
target     prot opt source               destination         
ACCEPT     tcp  --  anywhere             anywhere             tcp dpt:ssh
ACCEPT     tcp  --  anywhere             anywhere             multiport ports 6010,6011,6012
ACCEPT     tcp  --  anywhere             anywhere             tcp spt:ssh

Chain FORWARD (policy DROP)
target     prot opt source               destination         

Chain OUTPUT (policy DROP)
target     prot opt source               destination         
ACCEPT     tcp  --  anywhere             anywhere             multiport ports ssh,6010,6011,6012
student@internet-host-student-11:~$ sudo iptables -P FORWARD ACCEPT
student@internet-host-student-11:~$ sudo iptables -P OUTPUT ACCEPT
student@internet-host-student-11:~$ sudo iptables -P INPUT ACCEPT
student@internet-host-student-11:~$ sudo iptables -L
Chain INPUT (policy ACCEPT)
target     prot opt source               destination         
ACCEPT     tcp  --  anywhere             anywhere             tcp dpt:ssh
ACCEPT     tcp  --  anywhere             anywhere             multiport ports 6010,6011,6012
ACCEPT     tcp  --  anywhere             anywhere             tcp spt:ssh

Chain FORWARD (policy ACCEPT)
target     prot opt source               destination         

Chain OUTPUT (policy ACCEPT)
target     prot opt source               destination         
ACCEPT     tcp  --  anywhere             anywhere             multiport ports ssh,6010,6011,6012
student@internet-host-student-11:~$ sudo iptables -F
student@internet-host-student-11:~$ 
```

-----------------------
-----------------------
CTF Flags
***

1. IP/NFTables - Filtering T1

    PTable Rule Definitions

    Allow New and Established traffic to/from via SSH, TELNET, and RDP

    Change the Default Policy in the Filter Table for the INPUT, OUTPUT, and FORWARD chains to DROP

    Only allow Pivot to perform ping (ICMP) operations to/from

    Allow ports 6579 and 4444 for both udp and tcp traffic

    Allow New and Established traffic to/from via HTTP

    Once these steps have been completed and tested, go to Pivot and open up a netcat listener on port 9001 and wait up to 2 minutes for your flag. If you did not successfully accomplish the tasks above, then you will not receive the flag.

    - ssh 172.16.82.106 (T1)
    - want to allow new and established traffic to and from 22, 23, and 3389
    - flag: 467accfb25050296431008a1357eacb1

```
  13  sudo iptables -A INPUT -p tcp -m multiport --ports 22,23,3389 -j ACCEPT
   14  sudo iptables -A OUTPUT -p tcp -m multiport --ports 22,23,3389 -j ACCEPT
   15  sudo iptables -vL
   16  sudo iptables -P INPUT DROP
   17  sudo iptables -P FORWARD DROP
   18  sudo iptables -P OUTPUT DROP
   19  sudo iptables -A INPUT -p icmp --icmp-type 0 -s 10.10.0.40 -j ACCEPT
   20  sudo iptables -A INPUT -p icmp --icmp-type 0 -d 10.10.0.40 -j ACCEPT
   21  sudo iptables -D INPUT -p icmp --icmp-type 0 -d 10.10.0.40 -j ACCEPT
   22  sudo iptables -L
   23  sudo iptables -A INPUT -p icmp --icmp-type 8 -s 10.10.0.40 -j ACCEPT
   24  sudo iptables -A OUTPUT -p icmp --icmp-type 8 -d 10.10.0.40 -j ACCEPT
   25  sudo iptables -A OUTPUT -p icmp --icmp-type 0 -d 10.10.0.40 -j ACCEPT
   26  sudo iptables -L
   27  sudo iptables -A INPUT -p tcp -m multiport --ports 6579,4444 -j ACCEPT
   28  sudo iptables -A OUTPUT -p tcp -m multiport --ports 6579,4444 -j ACCEPT
   29  sudo iptables -A OUTPUT -p udp -m multiport --ports 6579,4444 -j ACCEPT
   30  sudo iptables -A INPUT -p udp -m multiport --ports 6579,4444 -j ACCEPT
   31  sudo iptables -A INPUT -p tcp -m multiport --ports 80 -j ACCEPT
   32  sudo iptables -A OUTPUT -p tcp -m multiport --ports 80 -j ACCEPT
   33  sudo iptables -L
   34  ssh 10.10.0.40
```
