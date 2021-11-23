## CCTC Networking Day 2 

- agenda
    - Lecture
        - Netowrk traffic sniffing
        - Wireshark, TCPDump, and **BPFs** (Berkeley Packet Filters)
        - Layer 2 switching tech
        - Layer 3 routing tech
   - BPF challenges
        - demo/example of one challenge
        - work on challenges till complete 

## Admin Data 

### CTFd info
| Field | Value | 
|-|-|
| Flag | N3tw0rk@RPFund3m3nt@ls| 
| name | Packet Manipulation 1 | 

## Day 2: Fundamentals (Network Traffic Sniffing)
- Capture Library
    - what makes traffic caputre possible?
        - Libpcap
        - WinPcap
        - NPCAP

Data is captured off the wire by a NIC in permiscuous mode 

**wireshark demo**
```
ssh student@10.50.39.177 -X
find / -iname "*.pcap" 2>/dev/null
/home/activity_resources/pcaps/remote_capture.pcap
/home/activity_resources/pcaps/attack_analysis3.pcap
/home/activity_resources/pcaps/attack_analysis1.pcap
/home/activity_resources/pcaps/attack_analysis2.pcap
/home/activity_resources/pcaps/BPFCheck.pcap
/home/activity_resources/pcaps/Xtra.pcap
/home/activity_resources/pcaps/ids.pcap
/home/activity_resources/pcaps/practice.pcap
student@internet-host-student-11:~$ PCAP= /home/activity_resources/pcaps/practice.pcap
-bash: /home/activity_resources/pcaps/practice.pcap: cannot execute binary file: Exec format error
student@internet-host-student-11:~$ PCAP=/home/activity_resources/pcaps/practice.pcap
student@internet-host-student-11:~$ echo $PCAP
/home/activity_resources/pcaps/practice.pcap
student@internet-host-student-11:~$ wireshark $PCAP
```
- This should open up all the packets
- You can see 3 tiers, top is the packets, middle is the explination, bottom is the output
- To apply a filter, right click, "apply as filter" 
- Useful things
    - Statistics --> **Protocol Hierarchy**
    - View --> Time Display Format --> UTC Time and Date 
    - Statistics --> Conversations (who is talking to who the most)
    - Statistics --> Endpoints (a list of all IPs that show up in the PCAP). Be careful that not all IPs are host IPs, this option will include multicast and broadcast addresses 

**TSHARK Demo**
- `curl cht.sh/TSHARK` 

**TCPDump**
- `sudo tcpdump`
- `sudo tcpdump not port 22`
- `sudo tcpdump tcp[2:2] !-22`
- Show list of available netowrk interfaces that can be listened on using "-D"
    - `sudo tcpdum -D`
- Show packets on specific interface
    - `sudo tcpdum -i eth0`
- -X(display packet data in HEX and ASCII)
- -XX (display the packet in HEX and ASCII to inslude the Erhtner portion
- -w to capture output to a file
    - `sudo tcpdump -w output.pcap`
- -r to read output file 
    - `sudo tcpdump -r pcap.txt`
- -v to make verbose
    - `sudp tcpdump -v`
- -n will give you number over name
    - so it will say "10.10.10.22" instead of "10.10.10.ssh" if looking at port 22 
- tcpdum for range of ports on 2 different hosts with a destination to a specific network 
    - `sudo tcpdump portrange 20-100 and host 10.1.0.2 or host 10.1.0.3 and dst net 10.20.0.0/24 -vn`
- tcpdump is filtering for src network and destination network, or destination hos. However, don't include packets from this destination host. If it meets this criteria, include it in my packet list 
    - `sudo tcpdump "(src net 10.1.0.0/24 && (dst net 10.3.0.0/24 || dst 10.2.0.3) && (! dst host 10.1.0.3))" -vn` 

**Show interfaces**
- `ip a`


**Reverse find command**
-`control r`
- begin typing syntax you want to match 


**Boolean/ conditional operators**
- And = &&
- Or = ||
- Not = !
- less than = < 
- greater than = <
- greater than or equal to = (>=)
- equal to = (==)
- not equal to = (!=)

**BPF**
Using BPFs with operators, bitmasking, and TCPDump creates a powerful tool for traffic filtering and parsing.

tcpdump {A} [B:C] {D} {E} {F} {G}

A = Protocol (ether | arp | ip | ip6 | icmp | tcp | udp)
B = Header Byte offset
C = optional: Byte Length. Can be 1, 2 or 4 (default 1)
D = optional: Bitwise mask (&)
E = Operator (= | == | > | < | <= | >= | != | () | << | >>)
F = Result of Expresion
G = optional: Logical Operator (&& ||) to bridge expressions
Example:
tcpdump 'ether[12:2] = 0x0800 && (tcp[2:2] != 22 && tcp[2:2] != 23)'

------------------
## CTFs

### Example
1. Basic Analysis - TTL 
Level I Challenge
What is the Berkeley Packet Filter, using tcpdump, to capture all packets with a ttl of 64 and less, utilizing the IPv4 or IPv6 Headers? There should be 4880 packets.
Enter the Filter syntax with no spaces

```
student@internet-host-student-11:~$ PCAP2=/home/activity_resources/pcaps/BPFCheck.pcap
student@internet-host-student-11:~$ echo $PCAP2
/home/activity_resources/pcaps/BPFCheck.pcap
student@internet-host-student-11:~$ sudo tcpdump 'ip[8]<=64||ip6[7]<=64' -n -r $PCAP2 |wc -l
reading from file /home/activity_resources/pcaps/BPFCheck.pcap, link-type EN10MB (Ethernet)
4880
```
- FLAG = ip[8]<=64||ip6[7]<=64

2. Basic Analysis - Dont fragement 
What is the Berkeley Packet Filter, using tcpdump, to capture all IPv4 packets with at least the Dont Fragment bit set? There should be 1897 packets.
- `sudo tcpdump 'ip[6] & 0x40 = 0x40' -n -r $PCAP2 |wc -l`

3. Basic Analysis - high port
What is the Berkeley Packet Filter, using tcpdump, to capture traffic with a Source Port higher than 1024, utilizing the correct Transport Layer Headers? There should be 4431 packets.
- `sudo tcpdump "tcp[0:2] > 1024 || udp[0:2] > 1024" -n -r $PCAP2 | wc -l `

4. Basic Analysis - UDP
What is the Berkeley Packet Filter, using tcpdump, to capture all Packets with UDP protocol being set, utilizing the IPv4 or IPv6 Headers? There should be 613 packets.

- `sudo tcpdump "ip[9] =17 || ip6[6]=17" -n -r $PCAP2 | wc -l`

5. Basic Analysis - tcp

What is the Berkeley Packet Filter, using tcpdump, to capture only packets with the ACK/RST or ACK/FIN flag set, utilizing the correct Transport Layer Header? There should be 1161 packets.

- `sudo tcpdump "tcp[13] = 0x11 || tcp[13]= 0x14" -n -r $PCAP2 | wc -l`

6. Basic Analysis - ID
What is the Berkeley Packet Filter, using tcpdump, to capture all packets with an IP ID field of 213? There should be 5 packets.

- ` sudo tcpdump "ip[4:2]=213" -n -r $PCAP2 | wc -l`

7. Basic Analysis - vlan 
What is the Berkeley Packet Filter, using tcpdump, to capture all traffic that contains a VLAN tag? There should be 150 packets.

- `sudo tcpdump 'ether[12:2] = 0x8100' -n -r $PCAP2 | wc -l`

8. Basic Analysis - dns

What is the Berkeley Packet Filter, using tcpdump, to capture all IPv4 packets relating to DNS? There should be 31 packets.

- `sudo tcpdump "tcp[0:2]=53 ||tcp[2:2]=53 ||udp[2:2] =53 || udp[0:2]=53" -n -r $PCAP2 | wc -l`

9. Basic Analysis - dscp
What is the Berkeley Packet Filter, using tcpdump, to capture all IPv4 packets with the DSCP field of 24? There should be 31 packets.
- `sudo tcpdump "ip[1]&252=96" -n -r $PCAP2 | wc -l`

10. Basic Analysis - Traceroute
What is the Berkeley Packet Filter, using tcpdump, to capture all IPv4 packets targeting just the beginning of traceroute as it's entering your network. This can be from a Windows or Linux machine using their default settings? There should be 55 packets.

- `sudo tcpdump "(ip[9]=1 || ip[9]=17) && ip[8]=1" -n -r $PCAP2 | wc -l` 
