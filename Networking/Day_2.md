## CCTC Networking Day 2 

- agenda
    - Lecture
        - Netowrk traffic sniffing
        - Wireshark, TCPDump, and **BPFs**
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
- 'sudo tcpdump tcp[2:2] !-22`
- #show list of available netowrk interfaces that can be listened on using "-D"
    - `sudo tcpdum -D`
- Show packets on specific interface
    - `sudo tcpdum -i eth0`
- -X(display packet data in HEX and ASCII)
- -XX (display the packet in HEX and ASCII to inslude the Erhtner portion


*Reverse find command*
-control r
