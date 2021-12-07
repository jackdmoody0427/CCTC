## CCTC Networking Day 6 (Network Analysis)

- agenda


## Admin Data 

### CTFd info
| Field | Value | 
|-|-|
| Flag | N@tF1lt3rsf0rL1f3 | 
| Name | IP/NFTables - NAT | 

## Day 6: Network Analysis

### **Fingerprinting and Host Identification**
- Variances in the RFC implementation for different OS’s and systems enables the capability for fingerprinting

- Tools used for fingerprinting and host identification can be used passively(sniffing/fingerprinting) or actively(scanning)

- **POF (Passive OS Fingerprinting)**
    
    - Looks at variations in initial TTL, fragmentation flag, default IP header packet length, window size, and TCP options

    - Configuration stored in: `/etc/p0f/p0f.fp`

### **Network Traffic Sniffing**

- What makes traffic capture possible?
    - Libpcap
    - WinPcap (oudated)
    - NPCAP

- **Network Traffic Baselining**
    - Snapshots of whta the network looks like during a time frame
    - No industry standard
    - 7 days to establish the intitial snapshot
    - Prerequisite Information 
    - **Network Baseline Objective**
        
        - Determines the current state of your network
        - Ascertain the current utilization of network resources
        - Idenifying normal vs peak network traffic time frames
        - Verify port/ protocol usage
    - **Analyze Network Traffic Statistics**

        - Protocol Hierarchy
        - Conversations
        - Endpoints
        - I/0 Graph
        - IPv4 and IPv6 Stats
        - Expert Info

### **Network Data Types**
- Full Packet Capture Data
- Session Data
    
    - Sflow
    - netFlow
- Statistical Data
- Packet String Data
- Alert Data
- Log Data

- **Data Collection Devices**
    
    - Sensors
        - In-Line
        - Passive

- **Methods of Data Collection**

    - Tap 
    - SPAN
    - ARP Spoofing (MitM)

### **Anomaly Detection**
- *Indicator of Attack (IOA)*
    - **Proactive**
    - A series of actions that are suspicious togeher
    - Focus on Intent
    - Look for what must happen
        - Code execution, persistence, lateral movement, etc. 

- *Indicator of Compromise (IOC)*
    - **Reactive**
    - Forensic Evidence
    - Provides Information that can change
        - Malware, IP addresses, exploits, signatures

### **Indicators**
- .exe/executable files
- NOP sled
- Repeated Letters
- Well Known Signatures
- Mismatched Protocols
- Unusual Traffic
- Large amounts of traffic/ unusual times

- **Potential Indicators of Attack**
    - Destinations
    - Ports
    - Public Servers/ DMZs
    - Off-hours
    - Network Scans
    - Alarm Events
    - Malware Reinfection
    - Remote Logins
    - High Levels of email protocols
    - DNS queries

- **Potential Indicators of Compromise**
    - Unusual traffic outbound
    - Anomalous user login or account use
    - Size of responses for HTML
    - High number of requests for the same file
    - Using non-standard ports/ application-port mismatch
    - Writing changes to the registry/system files
    - DNS requests
    - Unexpected/ unusual patching
    - Unusual tasks


### **Types of Malware**
- Adware/Spyware
    - large amount of traffic/ unusual traffic
        - IOA
            - Destinations
        - IOC
            - Unusual Traffic Outbound
- Virus
    - Phishing/watering hole
        - IOA
            - Alarm events, email protocols
        - IOC
            - Changes to registry/ system files

- Worm
    - phishing/ watering hole
        - IOA
            - Alarm events
        - IOC
            - Changes to registry/ files system

- Trojan
    - Beaconing
        - IOA
            - Destinations
        - IOC
            - Unusual traffic outbound, unusual tasks, changes to registry/ system files
- Rootkit
    - IOA
        - Malware reinfection
    - IOC
        - Anomalous user login/ account use

- Backdoor
    - IOA
        - Remote logins
    - IOC
        - Anomalous user login/ account use

- Botnets
    - Large amouns of IPs
        - IOA
            - Destinations, remote logins
        - IOC
            - Unusual tasks, anomalous user login/ account use

- Polymorphic and Metamorphic Malware
    - Depends on the malware type/ class 


## **Mitre Defend and Attack Matrixes**

## **7 Steps of the Kill chain**

1. recon
2. weaponization
3. delivery
4. Exploitation
5. Instillation
6. C2
7. Actions On 

[US Protech Killchain Guide](https://www.usprotech.com/files/2016/10/2016-USPT-Cybersecurity-Kill-Chain-Brochure-V-3-Final.pdf)

[Diamond Model in Cyber](https://www.anomali.com/blog/tracking-your-adversary-with-a-threat-intelligence-platform)



***
CTFs
***
1. How many total packets were captured in the pcap
    - 1908895
2. Determine all IP addresses that were captured in the pcap, and list them all in order. You should find 10

3. How many hosts are in teh capture? 
    - 8 (look at IP classes)

4. OSI

    What Transport Layer protocol is the most prominent in the capture?

    - Protocol Hierarchy Stats -> TCP --> Line-based test data 

5. OS Type
    p0f has extensive finger printing capabilities (as indicated by the name).

    Use p0f to read the pcap and determine the OS type of the host: 192.168.10.101
    - `sudo ./plf -r /home/activity_resources/pcaps/attack_analysis1.pcap 'src host 192.168.10.101' `
    - Linux 3.11 and newer
6. Cellular 

    There is traffic related to 2G & 3G Cellular Communications, which uses a packet oriented mobile data standard.
    
    What protocol is performing this communication?
    be sure to name the protocol and not the standard being used!

    - GPRS -> GSM 
7. Address 1 

    The protocol being used to generate the traffic associated with 239.x.x.x is a UDP based protocol which is commonly used with UPnP for finding devices and services on the network.

    What is this protocol?

8. Address 2 

    The protocol being used to generate the traffic associated with 239.x.x.x is a UDP based protocol which is commonly used with UPnP for finding devices and services on the network.

    What is this protocol?
    - SSDP 

9. Address 3 - source

    What is the mac address of the device that is sending the multicast SSDP traffic?

    - 00:50:56:c0:00:08

10. User Agent 4

    what user agent is making use of the protocol you discovered in Attack Analysis - addres 2 - protocol? 
    - Filter on SSDP
    - click on a capture
    - open the SSDP
    - see the 'user agent' is `Google Chrome`

11. DNS 1

    What is the IP address for the DNS server in the packet capture? 
    - filter DNS
    - look for the query to a website
    - see the destination and source ip that matches
    - 192.168.41.2

12. DNS 2
    What IP Address and Port is the query responding to?

    Example:
    XXX.XXX.XXX.XXX:PORT
    - open up a packet instance
    - look at the IP field
    - 192.168.10.111:54966

13. Service 1

    What is the serviec indicate by the use of the following ip: 224.0.0.251
    - Google it
    - mDNS

14. Service 2

    What is the FQDN and IP Address of the device indicated in the response to the query identified in `Attack Analysis - Service 1``? Look for the DNS A record.

    Example (No Spaces):
    keurig.domain,1.1.1.1
    - filter the ip with `ap.addr == 224.0.0.251`
    - click the response entry
    - look for the type A record
    - HP705A0FF92F8D.local,192.168.1.7

15. dfa
    - PN-PTCP 192.168.10.111:55

16. IOT

    - protocol hierarchy
    - zigbee
    - scop
    - apply as filter
    - SCoP,Hello

17. RCE

    Remote arbitrary Code Execution was captured targeting 192.168.10.111 via a gaming protocol.

    What is the name of the game?

    - Filter with `ip.addr == 192.168.10.111`
    - look for a weird protocol
    - quake3

18. Vuze

    The Vuze DHT protocol was used as an exploit against 192.168.10.111, indicated in the protocol hierarchy page of Wireshark.

    After analysis and some Open Source Research, what type of Application is Vuze?
    - bittorrent

19. Conversation

    Determine the IP addresses for the top two talkers in the capture (the two hosts that generated the most traffic). (list in order e.g. 1.1.1.1,2.2.2.2)

    - 192.168.10.101,192.168.10.111

20. OS Fingerprint

    Initial TTL can be used to determine host operating systems. Use a tool that will perform fingerprinting based on other criteria to determine the OS of the host with the IP address 192.168.10.111.

    - Linux

21. Attacked Port

    Filter traffic communication between the IP addresses of the hosts determined in challenge 19, a UDP flood is occurring. What port is being attacked?

    - filter the ip
    - 55

22. Attacked Port 2

    In the last challenge you discovered port 55 being targeted for attacks, this is within the well known range, what typical service is associated with it?

    - isi-gl 

23. Type of Attack

    What type of attack is the UDP flood discovered in challenge 22?

    - DoS

24. Type of Attack 2

    Is this an automated attack? (yes/no)

    Once you have completed challenge questions 1 - 24 you can shorten the pcap to make Wireshark run faster.

    First run this filter to select everything but the flooding of UDP port 55.

    !(udp.port==55)

    Next export the selected packets as a new pcap using File > Export Specified Packets.

    Save as a new pcap and load it in Wireshark. You should now only have 86345 packets instead of the 1.9 million you had before.

    - yes 

25. Server Version
    What version of Apache is running on the web server at the 192.168.10.111 address according to raw signatures in p0f?
    - look for the ip and find apache
    - 2.4.18

26. Website Tool

    What is the name of the website creation tool/software used on the 192.168.10.111 server indicated in the HTTP POST/GET messages and plugin scanning done by the attackers? (Supply the main software, not the plugin names)

    - `ip.dst == 192.168.10.111 && http.request.method == "POST"` 
    - wordpress

27. Scanning Tools

    Wordpress provides a plethora of plugins, however these are notorious for vulnerabilities, and there are several ways to scan these types of servers. Perform OSR on some of the top tools that could be used.

    Determine which 2 tools were used for scanning against 192.168.10.111. These tools can be identified through examining the user-agent strings.

    - `(ip.dst == 192.168.10.111 && http.request.method == "GET")`
    - Nikto, wpscan 

28. Credentials

    What is the username and password that was attempted against the axis2 plugin? (submit answer in the following format: jeff:mynamisjeff)

    - `http.request.method=="GET" && http contains "axis2"`
    - admin:axis2

29. Plugin

    Consider the user agent strings identified in challenge 27.

    Analyze the related traffic, and identify what Plugin the vulnerability scan triggered on?
        
        - `ip.dst == 192.168.10.111 &&( http.request.method == "POST")`
        - look for info with "plugins"
        - only 2 have it.
        - reflex-gallery

30. Plugin CVE

    Refer to challenge 29. What CVE is related to the plugin the web vulnerability scanner found? (you need to include the version in your research) Submit your answer as the cve listing (e.g. CVE-2019-9999)

    - google it
    - CVE-2015-4133

31. Exploit

    Reading the CVE details will provide you with the knowledge to know what the attacker is able to exploit. What was the Filename that was successfully uploaded by the attacker to 192.168.10.111?

    - `ip.dst == 192.168.10.111 &&( http.request.method == "GET") || http contains "php" && http contains "reflex-gallery"`
    - look through the encapsulated multipart part: 
    - msf.php

32. Exploit 2

    The malicious upload referred to in challenge 31 is used to start communication for a specific tool, what is the name of this tool/framework (not the attack payload)?
    - google it
    - metasploit

33. Payload

    refer to challenge 32. This popular attack payload provides an interactive shell to the attacker, this payload uses in-memory DLL injection. Identify the payload name (this is a single word, not the payload in hex).
    - google it
    - meterpreter

34. Language

    What progamming language is the payload disovered in 33 written in? 

    - ruby 

35. Payload UUID

    Refering to the payload identified in Challenge 34, what is the Payload UUID identified in the session of the host that was first compromised?

    Enter answer in this format: \x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff

    - `data contains "UUID"`
    - right click, follow TCP stream
    - \x81\xc2\xe4\x1d\xc3\x06\xf6\xf6\xeb\xd8\xf8\xd7\xb2\xe2\xea\x5b

36. Attacked IP

    The 192.168.10.111 web server is now under control of the attacker through a reverse TCP connection via the meterpreter session. The 192.168.10.111 server is used to pivot to another target and perform the same actions the attacker took against 192.168.10.111, what is it's ip address?

    - 192.168.10.112

37. Malware Type

    What type of malware is uploaded to the 192.168.10.112 server (not the malicious php upload to kick off the meterpreter session)? Look for a connection back to a malware repository in the TCP stream.

    - ransomware 

38. New Payload UUID

    - \xc5\x0f\xbc\x3a\x9f\x31\x91\x0b\x42\x66\x51\x69\x1b\x5c\x43\xa3

39. Malware Location

    Refer back to challenge 37, the malware referenced in this question was identified as ransomware. What is the github repo from which the malware is downloaded? (submit your answer in the following format: https://github.com/horst_simco/malwarez)

    - https://github.com/mauri870/ransomware 

40. Malware Language

    According to the github site, the malware was determined to be ransomware. What programming language was used to write this?

    - go

41. OS Target

    Refer back to challenge 38, the malware referenced in this question was identified as ransomware. What OS is targeted by the malware?

    - windows

42. Architecture

    The ransomware indicated in challenge 37 targets what type of system architecture?

    - x86

43. Assembly description

    What is the assembly description in teh assembly manifest for the ransomware 

    - Nothing to see here 

44. Date

    There is a protocol that provides clock synchronization between systems over packet-switched networks in this pcap. Use this information to determine the date of this packet capture. (format your answer as follows: Oct 20, 2019)

    - `NTP`
    - Jun 9, 2017