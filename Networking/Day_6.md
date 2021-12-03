## CCTC Networking Day 6 (Network Analysis)

- agenda


## Admin Data 

### CTFd info
| Field | Value | 
|-|-|
| Flag |  | 
| Name |  | 

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