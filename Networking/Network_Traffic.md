```
Pivot
Hostname: INTERNET_HOST
IP: 10.10.0.40 (Use the provided floating IP only for login from outside of the network
Creds: PROVIDED CREDENTIALS
Action: Utilize to Pivot into Gorgan Cyberspace and test filters & Rules

T1
Hostname: BLUE_Host-1
IP: 172.16.82.106
Creds: student : password
Action: Implement Host Filtering to Allow and Restrict Communications and Traffic

T2
Hostname: BLUE_Host-3
IP: 172.16.82.112
Creds: student : password
Action: Implement Host Filtering to Allow and Restrict Communications and Traffic

T3
Hostname: BLUE_INT_DMZ_HOST-1
IP: 172.16.40.10
Creds: student : password
Action: Implement Host Filtering to Allow and Restrict Communications and Traffic

T4
Hostname: (Will be provided by Mission Command)
IP: 10.50.23.7
creds: student9:password9 (X = Student Number)
Known Ports: Unknown
Action: Interrogate Target and validate Signatures
alt ssh port 25

T5
Hostname: BLUE_PRIV_HOST-1
IP: 192.168.1.10
creds: student : password
Action: Allow traffic through NAT Capabilities

T6
Hostname: BLUE_PRIV_HOST-3
IP: 192.168.3.30
creds: student : password
Action: Allow traffic through NAT Capabilities
```

## IP/NFTables: Filter
```
# Allow New and Established traffic to/from via SSH, TELNET, and RDP
sudo iptables -A INPUT -p tcp -m multiport --ports 22,23,3389 -m state --state NEW,ESTABLISHED -j ACCEPT
sudo iptables -A OUTPUT -p tcp -m multiport --ports 22,23,3389 -m state --state NEW,ESTABLISHED -j ACCEPT

# Change the Default Policy in the Filter Table for the INPUT, OUTPUT, and FORWARD chains to DROP
sudo iptables -P INPUT DROP
sudo iptables -P OUTPUT DROP
sudo iptables -P FORWARD DROP



# Only allow 10.10.0.40 to perform ping (ICMP) operations to/from
# echo-request = 8
# echo-reply = 0
sudo iptables -A INPUT -s 10.10.0.40 -p icmp --icmp-type 8 -j ACCEPT
sudo iptables -A INPUT -s 10.10.0.40 -p icmp --icmp-type 0 -j ACCEPT
sudo iptables -A OUTPUT -d 10.10.0.40 -p icmp --icmp-type 8 -j ACCEPT
sudo iptables -A OUTPUT -d 10.10.0.40 -p icmp --icmp-type 0 -j ACCEPT

# Allow ports 6579 and 4444 for both udp and tcp traffic
sudo iptables -A INPUT -p tcp -m multiport --ports 6579,4444 -j ACCEPT
sudo iptables -A OUTPUT -p tcp -m multiport --ports 6579,4444 -j ACCEPT
sudo iptables -A INPUT -p udp -m multiport --ports 6579,4444 -j ACCEPT
sudo iptables -A OUTPUT -p udp -m multiport --ports 6579,4444 -j ACCEPT

# Allow New and Established traffic to/from via HTTP
sudo iptables -A INPUT -p tcp -m multiport --ports 80 -m state --state NEW,ESTABLISHED -j ACCEPT
sudo iptables -A OUTPUT -p tcp -m multiport --ports 80 -m state --state NEW,ESTABLISHED -j ACCEPT

nc -lvp 9001

Your Host Filtering T1 Flag is:
467accfb25050296431008a1357eacb1
```

```
# Allow New and Established traffic to/from via SSH, TELNET, and RDP
sudo iptables -A INPUT -p tcp -m multiport --ports 22,23,3389 -m state --state NEW,ESTABLISHED -j ACCEPT
sudo iptables -A OUTPUT -p tcp -m multiport --ports 22,23,3389 -m state --state NEW,ESTABLISHED -j ACCEPT

# Change the Default Policy in the Filter Table for the INPUT, OUTPUT, and FORWARD chains to DROP
sudo iptables -P INPUT DROP
sudo iptables -P OUTPUT DROP
sudo iptables -P FORWARD DROP

# Allow New and Established traffic to/from via HTTP
sudo iptables -A INPUT -p tcp -m multiport --ports 80 -m state --state NEW,ESTABLISHED -j ACCEPT
sudo iptables -A OUTPUT -p tcp -m multiport --ports 80 -m state --state NEW,ESTABLISHED -j ACCEPT

nc -lp 9003

Your Host Filtering T3 Flag is:
05e5fb96e2a117e01fc1227f1c4d664c
```
```
# NFTable: CCTC
# Family: ip
sudo nft add table ip CCTC

# Create input and output base chains with:
# Hooks
# Priority of 0
# Policy as Accept
sudo nft add chain ip CCTC input { type filter hook input priority 0 \; policy accept \;}
sudo nft add chain ip CCTC output { type filter hook output priority 0 \; policy accept \;}

# Allow New and Established traffic to/from via SSH, TELNET, and RDP
sudo nft add rule ip CCTC input ct state { new,established } tcp sport { 22,23,3389 } counter accept
sudo nft add rule ip CCTC input ct state { new,established } tcp dport { 22,23,3389 } counter accept
sudo nft add rule ip CCTC output ct state { new,established } tcp sport { 22,23,3389 } counter accept
sudo nft add rule ip CCTC output ct state { new,established } tcp dport { 22,23,3389 } counter accept

# Change your chains to now have a policy of Drop
sudo nft add chain ip CCTC input { policy drop \; }
sudo nft add chain ip CCTC output { policy drop \; }

# Only allow 10.10.0.40 to perform ping (ICMP) operations to/from
sudo nft add rule ip CCTC input ip daddr 10.10.0.40 icmp type { echo-request,echo-reply } counter accept
sudo nft add rule ip CCTC input ip saddr 10.10.0.40 icmp type { echo-request,echo-reply } counter accept
sudo nft add rule ip CCTC output ip saddr 10.10.0.40 icmp type { echo-request,echo-reply } counter accept
sudo nft add rule ip CCTC output ip daddr 10.10.0.40 icmp type { echo-request,echo-reply } counter accept

# Allow ports 5050 and 5150 for both udp and tcp traffic to/from
sudo nft add rule ip CCTC input tcp dport { 5050, 5150} counter accept
sudo nft add rule ip CCTC input tcp sport { 5050, 5150} counter accept
sudo nft add rule ip CCTC input udp dport { 5050, 5150} counter accept
sudo nft add rule ip CCTC input udp sport { 5050, 5150} counter accept
sudo nft add rule ip CCTC output tcp dport { 5050, 5150} counter accept
sudo nft add rule ip CCTC output tcp sport { 5050, 5150} counter accept
sudo nft add rule ip CCTC output udp dport { 5050, 5150} counter accept
sudo nft add rule ip CCTC output udp sport { 5050, 5150} counter accept

# Allow New and Established traffic to/from via HTTP
sudo nft add rule ip CCTC input ct state { new,established } tcp dport 80 counter accept
sudo nft add rule ip CCTC input ct state { new,established } tcp sport 80 counter accept
sudo nft add rule ip CCTC output ct state { new,established } tcp dport 80 counter accept
sudo nft add rule ip CCTC output ct state { new,established } tcp sport 80 counter accept

nc -lp 9002
Your Host Filtering T2 Flag is:
9f7a33941828bdafd2755fd20176cdf4
```
- Once you have received the flag for T1, T2, and T3, go to Pivot and perform an md5sum on the combination of T1 flag, T2 flag, and T3 flag combined and separated by underscores.
  - 467accfb25050296431008a1357eacb1_9f7a33941828bdafd2755fd20176cdf4_05e5fb96e2a117e01fc1227f1c4d664c
  - 953e720e688941b15b72c098022c51c3
  - Send the result of the md5sum of all three flags separated by underscores to the same IP address and port (IP 172.16.1.15 Port 5309) to receive your flag.
    - d3b88e04de1e76482a1972f36734a7d8

```
Task 1) On BLUE_SCR-Router (172.16.20.1) - Restrict connections coming into the BLUE NET from external networks.
1. Create a firewall called "RED" and set it up as a blacklist. Use rule numbers starting at 100.
2. Prevent the INTERNET_HOST ping (ICMP) operations to BLUE_HOST-3.
3. Prevent the INTERNET_HOST to establish NEW TELNET connections to BLUE_HOST_Net and BLUE_INT_DMZ_Net. Use a network group called "BLUE_NET".
4. Prevent access to traffic that is spoofing the (6) internal network addresses. Use network group called "ANTI-SPOOF".
5. Block the specific external host that is trying to brute force the BLUE_INT_DMZ_HOST web page. This was idenitified by sniffing web traffic to BLUE_INT_DMZ_HOST from IPTables and NFTables for Filtering activity.
6. Taking the flow of traffic into account, apply firewall RED to the appropriate interface in the correct direction.
7. Make sure to commit changes (DO NOT SAVE)

TASK 2) On BLUE_POP-Router - Make sure that BLUE_INT_DMZ_HOST-1 can be accessed by INTERNET_HOST.
1. Create a firewall called "WHITE" and set it up as a whitelist. Use rule numbers starting at 200.
2. Allow access from INTERNET_HOST to BLUE_INT_DMZ_HOST using tcp connections.
3. Allow access all web access to BLUE_INT_DMZ_HOST.
4. Allow ping (ICMP) operations from INTERNET_HOST to BLUE_HOST-1 only.
5. Allow access for ports 6579 and 5150 to reach their destinations. Use a port group called "slide".
6. Allow only established connections through the firewall WHITE.
7. Taking the flow of traffic into account, apply firewall WHITE to the appropriate interface in the correct direction.
8. Make sure to commit changes (DO NOT SAVE)

TASK 3) On BLUE_POP-Router - Make sure that BLUE_INT_DMZ_HOST-1 should have access to INTERNET_HOST, BLUE_HOST-1 and BLUE_HOST-3.
1. Create a firewall called "BLUE" and set it up as a whitelist. Use rule numbers starting at 300.
2. Make rule that will allow BLUE_INT_DMZ_HOST-1 to access BLUE_HOST-1.
3. Make rule that will allow BLUE_INT_DMZ_HOST-1 to access BLUE_HOST-3.
4. Make rule that will allow BLUE_INT_DMZ_HOST-1 to access INTERNET_HOST.
5. Apply firewall BLUE to the proper interface and direction.
6. Make sure to commit changes (DO NOT SAVE)

TASK 4) Rule verification.
Verify that the rules are working.
INTERNET_HOST should only be able to ssh to BLUE_INT_DMZ_HOST-1. BLUE_HOST-1 and BLUE_HOST-3 only accessible though BLUE_INT_DMZ_HOST-1.
INTERNET_HOST now can only ping BLUE_HOST-1. BLUE_HOST-3 should be filtered by firewall RED.
BLUE_HOST-1, BLUE_INT_DMZ_HOST-1 and BLUE_HOST-3 should not be able to ping each other.
INTERNET_HOST now can only pull web page from BLUE_INT_DMZ_HOST-1. All but BLUE_INT_DMZ_HOST-1 is filtered by firewall WHITE.
BLUE_INT_DMZ_HOST-1 will no longer get requests which should be filtered by firewall RED.
BLUE_HOST-1 you must now SSH through BLUE_INT_DMZ_HOST-1. BLUE_HOST-1 now should only see traffic on port 6579 only. Port 4444 is filtered by firewall WHITE.
To get to BLUE_HOST-3 you must now SSH through BLUE_INT_DMZ_HOST-1. BLUE_HOST-3 now should only see traffic on port 5150 only. Port 5050 is filtered by firewall WHITE.
```

## IP/NFTables: NAT
```
# Configure POSTROUTING chain to translate T5 IP address to T1 (Create the rule by specifying the Interface information first then Layer 3)

sudo iptables -t nat -A POSTROUTING -s 192.168.1.10 -p tcp -o eth0 -j MASQUERADE

nc -lp 9004 -> 0c2ca80fad4accccce3bcecec1d238ce
```

```
On T2 edit the /proc/sys/net/ipv4/ip_forward file to enable IP Forwarding. Change the value from 0 to 1.

# Create POSTROUTING and PREROUTING base chains with:
# Hooks
# Priority of 0
# No Policy Needed
sudo nft add table ip NAT
sudo nft add chain ip NAT PREROUTING { type nat hook prerouting priority 0 \;}
sudo nft add chain ip NAT POSTROUTING { type nat hook postrouting priority 0 \;}

# Configure POSTROUTING chain to translate T6 IP address to T2 (Create the rule by specifying the Interface information first then Layer 3)

sudo nft add rule ip NAT POSTROUTING ip saddr 192.168.3.30 oif eth0 masquerade

nc -lp 9005 -> be33fe60229f8b8ee22931a3820d30ac
```

```
Validate that T5 can access the web, and Demonstrate the capability to Mission Command
Validate that T6 can access the web, and Demonstrate the capability to Mission Command
ping -S 192.168.1.10 8.8.8.8
ping -S 192.168.3.30 8.8.8.8
```
- Enumerate services on T4 to gain access, and perform Passive Recon. What command was used to run snort on that machine.
  - `ps -elf | grep snort`
  - `/usr/bin/snort -D -c /etc/snort/snort.conf`
- Utilizing T4, which SNORT rule would create an alert when No TCP Flags are set or the URG, PUSH, and FIN TCP Flags are set?
  - `cat /etc/snort/snort.conf`
  - nm.rules
- Utilizing T4, which SNORT rule would create an alert when the Hex Indicator of a NOP Sled are detected?
  - shell.rules
- Utilizing T4, which SNORT rule would create an alert when a DNS Zone Transfer is detected with the content specified in CVE-1999-0532
  - dzt.rules
- Utilizing T4, which SNORT rule would create an alert when an ICMP Message is detected.
  - icmp.rules
- Using the provided Traffic Capture (/home/activity_resources/pcaps/ids.pcap) how many alerts are created with the default ICMP rule?
  - sudo snort -r ids.pcap
- Utilizing your INTERNET_HOST, create a new rule called cows.rules.
```
Rule Definition:
alert
any ICMP Messages Source to destination
Generate the message Cows
Detects the hex content of DEADBEEF
Set sid to 1000001

Provide the complete working rule that you created as the flag with NO SPACES between the ( ).
```
  - `alert icmp any any -> any any (msg:"Cows";content:"|DEADBEEF|";sid:1000001;)`
- Utilizing your INTERNET_HOST, and the provided Traffic Capture how many alerts are created with the content of DEADBEEF?
  - 80
  - remove unneeded rule from conf file first
  - `sudo snort -c /etc/snort/snort.conf -r ids.pcap`
- Utilizing your INTERNET_HOST, create a new rule called dmz.rules.
```
Rule Definition:
alert
any ICMP Echo Requests Detects Type 8 / Code 0 To 10.3.0.0/24
Generate the message DMZ Ping
Set sid to 1000002
```
    - `alert icmp any any -> 10.3.0.0/24 any (msg:"DMZ Ping";itype:8;icode:0;sid:1000002;)``
- Utilizing your INTERNET_HOST, and the provided Traffic Capture how many alerts are created for ICMP Echo Request messages to 10.3.0.0/24?
  - `sudo snort -c /etc/snort/snort.conf -r ids.pcap`
- Utilizing your INTERNET_HOST, create a new rule that will:
    - Track 3 ssh authentication attempts within 10 seconds coming from a Specific Source using both threshold.
      - `alert tcp any any -> any 22 (threshold: type both, track by_src, count 3, seconds=10;sid:1000069;)`
    - Utilizing the provided Traffic Capture how many alerts are created for SSH Brute Force attempts?
      - 9
- Utilizing your INTERNET_HOST, create a new rule that will:
  - Track IP Protocol and RDP traffic to and from 10.1.0.0/16 regardless of the traffic flow state.
    - `alert ip 10.1.0.0/16 3389 -> any any (sid:1000070;flow:stateless;)`
  - Utilizing the provided Traffic Capture how many alerts are created for RDP messages?
    - 409
- Utilizing your INTERNET_HOST, create a new rule that will:
  - Detect TCP Null scan to 10.3.0.0/24 regardless of the traffic flow state.
    - `alert tcp any any -> 10.3.0.0/24 (sid:1000071;flags:0;flow:stateless;)`
  - Utilizing the provided Traffic Capture how many alerts are created for TCP Null scan?
    - 327
- WannaCry ransomware and other Malware often use SMB and CIFS protocols as an attack vector for propagation. Identify the ports these protocols use.
  - SMB: TCP 139,445. CIFS: UDP 137,138
  - Utilizing your INTERNET_HOST, create a new rule that will:
  - Detect all traffic using the Identified Ports regardless of the traffic flow state going to 10.0.0.0/8.
    - alert tcp any any -> 10.0.0.0/8 [139,445] (sid:1000075;flow:stateless)
    - alert udp any any -> 10.0.0.0/8 [137,138] (sid:1000076;flow:stateless)
