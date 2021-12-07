## CCTC Networking Day 8 (Network Traffic Filtering: NAT & PAT)

- agenda


## Admin Data 

### CTFd info
| Field | Value | 
|-|-|
| Flag | i_am_filtering_your_noise | 
| IP/NFTables | T@bl3sth@tF1lt3r | 

## Day 8: Network Traffic Filtering NAT

### **NAT & PAT Operators & Chains**

| Statement Operator | Appilcable Chains | 
|-|-|
| snat| postrouting, input | 
| masquerade| postrouting (replacing traffic with a new ip address) | 
| dnat | prerouting, input | 
| redirect | prerouting, output |

- **Example source NAT w/ IPTables**

    packet before nat

    | ipv4 source | ipv4 destination|sport/dport| 
    |-|-|-|
    | 192.168.0.1| 8.8.8.8 | 49500/80 |
    
    packet after nat

    | ipv4 source | ipv4 destination|sport/dport| 
    |-|-|-|
    | 1.1.1.1| 8.8.8.8 | 49500/80 |

    - `iptables -t nat -A POSTROUTING -o eth0 -j SNAT --to 1.1.1.1`

- **Example destination NAT w/ iptables**

    packet before nat

    | ipv4 source | ipv4 destination|sport/dport| 
    |-|-|-|
    | 192.168.0.1| 8.8.8.8 | 49500/80 |
    
    packet after nat

    | ipv4 source | ipv4 destination|sport/dport| 
    |-|-|-|
    | 192.168.0.1| 10.0.0.1 | 49500/80 |

    - `iptables -t nat -A PREROUTING -o eth0 -j DNAT --to 10.0.0.1`

- **Example source PAT w/ iptables**

    packet before nat

    | ipv4 source | ipv4 destination|sport/dport| 
    |-|-|-|
    | 192.168.0.1| 8.8.8.8 | 49500/80 |
    
    packet after nat

    | ipv4 source | ipv4 destination|sport/dport| 
    |-|-|-|
    | 1.1.1.1| 8.8.8.8 | 9001/80 |

    - `iptables -t nat -A POSTROUTING -p tcp -o eth0 -j SNAT --to 1.1.1.1:9001`

- **Example destination PAT w/ iptables (Port forwarding)**

    packet before nat

    | ipv4 source | ipv4 destination|sport/dport| 
    |-|-|-|
    | 209.0.0.1| 1.2.3.4 | 49500/80 |
    
    packet after nat

    | ipv4 source | ipv4 destination|sport/dport| 
    |-|-|-|
    | 209.0.0.1| 10.0.0.1 | 9001/8080 |

    - `iptables -t nat -A POSTROUTING -p tcp -o eth0 -j DNAT --to 10.0.0.1:8080`

### **NAT & PAT w/ NFTables**
- Create the NAT table
    - nft add table ip NAT
- Create the NAT chains
    - nft add chain ip NAT PREROUTING {type nat hook prerouting priority 0 \; }
    - nft add chain ip NAT POSTROUTING {type nat hook postrouting priority 100 \; }

#### **Create the NAT rules**
- Source NAT
    - nft add rule ip NAT POSTROUTING ip saddr 10.1.0.2 oif eth0 snat 144.15.60.11
- Destination NAT
    - nft add rule ip NAT PREROUTING iif eth0 tcp dport { 80, 443 } dnat 10.1.0.3
- Source NAT w/ masquerade
    - nft add rule ip NAT POSTROUTING ip saddr 10.1.0.0/24 oif eth0 masquerade
- Destination NAT (port forwarding) with redirect
    - nft add rule ip NAT PREROUTING tcp dport 80 redirect to 8080

***
## Network Based Filtering