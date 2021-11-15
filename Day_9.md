### *CCTC OS NOTES DAY 9*

| Challenge Name | Flag |
| -- | -- | 
| | start2021|

**remember -f for last -f utmp**

/var/log ls -l | exec last -f /var/log/wtmp
## Linux Logging  

### 1 What is Logging 

port to pid to process to file with process 
9999 pid = 2184, process = 
port = 9999, pid = 2184, process = /bin/netcat -lp 9999, file = /bin/nc.traditional


# Questions

XML 3
File: /home/garviel/output.xml
Parse all of the IP addresses from the file using XPATH queries
https://www.w3schools.com/xml/xpath_intro.asp
HINT:
http://xpather.com/
http://www.whitebeam.org/library/guide/TechNotes/xpathtestbed.rhtm
Sample Output (without piping to MD5SUM)
 addr="XXX.xxx.xxx.xxx"
 addr="XXX.xxx.xxx.xxx"
 addr="XXX.xxx.xxx.xxx"
 addr="XXX.xxx.xxx.xxx"
 addr="XXX.xxx.xxx.xxx"
 addr="XXX.xxx.xxx.xxx"
--TRIMMED--
Flag format: md5 hash of output

`xpath -q -e '//@addr' /home/garviel/output.xml |md5sum`
0e850f14fc192c5105955ec094287bd2


XML 4
File: /home/garviel/output.xml
Select all of the IP addresses and ports using a single XPATH Union Statement
Pipe the result to md5sum for the flag
HINT:
https://librarycarpentry.org/lc-webscraping/02-xpath/index.html
Sample Output (without piping to MD5SUM)

`xpath -q -e '//@addr | //@portid' /home/garviel/output.xml |md5sum`

ff7990139b6d09aa65afb6e069db0dec

JSON 1
File: /home/garviel/conn.log
Use jq to pretty print the JSON file conn.log.
Hash the pretty-printed file with md5sum for the flag.
Sample JSON "Pretty Print" Output (without piping to MD5SUM)
  "ts": 1615383120.585641,
  "uid": "C9ybUDHykHdrh0h93",
  "id.orig_h": "10.50.24.73",
  "id.orig_p": 38156,
  "id.resp_h": "192.168.65.20",
  "id.resp_p": 443,
  "proto": "tcp",
  "duration": 2.8133392333984375e-05,
  "orig_bytes": 0,
  "resp_bytes": 0,
HINT:
https://jqplay.org/
https://docs.jsonata.org/simple
https://stedolan.github.io/jq/manual/

`cat /home/garviel/conn.log | jq .|md5sum`
25ebedf7442e470eaaa48b5f7d5b96f4


JSON 2
File : /home/garviel/conn.log
This file is a conn.log made in Zeek (Bro) with data about TCP/IP connections.
Use jq to locate and count the unique originating endpoint IP addresses in the file.
HINT: Use this link to understand the JSON object’s attributes
Flag format: #

`jq '."id.orig_h"' conn.log | sort | uniq | wc -l`
31

JSON 3
File: /home/garviel/conn.log
This file is a conn.log made in Zeek (Bro) with data about TCP/IP connections.
Use jq to locate and count connections where the destination IP sent more than 40 bytes to the source IP.
Flag format: #

jq 'select(."resp_bytes" > 40) | ."resp_bytes"' conn.log |wc -l
177

Whut 3
Identify the Cyber Attack Technique that Balrog is trying on the machine.
HINT: https://attack.mitre.org/

Essetially, command F'd around Balrog adn found he was trying to do somethign with passwords, then just typed that into Attack matrix 
password credentials

XML 5
File: /home/garviel/output.xml
Select every IP address with open (in use) ports using XPATH queries and XPATH axes.
Pipe the result to md5sum for the flag
Sample Output (without piping to MD5SUM)

` xpath -q -e '//host/ports/port/state[@state="open"]/parent::*/@portid | //host/ports/port/state[@state="open"]/ancestor::ports/preceding-sibling::address/@addr' output.xml | md5sum`
ef0acbb3e9a376395d35c4ad9e9418ba