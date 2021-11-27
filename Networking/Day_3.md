## CCTC Networking Day 3

- agenda


## Admin Data 

### CTFd info
| Field | Value | 
|-|-|
| Flag | raw_packet_start | 
| name |  | 

## Day 3: Packet Creation and Socket Programming

### SOCKET TYPES

- Stream Sockets - Connection oriented and sequenced; methods for connection establishment and tear-down. Used with TCP, SCTP, and Bluetooth.

- Datagram Sockets - Connectionless; designed for quickly sending and receiving data. Used with UDP.

- Raw Sockets - Direct sending and receiving of IP packets without automatic 
col-specific formatting.

### USER SPACE VS. KERNEL SPACE SOCKETS
- User Space Sockets
    - Stream Sockets
    - Datagram Sockets

- Kernel Space Sockets
    - Raw Sockets

### SOCKET CREATION AND PRIVILEGE LEVEL
- User Space Sockets - The most common sockets that do not require elevated privileges to perform actions on behalf of user applications.

- Kernel Space Sockets - Attempts to access hardware directly on behalf of a user application to either prevent encapsulation/decapsulation or to create packets from scratch, which requires elevated privileges.

### NETWORK PROGRAMMING WITH PYTHON3
Network sockets primarily use the Python3 Socket library and socket.socket function.

import socket
  s = socket.socket(socket.FAMILY, socket.TYPE, socket.PROTOCOL)
  
#### THE SOCKET.SOCKET FUNCTION
Inside the socket.socket. function, you have these arguments, in order:

socket.socket([*family*[,*type*[*proto*]]])
family constants should be: AF_INET (default), AF_INET6, AF_UNIX

type constants should be: SOCK_STREAM (default), SOCK_DGRAM, SOCK_RAW

proto constants should be: 0 (default), IPPROTO_RAW

### PYTHON3 LIBRARIES AND REFERENCES

| Field | Value | 
|-|-|
| Socket |https://docs.python.org/3/library/socket.html | 
| Struct | https://docs.python.org/3/library/struct.html | 
| Sys | https://docs.python.org/3/library/sys.html | 
| Errors| https://docs.python.org/3/tutorial/errors.html | 
| Exceptions | https://docs.python.org/3/library/exceptions.html |


### STREAM AND DATAGRAM SOCKET DEMOS
Follow along with the instructor on the Internet Host

streamSEND.py
```
#!/usr/bin/python3

'''
Start of socket demo 24NOV2021
'''
import socket 

#you can also do s= socket.socket() due to AF_INET and SOCK_STREAM being defaults

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

#define IP address and port pair

ipaddr = "127.0.0.1"
port = 54321

#call on socket object 'connect(address)'
s.connect((ipaddr,port))

#to send a string as a bytes-like object, add the prefix b to the string. \n is used to go the the next line (hit enter)

s.send(b'Hello\n')

#it is recommended that the buffersize used with teh recvfrom is a power of 2 and not a very large number of bits

response, conn = s.recvfrom(1024) #use socket object 'recvfrom(buffersize)'

#In order to recieve a message that is sent as a bytes-like object you must decode into utf-8(default)

s.close()

```

## Raw IPv4 Sockets

- Raw Socket scripts must include the IP header and the next headers.
- Requires guidance from the "Request for Comments" (RFC)to follow header structure properly.
    - RFCs contain technical and organizational documents about the Internet, including specifications and policy documents.
- See RFC 791, Section 3 - Specification for details on how to construct an IPv4 header.

### RAW SOCKET USE CASE
- Testing specific defense mechanisms - such as triggering and IDS for an effect, or filtering
- Avoiding defense mechanisms
- Obfuscating data during transfer
- Manually crafting a packet with the chosen data in header fields

### RAW SOCKET Demo
1. make script (rawIP.py)
```
#!/usr/bin/python3

#For building the socket 
import socket

#for system level commands
import sys

#For doing an array in the TCP Command
import array

# For establishing the packet structure (used later on), this will allow direct acceess to the methods and functions in the struct module

from struct import * 

#Create raw socket

#This is the exception handling part
try:
    s =socket.socket(socket.AF_INET, socket.SOCK_RAW,socket.IPPROTO_RAW)

    packet = ''

    src_ip = '10.1.0.2'
    dst_ip = '10.3.0.2'

    #Lets add the IPv4 header info

    ip_ver_ihl = 69                      #This is putting the decimal conversion of 0x45 fro Version and Internet header length
    ip_tos = 0                           #This combines DSCP and ECN fields
    ip_len = 0                           #The kernel will fill in the actual lenght of the packer
    ip_id = 12345                        #Thsi set the IP Identification of the packet
    ip_frag = 0                          #This sets the fragmentation to offf
    ip_ttl = 64                          #This determines the TTL of the packet when leaving the machine
    ip_proto = 6                         #This sets the IP Protocol to 6 (TCP) so additional headers are required
    ip_check= 0                          #The kernel will fill in th echecksum for the packet
    ip_srcadd = socket.inet_aton(src_ip) #inet_aton(string) will ocnvert an IP address to a 32 bit binary number
    ip_dstadd = socket.inet_aton(dst_ip) #inet_aton(string) will convert an IP address to a 32 bit binary number

    ip_header= pack('!BBHHHBBH4s4s',ip_ver_ihl,ip_tos,ip_len,ip_id,ip_frag,ip_ttl,ip_proto,ip_check,ip_srcadd,ip_dstadd)

    #B = 1 byte (Byte)
    #H = 2 bytes (Half word)
    #4s = 4 bytes (word - converted from string to binary)

    #Add message to go with packet
    message = b'This be da message yuh'
    #update our packet variable with our payload(message)
    packet = ip_header + message

    #Now we gotta send it!
    s.sendto(packet,(dst_ip,0))

except socket.error as msg:
    print(msg)
    sys.exit()
```
3. open wireshark 
4. apply filter: `ip.dst == 10.3.0.2`

**Instructor Version of script after lunch**
```
#--IMPORT MODULES
import socket 		# For building the socket
import sys 		# For system level commands
from struct import * 	# For packet structure and allow direct access to methods/functions in struct module.

#--CREATE RAW SOCKET
# When building out raw sockets it is recommended to perform exception handling.
# Errors are considered exceptions in python, and can either break the program, or just make it not work as intended.  This can happen if
# The way we try to avoid those errors is by handling exceptions using 'try' and 'except' for the type of error
# Here is an example of error handling for an IPv4 raw socket:
try:
  s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
except socket.error as msg:
    print(msg)
    sys.exit()

packet = ''

src_ip = "10.1.0.2"
dst_ip = "10.3.0.2"

#--BUILD IPv4 HEADER
ip_ver_ihl = 69				# This is putting the decimal conversion of 0x45 for Version and Internet header Length
ip_tos = 0				# This combines the DSCP and ECN fields
ip_len = 0				# The kernel will fill in the actual length of the packet
ip_id = 12345				# This sets the IP Identification for the packet
ip_frag = 0				# This sets fragmentation to off
ip_ttl = 64				# This determines the TTL of the packet when leaving the machine
ip_proto = 6				# This sets the IP protocol to 6 (TCP) so additional headers are required
ip_check = 0				# The kernel will fill in the checksum for the packet
ip_srcadd = socket.inet_aton(src_ip)	# inet_aton(string) will convert an IP address to a 32 bit binary number
ip_dstadd = socket.inet_aton(dst_ip)	# inet_aton(string) will convert an IP address to a 32 bit binary number

#--PACK IPv4 HEADER
ip_header = pack('!BBHHHBBH4s4s' , ip_ver_ihl, ip_tos, ip_len, ip_id, ip_frag, ip_ttl, ip_proto, ip_check, ip_srcadd, ip_dstadd)
# ! allows us to format the packet to be in the correct order (network byte order)
# B = 1 byte (Byte)
# H = 2 bytes (Half Word)
# 4s = 4 bytes (Word - Converted from string to binary)

#--ADD A MESSAGE
message = b'This is a message'

#--PUT IT ALL TOGETHER
packet = ip_header + message

#--SEND THE PACKET
s.sendto(packet, (dst_ip,0))
```
## RAW IPV4 TCP SOCKET DEMO 
```
#--IMPORT MODULES
import socket 		# For building the socket
import sys 		# For system level commands
from struct import * 	# For packet structure and allow direct access to methods/functions in struct module.
import array		# For doing an array in the TCP checksum

#--CREATE RAW SOCKET
# When building out raw sockets it is recommended to perform exception handling.
# Errors are considered exceptions in python, and can either break the program, or just make it not work as intended.  This can happen if
# The way we try to avoid those errors is by handling exceptions using 'try' and 'except' for the type of error
# Here is an example of error handling for an IPv4 raw socket:
try:
  s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
except socket.error as msg:
    print(msg)
    sys.exit()

packet = ''

src_ip = "10.1.0.2"
dst_ip = "10.3.0.2"

#--BUILD IPv4 HEADER
ip_ver_ihl = 69				# This is putting the decimal conversion of 0x45 for Version and Internet header Length
ip_tos = 0				# This combines the DSCP and ECN fields
ip_len = 0				# The kernel will fill in the actual length of the packet
ip_id = 12345				# This sets the IP Identification for the packet
ip_frag = 0				# This sets fragmentation to off
ip_ttl = 64				# This determines the TTL of the packet when leaving the machine
ip_proto = 6				# This sets the IP protocol to 6 (TCP) so additional headers are required
ip_check = 0				# The kernel will fill in the checksum for the packet
ip_srcadd = socket.inet_aton(src_ip)	# inet_aton(string) will convert an IP address to a 32 bit binary number
ip_dstadd = socket.inet_aton(dst_ip)	# inet_aton(string) will convert an IP address to a 32 bit binary number

#--PACK IPv4 HEADER
ip_header = pack('!BBHHHBBH4s4s' , ip_ver_ihl, ip_tos, ip_len, ip_id, ip_frag, ip_ttl, ip_proto, ip_check, ip_srcadd, ip_dstadd)
# ! allows us to format the packet to be in the correct order (network byte order)
# B = 1 byte (Byte)
# H = 2 bytes (Half Word)
# 4s = 4 bytes (Word - Converted from string to binary)

#--BUILD TCP HEADER
tcp_src = 54321		# source port
tcp_dst = 7777		# dest port
tcp_seq = 454		# sequence number
tcp_ack_seq = 0		# tcp ack sequence number
tcp_data_off = 5	# data offset specifying the size of tcp header * 4 which is 20
tcp_reserve = 0		# the 3 reserve bits + ns flag in reserve field
tcp_flags = 0		# tcp flags field before the bits are turned on
tcp_win = 65535		# maximum allowed window size reordered to network order
tcp_chk = 0		# tcp checksum which will be calculated later on
tcp_urg_ptr = 0		# urgent pointer only if urg flag is set

# Combined the left shifted 4 bit tcp offset and the reserve field
tcp_off_res = (tcp_data_off << 4) + tcp_reserve

# TCP flags by bit starting from right to left
tcp_fin = 0		# Finished
tcp_syn = 1		# Synchronization
tcp_rst = 0		# Reset
tcp_psh = 0		# Push
tcp_ack = 0		# Acknowledgement
tcp_urg = 0		# Urgent
tcp_ece = 0		# Explicit Congestion NOtification Echo
tcp_cwr = 0		# Congestion Window Reduced

# Combine the tcp flags by left shifting the bit locations and adding the bits together
tcp_flags = tcp_fin + (tcp_syn << 1) + (tcp_rst << 2) + (tcp_psh << 3) + (tcp_ack << 4) + (tcp_urg << 5) + (tcp_ece << 6) + (tcp_cwr << 7)

#--PACK THE TCP HEADER
# The ! in the pack format string means network order
tcp_hdr = pack('!HHLLBBHHH', tcp_src, tcp_dst, tcp_seq, tcp_ack_seq, tcp_off_res, tcp_flags, tcp_win, tcp_chk, tcp_urg_ptr)
# B = 1 byte (Byte)
# H = 2 bytes (Half Word)
# L = 4 bytes (32 bit Word as an integer)

#--ADD A MESSAGE
message = b'Hello! Is it me you are looking for?'

#--PSEUDO HEADER FIELDS
src_address = socket.inet_aton(src_ip)
dst_address = socket.inet_aton(dst_ip)
reserved = 0
protocol = socket.IPPROTO_TCP
tcp_length = len(tcp_hdr) + len(message)

# Pack the pseudo TCP header
ps_hdr = pack('!4s4sBBH', src_address, dst_address, reserved, protocol, tcp_length)
ps_hdr = ps_hdr + tcp_hdr + message

# Create a function to calculate the checksum before we call on it
def checksum(data):
        if len(data) % 2 != 0:
                data += b'\0'
        res = sum(array.array("H", data))
        res = (res >> 16) + (res & 0xffff)
        res += res >> 16
        return (~res) & 0xffff

# Combine the things
tcp_chk = checksum(ps_hdr)

# PACK ALL THE THINGS.
# Pack the tcp header to fill in te correct checksum - remember checksum is NOT in network byte order
tcp_hdr = pack('!HHLLBBH', tcp_src, tcp_dst, tcp_seq, tcp_ack_seq, tcp_off_res, tcp_flags, tcp_win) + pack('H', tcp_chk) + pack('!H', tcp_urg_ptr)

#--PUT IT ALL TOGETHER
packet = ip_header + tcp_hdr +  message

#--SEND THE PACKET
s.sendto(packet, (dst_ip,0))
```
-------------------------------------

## Flags
Gorgas Socket Manipulation (GPM)
XX OCT 2023
Start Time: 1300
Duration: 4 hours

Type of Operation: Socket Programming for Datagram, IP, TCP

Objective: Gorgas Cyber Forces are preparing for an upcoming mission and have requested assistance with packet manipulation. They need to send custom message to allied forces throughout the region; however, they currently do not have anyone available that understands how. Using Python your team is required to complete each of the following tasks (Specific details for each task are identified in the challenge):

Utilize sockets and craft a custom Raw IPv4 Sockets

Utilize sockets and craft a custom Raw IPv4 TCP Sockets

Utilize sockets and craft a custom Datagram Socket Message Sender

Utilize sockets and craft a custom Stream Socket Message Sender

Click Here to view there current progress on the scripts

Tools/Techniques: Python3, Wireshark/TCPDump

Scenario Credentials: FLAG = raw_packet_start

Prior Approvals: Prior to completing each of the four tasks, ensure you understand the various items of the script you developed.

Scheme of Maneuver:
> Linux Workstations:
→ T1: INTERNET_HOST
-→ T2: BLUE_DMZ_Host

Target Section:

T1
Hostname: INTERNET_HOST
IP: PROVIDED FLOAT IP
OS: Linux
Creds: PROVIDED CREDENTIALS
Last Known SSH Port: 22
PSP: none
Malware: none
Action: Send a Datagram Socket Message to this host

T2
Hostname: BLUE_DMZ_Host
IP: 172.16.1.15
OS: unknown
Creds:unknown
Last Known SSH Port: unknown
PSP: Unknown
Malware: Unknown
Action: Send a Stream Socket Message to this host

------------------
## CTFs
- AddressFamilies
What are the 3 Address Families associated with the python3 socket module?
    - socket.AF_Unix, socket.AF_INET, socket.AF_INET6
- Connections
What are the two socket functions called to open a connection and to disconnect from that connection?
    - socket.connect(), socket.close()

- Header Preperation
- What python3 library function is utilized to combine the various pieces of your raw socket packet into network order?
        - Very FEW TRIES LEFT 

- Missing Data
- What must be manually created with raw sockets that stream and datagram sockets creates for you?
    - 6 tries left 
- Sending UDP
What function within the socket module allows you to Send data to a socket, while not already being connected to a remote socket?
    - socket.sendto()
    
- Transport Layer Sockets
Provide an example of the two required items needed to be set in order to send a Datagram or Stream socket? (excluding any of the socket.socket functions)
    - ipaddr, port
    
 - Object
 When sending data across a connection, what must a string be converted to before being sent due to encoding?
    - 3 tries remaining

