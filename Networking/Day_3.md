## CCTC Networking Day 3

- agenda


## Admin Data 

### CTFd info
| Field | Value | 
|-|-|
| Flag | | 
| name |  | 

## Day 3: Packet Creation and Socket Programming

### SOCKET TYPES

- Stream Sockets - Connection oriented and sequenced; methods for connection establishment and tear-down. Used with TCP, SCTP, and Bluetooth.

- Datagram Sockets - Connectionless; designed for quickly sending and receiving data. Used with UDP.

- Raw Sockets - Direct sending and receiving of IP packets without automatic protocol-specific formatting.

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
