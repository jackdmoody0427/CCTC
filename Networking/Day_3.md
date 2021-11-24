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
