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
Socket

https://docs.python.org/3/library/socket.html

Struct

https://docs.python.org/3/library/struct.html

Sys

https://docs.python.org/3/library/sys.html

Errors

https://docs.python.org/3/tutorial/errors.html

Exceptions

https://docs.python.org/3/library/exceptions.html

### STREAM AND DATAGRAM SOCKET DEMOS
Follow along with the instructor on the Internet Host

