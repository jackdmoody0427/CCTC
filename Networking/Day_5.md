## CCTC Networking Day 5

- agenda


## Admin Data 

### CTFd info
| Field | Value | 
|-|-|
| Flag |  | 
| Name |  | 

## Day 5: Network Tunneling (part of Movement and Data Tranfer)

```
HOW TO TUNNEL
1. you got an ip
2. start with you scan.sh
3. if there are ports open, open nc banner grab to see what services are on those ports (to validate it)
4. if one of those ports are web or FTP, do a wget -r on it
5. if one is ssh or telnet, connect to it and do the passive scan (ip a, netstat -nltp, ls usr/share/cctc/)
6. determine if you need to do a dynamic then run scan.sh on that box’s network 
```
### SSH Port Forwarding
- creates channels using SSH-CONN protocol
- Allows for tunneling of other services through SSH
- Provides insecure service encryption

Syntax for local port forwarding:
```
ssh -p <optional alt port> <user>@<pivot ip> -L <local bind port>:<tgt ip>:<tgt port> -NT

or

ssh -L <local bind port>:<tgt ip>:<tgt port> -p <alt port> <user>@<pivot ip> -NT
```
Example (Create a local port [1111] on the local host that fowards to a target machine's port 80):
```
ssh student@10.2.0.2 -L 1111:3.233.98.14:80 -NT
or
ssh -L 1111:34.23.98.14:80 student@10.2.0.2 -NT
```

### SSH Local Port Forwarding Through a Local Port
```
ssh student@10.2.0.2 -L 1111:10.3.0.2:22 -NT
ssh student@localhost -p 1111 -L 2222:34.233.98.12:80 -NT
ssh student@localhost -p 2222 -L 3333:
firefox localhost:2222
```
- Creates an additional local port on the lcoal host that forwards to a target machine thorugh the previous channel created

I made an image file that shows this visually, but I can't figure out how to get it to load in markdown
![local port example](/home/usacys/Desktop/CCTC_Networking/local_tunnel_example.png "a title")

### SSH Dynamic Port Forwarding
Syntax
```
ssh -D <port> -p <alt port> <user>@<pivot ip> -NT
```
- proxychains default port is ***9050***
- Creates a dynamic socks4 proxy that interacts alone, or with a previously established remote or local port forward
- Allows the use of scripts and other userspace programs through the tunnel 

Example:
```
net1:
ssh student@10.2.0.2 -L 1111:10.3.0.2:22 -NT
ssh student@localhost -D 9050 -p 1111 -NT

proxychains curl ftp://www.onlineftp.ch
proxychains wget -r www.espn.com
proxychains ./scan.sh
proxychains ssh user@192.0.2.100 -p 2022
```

#### Demo Time
10.50.24.207 (10.0.0.103) pivot

10.0.0.101r
10.0.0.102
10.0.0.104

### SSH Remote Port Forwarding

Syntax
```
ssh -p <optional alt port> <user>@<remote ip> -R <remote bind port>:<tgt ip>:<tgt port> -NT

or

ssh -R <remote bind port>:<tgt ip>:<tgt port> -p <alt port> <user>@<remote ip> -NT
```

***
## CTFs
***
    Your Networking Class Identifier is N (Credentials will be net4_studentx for your student number)
    T  3 (Atropia) IP address is - 10.50.23.148
    T4 (Pineland) IP address is - 10.50.22.80 (Note - You can only telnet here to act as an insider, this will not be a routed path)
    START FLAG: dig_dug_dig_dug

    Tunnels Training - Task 2 Start
    Mission Command will provide the IP Addresses to the following targets:T3 T4

    The Flag to commence Task 2 will be provided by Mission Command

    Credentials for this environment are:

    netY_studentX:passwordX
    (netY = Networking Class Identifier & studentX = Student Number & passwordX = Student Number)


1. Local Practice: 


    T3 is the authorized initial pivot. Conduct passive recon on the Target T3, it appears to have access to the 10.3.0.0/24 subnet.

    Create a Local Port Forward from your Internet_Host to T3 targeting:
    ip: 10.3.0.27
    port: `HTTP``

    Identify the flag on Victoria's HTTP Server

- IH: `ssh net4_student11@10.50.23.148 -L 41101:10.3.0.27:80 -NT`
- seperate IH: `firefox localhost:41101`
- We are not interested in the possibilities of defeat. They do not exist. 


2. Dynamic Practice

    T3 is the authorized initial pivot

    Conduct passive recon on the Target T3, it appears to have access to the 10.3.0.0/24 subnet.

    Create a Dynamic Port Forward from Internet_Host to T3 then use proxychains to pull the flag.
    Target ip: 10.3.0.1

    Identify the flag on Cortina's FTP Serve

- IH: `ssh net4_student11@10.50.23.148 -D 9050 -NT`
- IH (new terminal): ` proxychains wget -r ftp://10.3.0.1`
- cd /10.3.0.1/
- cat flag.txt
- If I'm not back in five minutes, just wait longer!


3. Compromised
    Access to T4 has been provided via telnet. This is a Compromised host within Donovia

    Leverage this internal access to act as an insider threat throughout this Grorgan Cyber Training Operation. Conduct passive recon on this host and determine where the shared location for data relating to CCTC is on the machine.

- telnet 10.50.22.80
- ls -a
- cat hint.txt
- find / -iname "*flag*" 2>dev/null
- cat /usr/share/cctc/flag.txt
- Star Wars! 

4. Remote Practice

    T3 is the authorized initial pivot. Conduct passive recon on the Target T4, it appears to have access to the 10.2.0.0/25 subnet.

    Create a Remote Port Forward from T4 to T3 binding the source as one of Your authorized ports, from the Mission Prompt, targeting:
    ip: 10.2.0.2 port: HTTP

    Create a Local Port Forward from Internet_Host to T3 targeting the port you just established.
    When creating tunnels your authorized port ranges to utilize are NssXX (N = Net number, ss = Student Number and XX = is student assigned port number)

    Use curl or wget to pull the flag.
    Identify the flag on Mohammed Web Server

    1. Hint 1: 
    ```
    internet_host$ telnet {T4_float_ip}

    pineland$ ssh netX_studentX@{T3_inside_ip} -R NssXX:localhost:22 -NT
    ```
    - PL: `ssh net4_student11@10.3.0.10 -R 41103:localhost:22 -NT`
    2. Hint2:
    `internet_host$ ssh netX_studentX@{T3_float_ip} -L NssXX:localhost:NssXX -NT`
    - IH: `ssh net4_student11@10.50.23.148 -L 41104:localhost:41103 -NT`
    - New IH: `ssh net4_student11@localhost -p 41104 -D 9050 -NT`
    3. Great, now you have proxychains. Get access to 10.2.0.2
    - `proxychains wget 10.2.0.2`
    - `cat index.html.1`
    - Millennium Falcon!

5. Mohammed FTP
    
    T3 is the authorized intital pivot

    build a dynamic tunnel to T4 and conduct active recon to find teh 'mohammed' host. Identify the flag on Mohammed's FTP Server 
    - from your proxychains do : `proxychains wget 10.2.0.2`
    - cat flag.txt
    - You have accessed Mohammed's FTP server. The flag for is this important intel: I'm sorry, Dave. I'm afraid I can't do that-Hal, A Space Odyssey!

6. Cortina HTTP

    T3 is the authorized initital pivot

    Build a dynamic tunnel to T3 and conduct active recon to find the **Cortina** host. Identify the flag on Cortina's http server
    
    - `ssh net4_student11@10.50.23.148 -D 9050 -NT`
    - `proxychains wget -r 10.3.0.1`
    - cat index.html
    - You have accessed Cortina's official website. The flag is: With great power there must also come great responsibility!

7. Victoria FTP

    use your dynamic tunnel to t3 and conduct acive recon to find the victoria host

    - `proxychains wget -r ftp://10.3.0.27`
    - `cat flag.txt`
    - You have accessed Victoria's FTP server. The flag is "Invention, my dear friends, is 93% perspiration, 6% electricity, 4% evaporation, and 2% butterscotch ripple."

8. Mojave FTP

    You will need to conduct a search for lcues fo rthe network address of the mojave host. Identify the flag on Mojave's FTP server
    
    1. got on proxychains, did a scan for 10.2.0 from 1 to 254 from ports 21-23 80. 
    2. saw a new network 10.2.0.3
    3. Do a netstat -nltp 
    4. cat /usr/share/cctc/hint.txt
        - You have accessed the Atlantica government server. There is nothing interesting on this server, however, it used to have access to the 10.4.0.0/24 and 10.5.0.0/24 networks until the admins shut it down. Try to access those networks through another way.

***
CTF Part 2
***

0. Data collection

    T5 Ip = 10.50.32.104
    - socket.d/scan.sh
        
        scan on that ip and you'll see 23 is open
    - 23

1. Initial Ports

    What flag did you find on Net-SSH-01 after identifying it's additional open ports?

    The flag is hosted on a port that can not be seen from the outside.
    - IH: telnet 10.50.32.104
    - netstat -nltp, see port 80 is open
    - ip a 
    - make remote tunnel on SSH01: `ssh -R 41110:localhost:22 student@10.50.39.177 -NT`
    - make dynamic tunnel: `ssh net4_student11@localhost -p 41110 -D 9050 -NT`
    - proxychains wget -r 192.168.0.10
    - gimp flag
    - Do Not Throw Away Sausage Pizza

2. High Port 

    Net-SSH-03 has a flag being hosted on a high port, what coutnry is it referring to with the question? 
    - `proxychains scan from 192.168.0 from 1 to 254`
    - `proxychains nmap -sT 192.168.0.30`
    - `proxychains nc 192.168.0.30 4444`
    - Finland

3. Data Collection

    What is the IP address of net-ssh-02. It has HTTP & FTP open and has access to a single machine hidden behind it
    - scan the 192.168.0.20 for well known ports
    - wget ftp and http
    - get a hint.png
    - Ssh is using an alternate port above the well known ports. Use bannder grabbing to figure out so you pivot to the next machine that only this one has access to 
    - 192.168.0.20

4. find the flag on 20
    - used a wget for http and ftp
    - gives a flag.png
    - <> <> <> <>

5. 1st Pivot Access

    Find the hidden system behind net-ssh-02. What is the flag found on this isolated system

6. 2nd Pivot

    net-ssh-04 is another potential pivot
    to find this flag you need to identify a system hosting multiple flies over http

    -wget -r http then looking at flag
    - goodbye my friend you've been bad to me again (or something like that)

7. 2nd pivot access

    what other subnet does ssh-04 have access to?
    - look at hint in folder. 
    - 172.16.0.0/24

8. Inner Net
    
    what host IP address did you find (pas net-ssh-04) that you can login to using a well known port 

    - make new tunnel `ssh net4_student11@localhost -p 41110 -L 41140:192.168.0.40:5555`
    - dynamic `ssh net4_student11@localhost -p 41140 -D 9050 -NT`
    - scan new network
    - find 172.16.0.60

9. inner flag

    0x8100

10. Inner 80 Flag

    What is the answer to the flag found on a high port on Net-SSH-08?
    - proxychains telnet 172.16.0.60
    - `ssh -R 41150:localhost:22 net4_student11@192.168.0.40 -p 5555 -NT`

    - telnet tunnel to 6 instead to preserve proxychain: `ssh net4_student11@localhost -p 41140 -L 41160:172.16.0.60:23 -NT`
    