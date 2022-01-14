## CCTC Security Day 1
- agenda

exploit research = AORopen
## Admin Data 

### CTFd info
| Field | Value | 
|-|-|
| Stack # | 10 | 
| Username | JAMO-005-B | 
| Password | YdY8vrRGOsRfhy6 |
| lin.internet | 10.50.36.131 |

## Day 1: Penetration Testing 

### **6 Phases of Pen Testing**

Phase 1: Mission Definition

    - Define mission goals and targets
    - Determine scop of mission
    - Define RoE

Phase 2: Recon

    - Information gathering about the target through public sources

Phase 3: Footprinting

    - Accumulate data through scanning and/or interaction with the target/ target resources

Phase 4: Exploitation & Initial Access

    - Gain intial foothold on network

Phase 5: Post-Exploitation

    - Establish persistence
    - Escalate privileges
    - Cover your tracks
    - Exfiltrate target data

Phase 6: Document Mission

    - Document and report mission details 

### Pen Test Reporting

- ## DOCUMENT EVERYTHING 
- IP addresses, usernames/ passwords, what worked, what didn't work, company domains, 
- Should be written out like a lab notebook. Want to include gritty details of expectations and realitites 
- Use things like screen captures 

***
***
## Day 1 Cont: Vulnerability and Exploitation Research

- Introduction to exploit research
    - transition from recon to weaponization
    - Leverage intell/data of network
    - "pairing" vulnerabilities to exploits
    - aligning exploits to operational objectives


websites for exploit research

    - Exploit DB
    - mitre CVE
    - NIST CVE

***
***
## Day 1 Cont: Scanning and Recon

### OSINT:
Data to collect
    
    - Web data: cached content, analytics, proxy web apps, CL interrogation
    - Sensitive Data: Business data, profiles, non-profits, business filings, historical/ public listings
    - Publicly Accessible: Physical addresses, phone numbers, email addresses, user names, search engine data, web and traffic cameras, wireless access point data
    - Social Media: twitter, facebook, linkedin, etc
    - Domain and IP data: DNS registration, IP address assignments, goelocation data, whois


## NMAP STUFF

- banner.nse
- http-enum.nse
- `nmap 10.5.36.201 -Pn --scrpt baner -p 1-1000`

## To set up a proxy to interact with webage from opstation 

- `ssh -X 10.50.32.96`
- `terminator`
- `firefox`
- set up dynamic port on pivot box: `ssh student@ip -D 9050`
- firefox
- settings
- lovslhody, 
- 

***
***
## CTF Challenges
### Exploit Research

1. Asa - webvpn

        - What CVE is associated with ASA 5500 if WebVPN is enabled on the interface and accessible?
        - 2018-0101

2. Asa - type

        - What type of vulnerability does this CVE address?
        - Remote code

3. Asa - score

        - The NIST assigned this CVE what base score? 
        - 10.0
4. Asa - poc

        - There is a proof of concept named crash that was created. What ID was assign to it by Offensive Security?
        - 43986

5. Windows - Printconfig

        - What recent Windows vulnerability dealt with a issue were the user could overwrite the PrintConfig.dll prior to 2020?
        - 20188840

6. Windows - Smart Person 

        - what is the name of the person that discovered the vulnerability
        - SanboxEscaper

7. Windows - Method

        - What function/method does this vulnerability take advantage of?
        - SchRpcSetSecurity

8. Initial Access

        - which technique is most used to gain initial access? 
        - phishing 
