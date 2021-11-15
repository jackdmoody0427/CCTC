### *CCTC OS NOTES DAY 10*


TEST TOPICS

windows registry
windows processes

linux persistence
linux processes 
linux services
powershell profiles, services, registry, "run and runonce"
# This is NOT ON THE TEST
| Challenge Name | Flag |
| -- | -- | 
| | start4477|

## Windows_Memory_Analysis

### 1 Intro to Memory Forensics
Memory forensics is a vital form of cyber investigation that allows an investigator to identify unauthorized and anomalous activity on a target computer or server. This is usually achieved by running special software that captures the current state of the system’s memory as a snapshot file, also known as a memory dump. Which an investigator can check both on and off site.

#### 1.1 What is memory forensics?
Memory forensics (also known as memory analysis) refers to the analysis of volatile data in a computer’s memory. Information security professionals conduct memory forensics to investigate and identify attacks or malicious behaviors that do not leave detectable tracks on hard drive data.

#### 1.2 Types of memory

| types of memory | what it does |
| -- | -- | 
|volatile memory | - non-persistent: requires power to maintain stores  info, immediate loss of data after power losse - examples: ram  |
|Non-volatile memory | -persistent: doesn't require a continuous power supply to retain the dta stored in computing decise -examples: HDD, USB|

#### 1.3 importance of memory forensics
Memory forensics can provide unique insights into runtime system activity, including open network connections and recently executed commands or processes. Often, critical data of attacks or threats will exist solely in system memory – examples include network connections, account credentials, chat messages, encryption keys, running processes, injected code fragments, and internet history which is non-cacheable. Memory contains any executable program – malicious or otherwise – making memory forensics critical for identifying otherwise obfuscated attacks.

- Data that has not stored on a disk is present in memory
- Deleted files or modified can be scraped from RAM and used as evidence or for timelining an attack.

**Examples**:
- Bash history writes to ~/.bash_history once the terminal session ends, but each command that has been ran during the current terminal session resides in RAM and can be viewed using the bash plugin
- If a user deletes ~/.bash_history , recovery of data is still possible.
- Volatility reads deleted or modified logs and scraped from memory using the mfind, mcat & mls plugins.

#### 1.4 Order of Volatility "the half-life of data"
this denotes how quickly various types of data dissapear from the system
**order of Volatility from most to least 


notes to download notepad++, but it's also in the FG 
```
PS C:\windows\system32> invoke-webrequest -uri "https://github.com/notepad-plus-plus/notepad-plus-plus/r
eleases/download/v7.8.8/npp.7.8.8.Installer.x64.exe" -outfile "C:\npp.7.8.8.Installer.x64.exe"
PS C:\windows\system32> cd C:\
PS C:\> Start-Process .\npp.7.8.8.Installer.x64.exe -ArgumentList '/S'
```
-------------------------------------------------

## Challenges
plugin_1
What Volatility plugin will dump a process to an executable file sample?
- procdump

plugin_2
What Volatility plugin will extract command history by scanning for _COMMAND_HISTORY?
- cmdscan

plugin_3
What Volatility plugin will show driver objects?
- driverscan

basics_2
What command do you run to find which memory profile to use with a memory image?
- memoryinfo

basics_1
What switch/argument will list all plugins for Volatility?
- -h

volatility_Data
What type of data is the most volatile?
Flag format: datatype,datatype
- registers,cache

basics_3
What is the 12th plugin listed in the Volatility help menu?
- cmdscan

basics_4
What profile do you use in conjunction with this memory image?
0zapftis.vmem
- `.\volatility_2.6_win64_standalone.exe -f "C:\Users\Public\Desktop\Memory\0zapftis.vmem" imageinfo` 
- WinXPSP2x86

malware_1
What command did the attacker type to check the status of the malware?
- ` .\volatility_2.6_win64_standalone.exe -f "C:\Users\Public\Desktop\Memory\0zapftis.vmem" cmdscan` 
- `sc query malware`

malware_2
What are the last 7 digits of the memory offset for the driver used by the malware?
- `.\volatility_2.6_win64_standalone.exe -f "C:\Users\Public\Desktop\Memory\0zapftis.vmem" driverscan`
- 1a498b8

malware_3
The process running under PID 544 seems malicious. What is the md5hash of the executable?

`Get-FileHash -Algorithm md5 .\executable.544.exe`

6CEE14703054E226E87A963372F767AA

malware_4
What remote IP and port did the system connect to?
Flag format: ip:port

- `.\volatility_2.6_win64_standalone.exe -f "C:\Users\Public\Desktop\Memory\0zapftis.vmem" connscan`
- 172.16.98.1:6666