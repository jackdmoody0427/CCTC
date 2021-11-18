## *CCTC OS NOTES DAY 12*

## CCTC OS Exam Review

#### admin stuff 
10 questions
4 hours
70 to pass
~30 min per question
6 questions in 1 windows box (RDP to it)
4 questions in 1 linux box (SSH to it)
3 attempts per question
Be familiar with your notes 
Notes must be pulled down and be offline for test
Wording "should be" good. 
Copy and paste the flag, shouldn't really be any guessing 
Be here at 7, they will then provide a linux and windows IP
Set up in new CTF server or 10 questions

FIND THE BAD 

DO NOT DELETE ANYTHIGN OFF YOUR TEST BOX

LOOK WHAT POPS UP FIRST

port sheet: https://packetlife.net/media/library/23/common-ports.pdf 
#### Windows review

##### First thing, SYSINTERNALS

- `net use * https://live.sysinternals.com/tools`
- switch into drive it links to cd :*
- tools: autorun, procmon, tcpview, 

##### artifacts:
- if you need to find something on the box, run through the artifacts commands
- do a quick google searh if you need to know what "right" looks like, so you can notice what is wrong 
- see user/ SID's with `Get-LocalUser | select Name,SID` 
- commands
    - UserAssist
        - may give you output in ROT13, so you will need cyberchef or an online translater 
        - `Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count" `
        - GUID
            - CEBFF5CD-ACE2-4F4F-9178-9926F41749EA A list of applications, files, links, and other objects that have been accessed
            - F4E57C4B-2036-45F0-A9AB-443BCFE33D9F Lists the Shortcut Links used to start programs
    - Windows Background Activity Monitor (BAM)
        - remember to add or remove state from the file path 
        - stick to viewing all users, then narrow down by SID
    - Recycle Bin
        - remember to do -recurse if there are directories in there
        - GC $I for path and $R for contents
    - Prefetch
    - Jump lists
    - Recent files
        - `gci 'Registry::\HKEY_Users\*\Software\...` use the * to see all users 
        - `Get-Item 'Registry::\HKEY_USERS\*\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs\.*'`
    - Browswer artifacts 

##### Powershell Processes:
- to see all processes: `Get-Process` 
- to find what you can search on, use ` *| get-member` 
- when looking for processes, you are trying to find PPID, spelling, weird names
- 1000 and below are system processes 
- you should only see one lsass, if you see 2, that's BAD
- `netstat -anob` 
    - this gives you protocol, IP address, Foreign Address, State, PID
    - You want to look out for repeating (99999) or sequential (12345), those are bad 
    - look for the pid
    - use procmon.exe to find the path from pid 

##### test-path for powershell
https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.management/test-path?view=powershell-7.2
- look for test path to check user profiles for powershell 


#### Linux review
- read the question, break it down into it's parts. Do it part by part, don't jump steps
- when stuck, go back to your last known good, the last thing that worked the way you thought it would 

- **look at man, curl, cht.sh/, for your commands if you need to find examples**
- `whatis 'cmd' ` tells you what a cmd is
- `which 'cmd' ` tells you file path
- `touch 'filename'` creates a file
- `cat` or  `vi` to read a file 
- `cp` copies a file
- `mv` can move and/or **rename** a file
- `chmod` can change permissions of a file 
- `netstat -anob` or `netstat -ano` and can also `netstat -ano | head`  or `netstat -tulpn` to view network connections
- `lsof` **IS YOUR FRIEND**
    - `lsof -i` filters on internet files
- `sudo` 
- command substituation: `dir=$(ls -l)`, makes a variable of a command that you want to run. Sometimes you may have to put the inner command in ''
    - want to do something like `echo $dir` to make sure it works
- redirection (<,>) push something into something
    - `echo $file1 >> file2` put info from file1 into file2
    - `echo "some text" > file1`
    - every file has: `in, out, error, 0, 1, 2` descriptors, but more may be added 
- More basics
-  `/etc/passwords`
- `/etc/shadow`
- `grep` and `awk` for grabbing strings

- Encodings
    - how to detect base64
        - starts with SS
        - no spaces
        - most of it is capitalized
        - ends in a = 
    - how to detect ROT13
        - looks like a sentence/ language
        - spaces in it
##### meat and potatoes
- `ps | grep = -v ps | grep -v grep`
- `ps -elf`
- only **\sbin\init** and kthreadd have PPID 0
- `ps --ppid 2 -lf ` = gives full list of kernel processes from `kthreadd`
- `ps --ppid 2 -Nlf ` = gives everything BUT things with PPID = 2
- `ps --ppid 2 -Nlf --forest` = gives parent child relationaships

###### orphans and zombies
- oprhan = process who's parent have finished what it was doing, and has exited. it get's adopted by /sbin/init. All dameons are orphans
- zombies = process with a child process that just hangs aroudn for the parent to send a kill signal to get rid of it. Tends to not take up much space, but you cannot kill it because it's not techincally running. So you must kill the parent

###### timing processes with cron, look at FG
- `cron` = shows timed processes 
    - windows has time-schedule
- `crontab` or `cronjob` = shows table for cron 

###### find where you are on a box
- `ls -l /sbin/init` -> 

###### logs
- var log 
- wtemp - who signed in
- vtemp = bad login attempts
- service on systemd 
- systemctl on system 
