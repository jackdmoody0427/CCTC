## *CCTC OS NOTES DAY 3*

| Challenge Name | Flag |
| -- | -- | 
| linux_basics2 | start5309 | 
## Linux Essentials
Helpful website: https://file.groupme.com/v1/67490046/files/20f81927-eb53-440b-b65d-aae8a8e474da 
### 1: Commands, Arguments, and Help
BASH, much like PowerShell, does 4 things:
**BASH = Borne Again Shell**
1. Execute Commands with or without arguments
2. Redirect output from commands to a variety of locations (covered later)
3. Parse text(string) input and output into lines formatted as the user finds useful
4. Accept scripts to automate execution of all the above tasks

#### 1.1 Commands
These are like the normal apple/ Unix (pwd, ls, mkdir, etc)
- pwd (print working directory)
- hostname (operation station name)
- whoami (ensure you know who you are operating as, to avoid getting caught)
#### 1.2 Arguments
the -* such as ls -l, ls -a etc 
- -l shows files in directory
- -a shows hidden files
- -lh shows listof files in directory with timestamp 
- *cmd* --help (displays some documentation)

#### 1.3 Help
**commands for help in Linux**
- man *cmd* (manual for help)
- curl cht.sh/ *cmd* (shows most common used syntax examples)
- apt-get update (to get various updates)
- whatis *cmd* (quick definition of command)

#### 1.5 Redirection
Success and Failure Output from commands by default is sent to the terminal, but it can be redirected to other locations as well. Output from commands are assigned to a stream. There are three types of streams by default:

0. standard input 0 ←--- the default for a command arguments

1. standard output 1 ←--- the default for successful command output

2. standard error 2 ←--- the default for failed commands or errors

Redirection is done with the > character and a file name or a numbered stream.

Using a 1> redirect outpute to a file in bash
```
student:~$ directories=$(ls /) 
workstation21:$ echo $directories 1> thisisanewfile 
workstation21:$ cat thisisanewfile 
```
Using a 2> redirect errors to a location in bash
```
student:~$ ls bacon 
ls: cannot access 'bacon': No such file or directory

workstation21:$ ls bacon 2> errorfile 
workstation21:$ cat errorfile 
ls: cannot access 'bacon': No such file or directory
```

#### 1.6 Piping
Piping redirects standardoutput or 1 to standardinput or 0 to be processed as an argument to another command using the | character.

using piping filter command output using grep
```
student:~$ ls -Rlisa /etc | grep syslog 
1378 4 -rw-r--r--   1 root root 1358 Jan 30  2018 rsyslog.conf
1379 4 drwxr-xr-x   2 root root 4096 Feb  2 14:28 rsyslog.d
566  4 -rw-r--r--   1 root root 1550 Apr 24  2018 usr.sbin.rsyslogd
527  0 lrwxrwxrwx   1 root root   33 Jan 31  2020 usr.sbin.rsyslogd -> /etc/apparmor.d/usr.sbin.rsyslogd
535  0 -rw-r--r--   1 root root    0 Jan 31  2020 usr.sbin.rsyslogd
768  4 -rw-r--r--   1 root root  124 Jan 14  2018 rsyslog
958  4 -rwxr-xr-x   1 root root 2864 Jan 14  2018 rsyslog
1043 4 -rw-r--r--   1 root root  804 Jan 14  2018 rsyslog
1054 4 -rw-r--r--   1 root root  501 Jan 14  ## *CCTC OS NOTES DAY 3*

| Challenge Name | Flag |
| -- | -- | 
| linux_basics2 | starts5309 | 
## Linux Essentials
Helpful website: https://file.groupme.com/v1/67490046/files/20f81927-eb53-440b-b65d-aae8a8e474da 
### 1: Commands, Arguments, and Help
BASH, much like PowerShell, does 4 things:
**BASH = Borne Again Shell**
1. Execute Commands with or without arguments
2. Redirect output from commands to a variety of locations (covered later)
3. Parse text(string) input and output into lines formatted as the user finds useful
4. Accept scripts to automate execution of all the above tasks

#### 1.1 Commands
These are like the normal apple/ Unix (pwd, ls, mkdir, etc)
- pwd (print working directory)
- hostname (operation station name)
- whoami (ensure you know who you are operating as, to avoid getting caught)
#### 1.2 Arguments
the -* such as ls -l, ls -a etc 
- -l shows files in directory
- -a shows hidden files
- -lh shows listof files in directory with timestamp 
- *cmd* --help (displays some documentation)

#### 1.3 Help
**commands for help in Linux**
- man *cmd* (manual for help)
- curl cht.sh/ *cmd* (shows most common used syntax examples)
- apt-get update (to get various updates)
- whatis *cmd* (quick definition of command)

#### 1.5 Redirection
Success and Failure Output from commands by default is sent to the terminal, but it can be redirected to other locations as well. Output from commands are assigned to a stream. There are three types of streams by default:

0. standard input 0 ←--- the default for a command arguments

1. standard output 1 ←--- the default for successful command output

2. standard error 2 ←--- the default for failed commands or errors

Redirection is done with the > character and a file name or a numbered stream.

Using a 1> redirect outpute to a file in bash
```
student:~$ directories=$(ls /) 
workstation21:$ echo $directories 1> thisisanewfile 
workstation21:$ cat thisisanewfile 
```
Using a 2> redirect errors to a location in bash
```
student:~$ ls bacon 
ls: cannot access 'bacon': No such file or directory

workstation21:$ ls bacon 2> errorfile 
workstation21:$ cat errorfile 
ls: cannot access 'bacon': No such file or directory
```

#### 1.6 Piping
Piping redirects standardoutput or 1 to standardinput or 0 to be processed as an argument to another command using the | character.
2018 rsyslog
ls: cannot open directory '/etc/polkit-1/localauthority': Permission denied 
```

### 2: Automation and Logic

#### 2.1 For Loops
**For Loops** go by many names such as **Counting Loops** and **Interactive Loops**, but they all do the same thing ==execute a command or commands multiple times with a changing variable as an argument.== complete for loop will have the following: 
1. a collection of objects assigned to a variable
2. a variable that represents the value in the collection correctly being worked on
3. a command or commands that will execute with each value in the collection of variables
**You can seperate commands using a *;* to keep it in same line**

Ex: `for item in $objects; do echo $item; done`

#### 2.2 If Statements
If statements are logical expressions that compare objects against various tests to see if they evaluate as true or false. They are understood in a sentence form like this:

1. If this comparison is true, then do this
    - or
2. Else If this comparison is true, then do this
    - or
3. If nothing is true, do this

One line For loop and if statment: 
`for object in $objects; do if [ -d $object ]; then echo "$object is a directory"; else echo "$object is a file" ; fi ; done` 

#### 2.3 While Loops 
Basic while loop"
`while [ 1 -eq 1 ]; do echo "To Infinity and Beyond!"; done `

### 3: Linux Filesystem

#### 3.1 Linux Filesystem Hierarchy 
Every *Nix system from Ubuntu to Debian has a defined file system layout which is known as the Linux FSH (File System Hierarchy). It is a standard which defines the directory structure on all Linux distributions. What does that mean? Well, by default it defines:

1. The root directory of the file system /
    - Everything starts from this directory. Think of it as the doorway to the Linux Filesystem

2. Essential user commands in /bin
    - Contains commands like ls and echo which every user can use.

3. User Directories in /home
    - Contains directories for every non-root user on the system (with a home directory and login shell)

4. Host specific system configurations in /etc
    - Stands for everything configurable
    - Contains network configurations, system services(daemons), firewall configurations, etc.

5. Variable data files in /var
    - Contains all of the system logs by default

#### 3.2 Files and Folders

```
student@linux-opstation-kspt:~$ cd / 
student@linux-opstation-kspt:/$ 
student@linux-opstation-kspt:/$ls -l $PWD/* 
drwxr-xr-x   2 root root  4096 Feb  4  2020 /bin
drwxr-xr-x   3 root root  4096 Feb  4  2020 /boot
drwxr-xr-x  19 root root  3840 Jan 23 12:29 /dev
drwxr-xr-x 117 root root  4096 Feb 12 16:49 /etc
drwxr-xr-x   4 root root  4096 Jan 23 12:25 /home

student@linux-opstation-kspt:/$ cd /bin 

student@linux-opstation-kspt:/bin$ ls -ld $PWD/* 
-rwxr-xr-x 1 root root 1113504 Jun  6  2019 /bin/bash
-rwxr-xr-x 1 root root  716464 Mar 12  2018 /bin/btrfs

student@linux-opstation-kspt:/bin$ ls -l 
-rwxr-xr-x 1 root root 1113504 Jun  6  2019 bash
-rwxr-xr-x 1 root root  716464 Mar 12  2018 btrfs
-rwxr-xr-x 1 root root  375952 Mar 12  2018 btrfs-debug-tree
```
