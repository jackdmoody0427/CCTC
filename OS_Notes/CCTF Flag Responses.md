CCTF Flag Responses


## 01_windows_powershell

CimClasses2
To complete this challenge, find the description of the Lego Land service.
`Get-WmiObject win32_service | where-object {$_.Name -eq 'LegoLand'} | format-list Description`

Logic4
Count the number of files in the Videos folder in the CTF user's home directory.
` (Get-ChildItem Videos/ | measure-object).count`

Logic5
Find the only line that makes the two files in the CTF user's Downloads folder different.
`Compare-Object (get-content new.txt) (Get-Content old.txt)`

Logic6
The password is the 21st line from the top, in ASCII alphabetically-sorted, descending order of the words.txt file
`Get-Content .\words.txt | sort-object -Descending | select -Index 20`

Logic7
Count the number of unique words in words.txt, found on the CTF user's desktop, in the CTF folder
` (Get-Content .\words.txt | sort-object -Unique).count`

basics8
How many methods are available for the get-process cmdlet?
`(Get-Process | get-member -membertype method).count`

Logic9
Count the number of folders in the Music folder in the CTF user’s profile.
`(Get-ChildItem .\Music\ -recurse | Where-Object {$_.PSIsContainer }).count`

regex_2
Count the number of times, case-insensitive, gaab is listed in words.txt in the CTF folder on the CTF user's desktop
`(gc .\words.txt | Select-String -allmatches "gaab").count`

regex_3
Count the number of words, case-insensitive, with either a or z in a word, in the words.txt file on the CTF user's desktop
` ($content | Where-Object {$_ -match "[a,z]"}).count`

regex_4
Count the number of times az appears in the words.txt file on the CTF user's desktop.
`($content | Where-Object {$_ -match "az"}).count`


## 02_widows_powershell_profiles
Profiles1
Which PowerShell profile has the lowest precedence?
`current user, current host`

Profiles2
Which PowerShell profile has the highest precedence?
`all users, all hosts`

Profiles3
Which PowerShell variable stores the current user’s home directory
`$Home`

Profiles4
Which PowerShell variable stores the installation directory for PowerShell?
`$PSHOME`

Profiles5
Which PowerShell variable stores the path to the "Current User, Current Host" profile?
`$PROFILE`

Profiles6
What command would you run to view the help for PowerShell Profiles?

Profiles7
What command would tell you if there was a profile loaded for All Users All Hosts
`Test-Path -Path $PROFILE.AllUsersAllHosts`

# Day 2

## 05_windows_registry

basics_1
What registry hive contains all machine settings?
HKLM

basics_2
What registry hive contains all user settings?
HKU

basics_4cd 
hkey_current_user\hkey_users

## 06_windows_file_system
basics_7

```
C:\Windows\System32\drivers\etc> get-acl hosts |format-list
builtin\users
```

basics_9
Find the last five characters of the MD5 hash of the hosts file
`PS C:\Users\CTF\Favorites> cat .\README`

basics_10
There is a hidden directory in the CTF user's home directory. The directory contains a file. Read the file.

`ls -force` shows hidden files/ directories depending

basics_12
Find the ADS in CTF user's home, and read it

```
gci -recurse | % {gi $_.FullName -stream *} | where stream -ne ':$Data'
cat .\Documents\nothing_here:hidden
```
basics_13

`cat Microsoft.Powershell.Core\FileSystem::C:\Windows\PLA\not_anihc\"The Fortune Cookie:none"
Password: fortune_cookie` 

# Day 3 

## 04_Linux_Basics2
Linux Basics 2: 
For the ls command, what arguments, or switch options, will allow you to print human-readable file sizes in a long-list format?
	

Linux Basics 3: 
What character will pipe the standard output from
echo "I’m a plumber"
to another command, as standard input?


Linux Basics 4: 
What argument/switch option, when used with man, will search the short descriptions and man-page-names for a keyword that you provide?


LFS Heirarchy4: 
The absolute path to the directory which contains non-essential binaries that are accessible by standard users as well as root.


LFS Heirarchy5: 
An absolute path to a directory which contains binaries only accessible by the root user, or users in the root group.


**Linux Basics 5:** 
Search the man pages for the keyword digest. Then, use one of the binaries listed, to hash the string OneWayBestWay using the largest sha hash available.

`/usr/share/man/man1/sha512sum.1.gz`
`echo -n OneWayBestWay | sha512sum`

Linux Basics 6: 
This file contains encrypted contents. Identify its file type, then decode its contents.


LFS Hierarchy 7: 
Search the user home directories to find the file with the second-most lines in it.
The flag is the number of lines in the file.


Users and Groups2: 
Identify all members of the Lodge group. List their names in alphabetical order with a comma in between each name.


Users and Groups3: 
Find the user with a unique login shell.


Permissions1: 
Find the directory named Bibliotheca. Enter the absolute path to the directory.




Permissions2: 
Identify the number of users with valid login shells, who can list the contents of the Bibliotheca directory.



Permissions3: 
The permissions that user sejanus has on /media/Bibliotheca, in octal format.


Permissions5: 
Locate the file within /media/Bibliotheca that is modifiable by the only user that is part of the Chapter group, but not part of the Lodge group.


Permissions7: 
The file within /media/Bibliotheca where the owning group has more rights than the owning user.

Permissions 8:
Execute the file owned by the Guardsmen group in /media/Bibliotheca, as the owning user.
The flag is the code name provided after a successful access attempt.

Permissions4: 
The user tyborc is unable to access the directory:
/media/Bibliotheca/Bibliotheca_unus
Why? Identify the permission missing, in standard verb form.

You only have a single submission attempt for this challenge.
Locate the file in /media/Bibliotheca that Inquisitor Quixos has sole modification rights on.
The flag is the absolute path for the file.

Permissions9: 
Read the concealed file within the Bibliotheca

Permissions10: 
Find the warp and read its secrets for the answer.

Regular Expressions1: 
Using the commands ls and grep, identify the number of directories in /etc/ that end in .d

Regular Expressions2: 
File: home/garviel/numbers
Use regular expressions to match patterns similar to an IP address.
The answer is the number/count of lines that match in the file.
Get creative Get creative!

Regular Expressions3: 
File: home/garviel/numbers
Use regular expressions to match valid IP addresses. The flag is the number of addresses.
HINT: What are the valid numerical values of each octet in an IP address?

Regular Expressions4: 
File: home/garviel/numbers
Use regular expressions to match patterns that look similar to a MAC Address.
HINT: This is a loose match! Some of these results won't be true MAC addresses.
Flag format: ####

Reformat: File: home/garviel/numbers
Use awk to print lines:
>= 420 AND <=1337
The flag is a SHA512 hash of the output.

Reformat2:
File: home/garviel/connections
Use awk to create a separate CSV (comma separated value) file that contains columns 1-6.
The flag is an MD5 hash of the new file
Hint: Look at #fields on line 6 in the file to understand column layout.
Hint: This is a Zeek (formally known as Bro) connection log file in TSV format. Click This Link to learn about its formatting.
Sample Output

#separator \x09,,,,,
#set_separator,,,,,,
#empty_field,(empty),,,,
#unset_field,-,,,,
#path,conn,,,,
#open,2021-03-09-14-26-54,,,,
#fields,ts,uid,id.orig_h,id.orig_p,id.resp_h
#types,time,string,addr,port,addr
1615299704.748741,Cynd96jpqm760uz0k,192.168.242.216,60508,192.168.65.20,22
1615299962.756967,CFWnz12Wd2cXj3iSIe,fe80::c95c:6e92:5618:9df7,546,ff02::1:2,547
1615300118.087124,CuVCPTMljpoBDEuR1,192.168.65.10,62117,10.50.255.254,53
--- Trimmed ---

Bash Logic1: 
Directory: home/garviel/Battlefield/
Interpret the Titan Controls to navigate the minefield and annihilate the target.

Bash Logic2:  
The flag resides in $HOME/paths... you just need to determine which flag it is. It sits next to a string matching the name of a $PATH binary on your system.
Hint: The correct binary is not echo

Regular Expressions5: File: home/garviel/numbers
Use regular expressions to find Locally Administered or Universally Administered Unicast MAC addresses.
Give the count of Locally and Universally Administersed MAC addresses as the answer.
HINT: What characters specifically define a Locally or Universally Administered Unicast MAC Address?
Motivation

Bash Logic3: FILE: /home/garviel/Inquisition_Targets
Identify heresy by comparing the Inquisition_Targets file to members of the Guardsmen group.
HINT: Reformat and clean up the data before it is compared. awk and sort are your best friends!
The flag is the number of heretics on the system.
