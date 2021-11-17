#### 01_windows_PS
regex_5
On the CTF user's desktop, count the number of words in words.txt that meet the following criteria:
a appears at least twice consecutively
and is followed immediately by any of the letters a through g
Example: aac...aaa...

- `cd C:\Users\CTC\Desktop\CTF\words.txt`
- `(gc .\words.txt | Select-String -pattern "aaa|aab|aac|aad|aae|aaf|aag").length`
- 357

#### 04_linux_basics2
Regular Expressions2
File: home/garviel/numbers
Use regular expressions to match patterns similar to an IP address.
The answer is the number/count of lines that match in the file.

- `grep -Ewo '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' numbers  |wc -l`
- 78

Regular Expressions3
File: home/garviel/numbers
Use regular expressions to match valid IP addresses. The flag is the number of addresses.
HINT: What are the valid numerical values of each octet in an IP address?

- `grep -Ewo "(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])" numbers |wc -l`
- 18

Regular Expressions4
File: home/garviel/numbers
Use regular expressions to match patterns that look similar to a MAC Address.
HINT: This is a loose match! Some of these results won't be true MAC addresses.
Flag format: ####

- `cat numbers | grep -P '^(?:(?:[A-Z]|\d){2}-){5}(?:[A-Z]|\d){2}$' | wc -l`
- 4877


Reformat
File: home/garviel/numbers
Use awk to print lines:
>= 420 AND <=1337Alias	larry.c.coates.civ
E-mail	larry.c.coates.civ@army.mil
Office	Ft Knox
Phone	(502) 613-7598
The flag is a SHA512 hash of the output.

- `awk 'NR>=420 && NR<=1337 { print }' numbers |sha512sum   `
- e62ff70d772ef0977f4f8fe1751fda5689ce1daf1fabc6d0cc49da234d02719986c0acb97f582166170a5a1f418e854602a5eb98c773655906a3f85440c37d39

Bash Logic1
Directory: home/garviel/Battlefield/
Interpret the Titan Controls to navigate the minefield and annihilate the target.
- AAAAA3AAA3AAAABAABAAAA

Regular Expressions5
File: home/garviel/numbers
Use regular expressions to find Locally Administered or Universally Administered Unicast MAC addresses.
Give the count of Locally and Universally Administersed MAC addresses as the answer.
HINT: What characters specifically define a Locally or Universally Administered Unicast MAC Address?

- `cat numbers | grep -P '^(?:(?:[A-F]|\d)[048C26AE]-)(?:(?:[A-F]|\d){2}-){4}(?:[A-F]|\d){2}$' | wc -l`
- 178

Bash Logic2
The flag resides in $HOME/paths... you just need to determine which flag it is. It sits next to a string matching the name of a $PATH binary on your system.
Hint: The correct binary is not echo

```import subprocess
# set of all possible flags
with open('/home/garviel/paths') as fp:
  lines = fp.readlines()
  for l in lines:
    flag = l.split()[0]
    cmds = subprocess.run(['whereis', flag], stdout=subprocess.PIPE).stdout.decode().split(':')[1]
    if cmds != '\n':
      print(l)
```
- Vrc0vw7ZUaLBpQp 

#### 05_windows_registry
Basics_9
What registry sub-key runs a single time, then deletes its value once the machine reboots? The flag is the full path, using PowerShell.
Flag format: FULL\PATH\ALL\CAPS

- `HKLM\SOFTWARE\MICROSOFT\WINDOWS\CURRENTVERSION\RUNONCE`

basics_13
What is the value inside of the registry sub-key from Basics_9?

- `reg query HKLM\SOFTWARE\MICROSOFT\WINDOWS\CURRENTVERSION\RUNONCE`

- HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS\CURRENTVERSION\RUNONCE
    McAfee    REG_SZ    C:\virus.exe

- c:\virus.exe

basics_16
What suspicious user profile, found in the registry, has connected to this machine?

- `gci 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\' ` 
- Hacker_McHackerson

basics_17
What suspicious wireless network, found in the registry, has this system connected to?

- `gci 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles\'`
- Terror_cafe_network

basics_15
Figure out the manufacturer's name of the only USB drive that was plugged into this server.

- `gi "HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR\"`
- SanDisk

basics_12
What is the value inside of the registry key that loads every time the "Student" user logs on?
- `Get-ItemProperty '.\S-1-5-21-4025152481-2360450962-471945012-1003\Software\Microsoft\Windows\CurrentVersion\Run\'`
- C:\botnet.exe

basics_14
What is the value inside of the registry key that loads a single time when the "Student" user logs on?
- `Get-ItemProperty '.\S-1-5-21-4025152481-2360450962-471945012-1003\Software\Microsoft\Windows\CurrentVersion\RunOnce\'`
- C:\worm.exe

## 07_windows_boot_process

init_10
Challenge only allows ONE attempt
Based on the boot loader from Init_9, which firmware are we using (BIOS or UEFI) in our environment?
- BIOS

remediate_1
The system is booting into safe mode. Identify the flag from the command-line output.
- `bcdedit`
- 1RF5Zgf9P

remediate_2
The system is booting into safe mode. Correct that, and reboot into the desktop. The flag is on the desktop.
- `bcdedit /deletevalue {current} safeboot`
- 76Drp6hB

remediate_3
Prevent the system restart using the command line, and then identify persistence mechanisms that are reverting the OS and boot loader configurations. The flag is in the same folder as the persistence mechanism.
- Run -> msconfig -> Services -> Hide all Microsoft Services
- AlsKdJfhG

remediate_4
Run PowerShell... if you can. Resolve PowerShell dependencies. HINT: Search the entire file system for the PowerShell .dll and copy it back to where it needs to go. It is hidden in China. The flag is a file in the directory with the .dll
- run powershell, find note, look for dll
- rfVBgtYHn

remediate_5
Once you fix and launch PowerShell, the console is changed to a custom layout. Figure out what file is causing this, read the file, and inspect the file that it is referencing.
- look at PS profiles
- C:\Users\Yin\AppData\Local\Temp\7f7....pdf
- 8B7da4v6Y

## 08_linux_boot_2

Grub_1
Identify the Linux Kernel being loaded by the Grub, by examining its configuration. Enter the command used by the Grub, and the full path to the Kernel, as the flag.
- `cat /boot/grub/grub.cfg`
- linux,/boot/vmlinuz-4.9.0-12-amd64

## 09_windows_processes

hidden_processes_1
There is malware on the system that is named similarly to a legitimate Windows executable. There is a .dll in the folder that the malware runs from. The flag is the name of the .dll.
- `Get-Item HKCU:\Software\Microsoft\Windows\CurrentVersion\Run`
- There is a file path that's "C:\Users\Public\Downloads\scvhost.exe'
- cd to that path and ls 
- libmingwex-0.dll

hidden_processes_2
You notice that there is an annoying pop up happening regularly. Investigate the process causing it. The flag is the name of the executable.
- mcafeefiretray.exe

hidden_processes_3
Determine what is sending out a SYN_SENT message. The flag is the name of the executable.
HINT: Use a Sysinternals tool.
- mcafeefiretray.exe

hidden_processes_4
Malware uses names of legit processes to obfuscate itself. Give the flag located in Kerberos’ registry sub-key.
HINT: Use Sysinternals tools.
Creds:
Machine: Workstation1 (RDP from Admin-Station)
  login: student
  password: password
- `.\autoruns.exe`
- navigate to services
- click Kerberos
- parameters
- you'll see the flag (76aGreX5)
OR
- `gci "registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kerberos\"`
