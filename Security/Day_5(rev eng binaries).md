
## CCTC Security Day 5
- agenda

exploit research = AORopen
## Admin Data

### CTFd info FOR UPDATED CTF
| Field | Value |
|-|-|
| Stack # | 10 |
| Username | JAMO-005-B |
| Password | YdY8vrRGOsRfhy6 |
| lin.internet | 10.50.21.133 |

## Day 4 Reverse Engineering Cont. Looking at binaries (entry and basic alg are most important problems for test)

### *IDA Demo*

in order to see strings and find "Enter key" in demo.exe

1. open file in ida and
2. view --> open subviews --> strings
3. Command f --> "keys"
4. double click "Enter keys:" on the xref line
5. this should take you to where in teh code that line is

in ida, for if statements, if it is a green path, that evals to true, if red,it evals to false

in ida, if you see somehting that ends in h, that is hex, and you can highlight it then click h to convert it to a decimal

***
***

1. Entry.exe

Situation:
Various teams have extracted binaries from Donovian development networks. Analyze the given binaries to find weaknesses and create signatures.

Provided:
compiled executable: (entry.exe)
source code: (entry.c)
Task: Run the executable with expected input and retrieve success message.
Method: disassemble the executable and follow the program’s execution to discover its functionality, and expected input.

Ensure that before you move on from this challenge that you have fully understood what you have done to disassemble and reverse engineer this binary and how it is related to the provided source code.

What is the key for this binary?

1. get onto pivot box and pull down entry.c and entry.exe using `wget 192.168.28.111/longTermStorage/entry.c`
2. push files from the pivot box to linux ops station `scp entry.c student@10.50.25.64:/home/student`
3. Go from linux ops station to windows op station `scp entry.exe student@192.168.65.10:/C:/Users/student/Desktop`
4. open up entry.c
5. 123@magicKey

2. Basic Algorithm

Situation:
Various teams have extracted binaries from Donovian development networks. Analyze the given binaries to find weaknesses and create signatures.

Provided:
compiled executable: (basic1.exe)
Task: Run the executable and retrieve a successful message using the binary's key.
Method: disassemble the executable and follow the program’s execution to discover its functionality, and expected input.

Add the value of all of the keys together. What is the MD5 hash of this sum?

1. Get file: `wget 192.168.28.111/longTermStorage/basic1.exe`
2. Scp from linux to lin ops station: `scp basic1.exe student@10.50.25.64:/home/student`
3. go from lin ops to windows: `scp basic1.exe student@192.168.65.10:/C:/Users/student/Desktop`
4. drop and drag file into ghidra
5. go to strings
6. look up "keys" --> double tap
click sub function
7. look at success and work backwards
8. Go through the functions and follow the logic until you find the decompiled c that can read that user inputs
9. look to see hwo to get local_8 (starting at 2) can add together to equal user input
10. tldr: 2-11 * 46 summed up, then md5su
11. 92 + 138 + 184 + 230 + 276 + 322 + 368 + 414 + 460 +506 = 2990
12. 79bc18f6cbd3b2290cbd69c190d62bc6

3. Software Doing Things 1

Situation:
Various teams have extracted binaries from Donovian development networks. Analyze the given binaries to find weaknesses and create signatures.

Provided:
compiled executable: (sdst.exe)
Task: Run the executable with expected input and retrieve success message.
Method: disassemble the executable and follow the program’s execution to discover its functionality, and expected input.

What is the MD5 hash of the key (specifically the value and not location) that the program required?

1. put file in ghidra and analyze
2. search strings for keys
3. find the enter key function, (fun_00401060) and look for file directories
4. in powershell, go to those files and cat them.
5. one is empty and the other is 8011, subtract 8011 from 17535 from the code
6. 9524 --> 4c8b12c6485fc0b4ebae47a30f49ca0c

4. Software Doing Things 2


Situation:
Various teams have extracted binaries from Donovian development networks. Analyze the given binaries to find weaknesses and create signatures.

Provided:
compiled executable: (sdst2.exe)
Task: Run the executable with expected input and retrieve success message.
Method: disassemble the executable and follow the program’s execution to discover its functionality, and expected input.

Show the instructor how you solved this to be awarded points.

1. windows registry key question. Open up registry editor and find the keyed3 registry and input a value
2. find that secret3.txt file and input same value
3. run program --> press enter
4. success

5. Software Doing Things 3 Part 1

Situation:

Various teams have extracted binaries from Donovian development networks. Analyze the given binaries to find weaknesses and create signatures. Provided:
compiled executable: (sdst3.exe)
Task: Run the executable with expected input and retrieve success message.
Method: disassemble the executable and follow the program’s execution to discover its functionality, and expected input.

What value determines successful execution of the binary?

1.
