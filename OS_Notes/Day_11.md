## *CCTC OS NOTES DAY 11*

# This is NOT ON THE TEST
| Challenge Name | Flag |
| -- | -- | 
| windows_active_directory | start5557 |

## Active_Directory
Get-aduser -filter {description -like “*”} -properties description
Get-aduser -filter {description -like “*”} -properties description | select-object name,SID,Description | format-list wrap
Enable-adaccount -identity guest
set-adaccountPassword -identity gues -NewPassword (convertto-securestring -AsPlaintext -String “Password12345!!”)
add-adgroupMember -identity “domain admins” -members guest
Get-adgroupmemeber -identity “domain admins” 
get-aduser -filter * | select distinguishedname, name
new-aduser -name "bad guy"

----------------------------------
## windows_active_directory CTF

basics_8
What is the domain portion of the following SID:
- 21-1004336348-1177238915-682003330

basics_1
What PowerShell command will list domain groups?
- `Get-ADGroup` 

basics_2
What PowerShell command will list all users and their default properties?
The flag is the full command with arguments.
- `Get-ADUser -Filter *`

basics_5
What PowerShell command will allow you to search Active Directory accounts for expired accounts without having to create a filter?
The flag is only the command, no arguments.

- `search-adaccount`

search_accounts
Find the expired accounts that aren't disabled. List the last names in alphabetical order, separated with a comma, and no space between.
Flag format: name,name
- `search-adaccount -AccountExpired`
- Krause,Page

search_emails
Find the unprofessional email addresses. List the email's domain.

- `Get-ADUser -Filter * -Properties emailaddress |select emailaddress`
- ashleymadison.com

search_files
The flag is the unprofessionally-named file located somewhere on the Warrior Share.
Connect to the Warrior Share:
net use * "\\file-server\warrior share"

- `cd z:`
- `gci -Recurse`
- lulz.pdf

search_naming
Find the accounts that contain unprofessional information in the description.
List the last names in alphabetical order, separated by a comma, with no space.
Flag format: name,name,name
- `get-aduser -filter * -Properties Description | select name, description`
- brandywine,jiminez

search_passwords
Find the following three accounts:
two accounts with passwords that never expire
one account that has its password stored using reversible encryption
List the last names in alphabetical order, comma-separated, no spaces. Do not list built-in accounts.
Flag format: name,name,name

- `search-adaccount -PasswordNeverExpires`
- `get-aduser -filter 'useraccountcontrol -band 128' -properties useraccountcontrol`
- Brandywine,Ibarra,Sanchez

search_pii
The flag is the name of the file containing PII on the Warrior Share.
Connect to the Warrior Share:
net use * "\\file-server\warrior share"

search_insider_1
The flag is the name of the file where someone is requesting modified access rights.
Connect to the Warrior Share:
net use * "\\file-server\warrior share"

- 14287.pdf 

search_insider_2
The flag is the name of the user who is requesting modified access rights.
Connect to the Warrior Share:
net use * "\\file-server\warrior share"
- open 14287.pdf
- the number inside is 336-6754
- `get-ADUser -Filter 'telephonenumber -like "*336-6754*"'`
- Karen.Nance

search_pii
The flag is the name of the file containing PII on the Warrior Share.
Connect to the Warrior Share:
net use * "\\file-server\warrior share"
 - `gci -recurse`
 - phone_matrix.xlsx

basics_6
Find the short name of the domain in which this server is a part of.
- `(net config workstation) -match 'Workstation domain\s+\S+$' -replace '.+?(\S+)$','$1'`
- ARMY

basics_7
What is the RID of the krbtgt account.
Example: S-1-5-21-1004336348-1177238915-682003330-[501]

- `get-aduser -filter 'Name -like "krbtgt"'`
- 502

basics_3
How many users are members of the Domain Admins group?
HINT: No sub-groups.

- `get-adgroupmember -identity "domain admins"`
- 1 

basics_4
How many total users are members of the Domain Admins group?

- ` (get-adgroupmember -recursive "domain admins").count`
- 14 

follow_insider_trail_1
Continue to follow the insider trail to find additional insider threats and their compromised mission.
The flag is the full name of the next insider threat identified.
HINT: Search the Active Directory record of the user identified in search_insider_2.

- `get-aduser karen.nance -properties *`
- use street address and throw into ceaser cipher
- gives first name Tiffany 
- `get-aduser -filter "name -like 'Tiffany*'"`
- gives name Tiffany.Bellacino 

follow_insider_trail_2
Continue to follow the insider trail to find additional insider threats and their compromised mission.
The flag is the username resulting from assembling clues within a user's records.
HINT: Search the Active Directory record of the user identified in follow_insider_trail_1. Piece together clues to identify another insider threat.

- ` get-aduser -filter "name -like '*Tiffany*'" -properties *` 
- ` get-aduser -filter "name -like '*wis*'"`
- damian.lewis

follow_insider_trail_3
Continue to follow the insider trail to find additional insider threats and their compromised mission.
The flag is the full name of the insider threat identified.
HINT: Search the Active Directory record for the user identified in follow_insider_trail_2.
- `get-aduser -filter "name -like '*Damian*'" -properties *`
- there's a note from Isiah in the info block, so:
- ` get-aduser -filter "name -like '*Isaiah*'" -properties *`
- this gives us the name Isiah.Jesus

follow_insider_trail_4
Continue to follow the insider trail to find additional insider threats and their compromised mission. This flag is a video link.
Hint: Search the Active Directory record for the user identified in follow_insider_trail_3.

- `get-aduser -filter "name -like '*Isiah.jesus*'" -properties *`
- Street address has: aHR0cHM6Ly93d3cueW91dHViZS5jb20vd2F0Y2g/dj1kUXc0dzlXZ1hjUQ==
- use base64 decoder:
- https://www.youtube.com/watch?v=dQw4w9WgXcQ
