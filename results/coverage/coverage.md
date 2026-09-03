# Detection coverage matrix

ATT&CK Enterprise **19.2**, pinned and verified by SHA-256 (`logdet.attack`). Every technique name, tactic and declared log source below is ATT&CK's; only the keyword table that attaches a technique to a log message is authored.

## What the denominator is

A technique is *visible* when one of ATT&CK's own detection strategies has an analytic whose log source is one this system reads. Two readings, reported separately because they are not equally defensible:

- **strict** -- ATT&CK's syslog log sources (`linux:auth`, `linux:cron`, `linux:syslog`, `linuxsyslog`): **86** techniques.
- **wider** -- plus auditd's authentication events (`auditd:AUTH`, `auditd:USER_AUTH`, `auditd:USER_LOGIN`), which record the same events from a different subsystem: **89** techniques. This half is an authored claim, not ATT&CK's.

## Headline

| | count |
|---|---|
| Techniques the table maps | 11 |
| ...inside the strict universe | 1 of 86 |
| ...inside the wider universe | 2 of 89 |
| ...outside both (mapped from telemetry ATT&CK does not credit) | 9 |
| Mapped **and** observed on a corpus | 6 |
| Mapped but **never** observed | 5 |

## The matrix

| tactic | technique | mapped | ATT&CK log sources we read | synthetic | openssh | incidents |
|---|---|---|---|---|---|---|
| Initial Access / Persistence / Privilege Escalation / Stealth | `T1078` Valid Accounts | keyword | - | 311 | 364 | 3 |
| Initial Access / Persistence / Privilege Escalation / Stealth | `T1078.001` Valid Accounts: Default Accounts | **no** | `auditd:USER_LOGIN` | - | - | - |
| Initial Access / Persistence / Privilege Escalation / Stealth | `T1078.002` Valid Accounts: Domain Accounts | **no** | `linux:syslog` | - | - | - |
| Initial Access / Persistence / Privilege Escalation / Stealth | `T1078.003` Valid Accounts: Local Accounts | **no** | `auditd:USER_LOGIN`, `linux:auth` | - | - | - |
| Initial Access | `T1189` Drive-by Compromise | **no** | `linux:syslog` | - | - | - |
| Initial Access | `T1199` Trusted Relationship | **no** | `linux:syslog` | - | - | - |
| Initial Access | `T1200` Hardware Additions | **no** | `linux:syslog` | - | - | - |
| Initial Access | `T1566.003` Phishing: Spearphishing via Service | **no** | `linux:syslog` | - | - | - |
| Initial Access | `T1669` Wi-Fi Networks | **no** | `linux:syslog` | - | - | - |
| Execution / Persistence / Privilege Escalation | `T1053` Scheduled Task/Job | keyword | - | 0 | 0 | 0 |
| Execution | `T1059.004` Command and Scripting Interpreter: Unix Shell | **no** | `linux:syslog` | - | - | - |
| Execution | `T1059.005` Command and Scripting Interpreter: Visual Basic | **no** | `linux:syslog` | - | - | - |
| Execution | `T1059.006` Command and Scripting Interpreter: Python | **no** | `linux:syslog` | - | - | - |
| Execution | `T1059.007` Command and Scripting Interpreter: JavaScript | **no** | `linux:syslog` | - | - | - |
| Execution | `T1129` Shared Modules | **no** | `linux:syslog` | - | - | - |
| Execution | `T1203` Exploitation for Client Execution | **no** | `linux:syslog` | - | - | - |
| Execution | `T1204` User Execution | **no** | `linux:syslog` | - | - | - |
| Execution | `T1569` System Services | **no** | `linux:syslog` | - | - | - |
| Execution / Stealth | `T1574` Hijack Execution Flow | **no** | `linux:syslog` | - | - | - |
| Execution | `T1674` Input Injection | **no** | `linux:syslog` | - | - | - |
| Persistence / Privilege Escalation | `T1037.004` Boot or Logon Initialization Scripts: RC Scripts | **no** | `linux:syslog` | - | - | - |
| Persistence / Privilege Escalation | `T1098` Account Manipulation | keyword | - | 0 | 0 | 0 |
| Persistence | `T1136` Create Account | keyword | - | 3 | 0 | 2 |
| Persistence | `T1505` Server Software Component | **no** | `linux:syslog` | - | - | - |
| Persistence | `T1505.002` Server Software Component: Transport Agent | **no** | `linux:syslog` | - | - | - |
| Persistence / Stealth | `T1542.002` Pre-OS Boot: Component Firmware | **no** | `linux:syslog` | - | - | - |
| Persistence / Stealth | `T1542.003` Pre-OS Boot: Bootkit | **no** | `linux:syslog` | - | - | - |
| Persistence / Privilege Escalation | `T1546` Event Triggered Execution | **no** | `linux:syslog` | - | - | - |
| Persistence / Privilege Escalation | `T1547.013` Boot or Logon Autostart Execution: XDG Autostart Entries | **no** | `linux:auth` | - | - | - |
| Persistence | `T1668` Exclusive Control | **no** | `linux:syslog` | - | - | - |
| Privilege Escalation | `T1548` Abuse Elevation Control Mechanism | keyword | - | 6 | 0 | 2 |
| Stealth | `T1014` Rootkit | **no** | `linux:syslog` | - | - | - |
| Stealth | `T1036` Masquerading | **no** | `linux:syslog` | - | - | - |
| Stealth | `T1036.003` Masquerading: Rename Legitimate Utilities | **no** | `linux:syslog` | - | - | - |
| Stealth | `T1036.004` Masquerading: Masquerade Task or Service | **no** | `linux:cron` | - | - | - |
| Stealth | `T1036.006` Masquerading: Space after Filename | **no** | `linux:syslog` | - | - | - |
| Stealth | `T1070` Indicator Removal | keyword | - | 0 | 0 | 0 |
| Stealth | `T1211` Exploitation for Stealth | **no** | `linux:syslog` | - | - | - |
| Stealth | `T1480` Execution Guardrails | **no** | `linux:syslog` | - | - | - |
| Stealth | `T1480.001` Execution Guardrails: Environmental Keying | **no** | `linux:syslog` | - | - | - |
| Stealth | `T1564.005` Hide Artifacts: Hidden File System | **no** | `linux:syslog` | - | - | - |
| Stealth | `T1564.007` Hide Artifacts: VBA Stomping | **no** | `linux:syslog` | - | - | - |
| Stealth | `T1684.002` Social Engineering: Email Spoofing | **no** | `linux:syslog` | - | - | - |
| Defense Impairment | `T1685.003` Disable or Modify Tools: Modify or Spoof Tool UI | **no** | `linux:syslog` | - | - | - |
| Defense Impairment | `T1685.004` Disable or Modify Tools: Disable or Modify Linux Audit System Log | **no** | `linux:syslog` | - | - | - |
| Defense Impairment | `T1689` Downgrade Attack | **no** | `linux:syslog` | - | - | - |
| Credential Access | `T1110` Brute Force | keyword | `auditd:USER_LOGIN` | 78 | 457880 | 51 |
| Credential Access | `T1110.001` Brute Force: Password Guessing | **no** | `linux:syslog` | - | - | - |
| Credential Access | `T1110.002` Brute Force: Password Cracking | **no** | `linux:syslog` | - | - | - |
| Credential Access | `T1110.003` Brute Force: Password Spraying | **no** | `linux:syslog` | - | - | - |
| Credential Access | `T1110.004` Brute Force: Credential Stuffing | **no** | `linux:syslog` | - | - | - |
| Credential Access | `T1111` Multi-Factor Authentication Interception | **no** | `linux:syslog` | - | - | - |
| Credential Access | `T1552` Unsecured Credentials | **no** | `linux:syslog` | - | - | - |
| Credential Access | `T1552.001` Unsecured Credentials: Credentials In Files | **no** | `linux:syslog` | - | - | - |
| Credential Access / Collection | `T1557.003` Adversary-in-the-Middle: DHCP Spoofing | **no** | `linux:syslog` | - | - | - |
| Credential Access | `T1558` Steal or Forge Kerberos Tickets | **no** | `linux:syslog` | - | - | - |
| Credential Access | `T1621` Multi-Factor Authentication Request Generation | **no** | `auditd:AUTH` | - | - | - |
| Discovery | `T1016.001` System Network Configuration Discovery: Internet Connection Discovery | **no** | `linux:syslog` | - | - | - |
| Discovery | `T1018` Remote System Discovery | **no** | `linux:syslog` | - | - | - |
| Discovery | `T1046` Network Service Discovery | keyword | - | 0 | 0 | 0 |
| Discovery | `T1069.002` Permission Groups Discovery: Domain Groups | **no** | `linux:syslog` | - | - | - |
| Discovery | `T1087` Account Discovery | signal | - | n/a | n/a | 3 |
| Discovery | `T1087.002` Account Discovery: Domain Account | **no** | `linuxsyslog` | - | - | - |
| Discovery | `T1124` System Time Discovery | **no** | `linux:cron`, `linux:syslog` | - | - | - |
| Discovery | `T1201` Password Policy Discovery | **no** | `linux:syslog` | - | - | - |
| Discovery | `T1217` Browser Information Discovery | **no** | `linux:syslog` | - | - | - |
| Lateral Movement | `T1021` Remote Services | **no** | `linux:syslog` | - | - | - |
| Lateral Movement | `T1021.004` Remote Services: SSH | signal | `linux:syslog` | n/a | n/a | 3 |
| Lateral Movement | `T1021.005` Remote Services: VNC | **no** | `linux:syslog` | - | - | - |
| Lateral Movement | `T1210` Exploitation of Remote Services | **no** | `linux:syslog` | - | - | - |
| Lateral Movement | `T1534` Internal Spearphishing | **no** | `linux:syslog` | - | - | - |
| Collection | `T1039` Data from Network Shared Drive | **no** | `linux:syslog` | - | - | - |
| Collection | `T1114` Email Collection | **no** | `linux:syslog` | - | - | - |
| Collection | `T1125` Video Capture | **no** | `linux:syslog` | - | - | - |
| Command and Control | `T1132` Data Encoding | **no** | `linux:syslog` | - | - | - |
| Command and Control | `T1568` Dynamic Resolution | **no** | `linux:syslog` | - | - | - |
| Command and Control | `T1568.002` Dynamic Resolution: Domain Generation Algorithms | **no** | `linux:syslog` | - | - | - |
| Command and Control | `T1568.003` Dynamic Resolution: DNS Calculation | **no** | `linux:syslog` | - | - | - |
| Command and Control | `T1571` Non-Standard Port | **no** | `linux:syslog` | - | - | - |
| Command and Control | `T1572` Protocol Tunneling | **no** | `linux:syslog` | - | - | - |
| Command and Control | `T1573` Encrypted Channel | **no** | `linux:syslog` | - | - | - |
| Command and Control | `T1573.001` Encrypted Channel: Symmetric Cryptography | **no** | `linux:syslog` | - | - | - |
| Command and Control | `T1573.002` Encrypted Channel: Asymmetric Cryptography | **no** | `linux:syslog` | - | - | - |
| Exfiltration | `T1011.001` Exfiltration Over Other Network Medium: Exfiltration Over Bluetooth | **no** | `linux:syslog` | - | - | - |
| Exfiltration | `T1029` Scheduled Transfer | **no** | `linux:cron` | - | - | - |
| Exfiltration | `T1041` Exfiltration Over C2 Channel | keyword | - | 0 | 0 | 0 |
| Impact | `T1489` Service Stop | **no** | `linux:syslog` | - | - | - |
| Impact | `T1491` Defacement | **no** | `linux:syslog` | - | - | - |
| Impact | `T1491.001` Defacement: Internal Defacement | **no** | `linux:syslog` | - | - | - |
| Impact | `T1496.001` Resource Hijacking: Compute Hijacking | **no** | `linux:cron` | - | - | - |
| Impact | `T1499` Endpoint Denial of Service | **no** | `linux:syslog` | - | - | - |
| Impact | `T1499.002` Endpoint Denial of Service: Service Exhaustion Flood | **no** | `linux:syslog` | - | - | - |
| Impact | `T1499.003` Endpoint Denial of Service: Application Exhaustion Flood | **no** | `linux:syslog` | - | - | - |
| Impact | `T1529` System Shutdown/Reboot | **no** | `linux:syslog` | - | - | - |
| Impact | `T1565` Data Manipulation | **no** | `linux:syslog` | - | - | - |
| Impact | `T1565.002` Data Manipulation: Transmitted Data Manipulation | **no** | `linux:syslog` | - | - | - |
| Impact | `T1565.003` Data Manipulation: Runtime Data Manipulation | **no** | `linux:syslog` | - | - | - |
| Impact | `T1657` Financial Theft | **no** | `linux:syslog` | - | - | - |

### How to read a row

A `0` in a corpus column is a technique the table can emit and this corpus never triggered -- a claim with no evidence behind it, not a miss. The two signal-derived techniques (impossible travel, account enumeration) cannot appear in a line-level column at all: they exist only across an incident, so they are counted from a finished pipeline run when one is supplied and read `n/a` in a line-level column.

A sub-technique marked **no** under a parent this table does map is not a gap in detection so much as a gap in *resolution*: the table says T1110 Brute Force where ATT&CK distinguishes password guessing from spraying from stuffing, and nothing in an auth line separates them.

### Corpora

- **synthetic** -- 751 lines
- **openssh** -- 655147 lines
- **incidents** -- 94 incidents
