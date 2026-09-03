# Narrative faithfulness

Corpus: `data/processed/killpoint/parsed.csv` | model: `phi3` | 193 narratives | median 3.6s each

A claim is **grounded** when the thing it names is in the exact prompt
that produced the narrative. Technique IDs are checked against the
incident's own matched list, not against the prompt text, because that
is the constraint under test.

## Headline

- Narratives with no ungrounded claim: **94/193**
- **Invented technique IDs: 119** of 197 technique mentions

## By claim kind

| kind | claims made | ungrounded | rate |
|---|---|---|---|
| `technique` | 197 | 119 | 60.4% (119/197) |
| `ip` | 193 | 5 | 2.6% (5/193) |
| `user` | 22 | 1 | 4.5% (1/22) |
| `time` | 142 | 34 | 23.9% (34/142) |
| `quantity` | 62 | 7 | 11.3% (7/62) |
| `placeholder` | 0 | 0 | n/a |

## By arm

The `no-technique` arm is the control and it is not synthetic: those
incidents matched nothing, so their prompt carries the *"No known
technique matched"* fallback and **any** technique ID in their
narrative is invented by definition.

| arm | narratives | fully faithful | technique mentions | invented |
|---|---|---|---|---|
| handed >=1 technique | 43 | 32/43 | 90 | **12** |
| handed none (control) | 150 | 62/150 | 107 | **107** |

## Ungrounded claims

| incident | arm | kind | claimed | in the narrative |
|---|---|---|---|---|
| 1 | control | `technique` | `T1058` | ...ent progresses through stages T1058 (Disconnect) within MITRE ATT... |
| 5 | grounded | `time` | `2:38 PM` | ....67 between December 10th and 2:38 PM UTC in the year 2015, as evid... |
| 10 | control | `technique` | `T1529` | ...by MITRE ATT&CK technique ID T1529 ("Preauthenticated Logon").... |
| 10 | control | `technique` | `T1529` | ...stages of Preauthentication (T1529) since the disconnect occurre... |
| 10 | control | `technique` | `T1529` | ...by MITRE ATT&CK technique ID T1529 ("Preauthenticated Logon"). H... |
| 11 | control | `technique` | `T1058` | ...ent progresses through stages T1058 (Fingerprinting and Reconnais... |
| 11 | control | `technique` | `T1059` | ...sociated with techniques like T1059.0 and T1058), it is likely st... |
| 11 | control | `technique` | `T1058` | ...h techniques like T1059.0 and T1058), it is likely still in an ea... |
| 12 | control | `technique` | `T1059` | ...ent progresses through stages T1059 (Fingerprint Spoof) and possi... |
| 12 | control | `technique` | `T1059` | ...fer that it's at least within T1059 and potentially moving toward... |
| 16 | control | `time` | `2015-12-13 09:47:18` | ...ry: - 1 anomalous events from 2015-12-13 09:47:18 to 2015-12-13 09:47:18 - Dist... |
| 16 | control | `time` | `2015-12-13 09:47:18` | ...s from 2015-12-13 09:47:18 to 2015-12-13 09:47:18 - Distinct usernames involved... |
| 20 | control | `technique` | `T1059` | ...his scenario is "Compromise" (T1059), which involves an attacker... |
| 21 | control | `technique` | `T1055` | ...e system after exploiting it (T1055: User Execution). However, du... |
| 23 | control | `technique` | `T1527` | ...T&CK techniques, specifically T1527 - Remote Service Account Expl... |
| 24 | control | `technique` | `T1570` | ...ough stages 'Reconnaissance' (T1570) and potentially 'Lateral Mov... |
| 25 | control | `technique` | `T1058` | ...ent progresses through stages T1058 (User Host Isolation) and pot... |
| 25 | control | `technique` | `T1046` | ...lated to the initial phase of T1046 (Client Discovery), as it inv... |
| 27 | control | `technique` | `T1058` | ...s incident aligns with stages T1058: Disconnect (Technique ID not... |
| 28 | control | `technique` | `T1027` | ...adversary tactics/techniques (T1027 - Remote System Interaction),... |
| 29 | control | `technique` | `T1059` | ...ent progresses through stages T1059 (Valid Account) and T1046 (Pa... |
| 29 | control | `technique` | `T1046` | ...ges T1059 (Valid Account) and T1046 (Pass-the-Hash/Double-Pwn). A... |
| 30 | control | `technique` | `T1568` | ...h the 'Reconnaissance' stage (T1568) of MITRE ATT&CK framework as... |
| 32 | control | `time` | `2015-12-14 08:37:45` | ...ry: - 1 anomalous events from 2015-12-14 08:37:45 to 2015-12-14 08:37:45... |
| 32 | control | `time` | `2015-12-14 08:37:45` | ...s from 2015-12-14 08:37:45 to 2015-12-14 08:37:45... |
| 33 | control | `technique` | `T1059` | ...ent progresses through stages T1059 (User Execution) as it involv... |
| 33 | control | `technique` | `T1059` | ...stage beyond User Execution (T1059).  3. Confidence level: Low -... |
| 35 | control | `technique` | `T1058` | ...ent progresses through stages T1058: Disconnect, as it involves a... |
| 35 | control | `time` | `20:05` | ...1. At precisely 20:05 on December 14, 2015, a user... |
| 39 | control | `technique` | `T1059` | ...ent progresses through stages T1059 (Failed Logon) for both conne... |
| 42 | control | `time` | `20:40` | ...1. At precisely 20:40 on December 15, 2015, a user... |
| 44 | control | `technique` | `T1056` | ...gns with Tactic: Termination (T1056), as it involves an abrupt te... |
| 44 | control | `time` | `20:34:35` | ...1. At precisely 20:34:35 on December 15, 2015, a disco... |
| 45 | control | `technique` | `T1019` | ...with Phase B: Establishment (T1019), where initial access is gai... |
| 45 | control | `technique` | `T1056` | ...ions into Phase C: Execution (T1056) if the user was in the midst... |
| 46 | control | `technique` | `T1058` | ...ent progresses through stages T1058 (Disconnect) from the MITRE A... |
| 46 | control | `time` | `2:31 AM` | ...1. At exactly 2:31 AM on December 16, 2015, a user... |
| 46 | control | `time` | `2:31 AM` | ...h such a command execution at 2:31 AM.... |
| 48 | control | `technique` | `T1058` | ...ent progresses through stages T1058 (Disconnect) from the MITRE A... |
| 48 | control | `time` | `20:29` | ...1. At precisely 20:29 on December 16, 2015, a user... |
| 49 | control | `technique` | `T1059` | ...ITRE ATT&CK framework (tactic T1059: Establish a Channel), as thi... |
| 50 | control | `technique` | `T1055` | ...ncident aligns primarily with T1055 - User Execution and potentia... |
| 51 | control | `time` | `7:06 PM` | ...1. At precisely 7:06 PM on December 16, 2015, a user... |
| 54 | control | `technique` | `T1567` | ...e "Pre-authentication" stage (T1567) as there is no indication in... |
| 57 | control | `technique` | `T1078` | ...aligns with 'Initial Access' (T1078) and potentially could be rel... |
| 57 | control | `time` | `2:02 AM` | ...1. At precisely 2:02 AM on December 17, 2015, an unau... |
| 59 | control | `technique` | `T1563` | ...s incident aligns with stages T1563 (Disconnect) from MITRE ATT&C... |
| 61 | control | `technique` | `T1567` | ...e incident progresses through T1567 - Authentication Failure, as... |
| 61 | control | `technique` | `T1567` | ...specific ATT&CK stage beyond T1567 for this incident's progressi... |
| 61 | control | `time` | `20:08` | ...1. At precisely 20:08 on December 18, 2015, an unau... |
| 62 | control | `technique` | `T1566` | ...ough stages 'Reconnaissance' (T1566) and potentially could be con... |
| 63 | control | `technique` | `T1047` | ...h the 'Reconnaissance' stage (T1047) but also touches upon aspect... |
| 63 | control | `ip` | `185.35.35.106` | ...specifically from IP address 185.35.35.106, and review firewall rulesets... |
| 64 | control | `technique` | `T1026` | ...with Tactic: Defense Evasion (T1026), where an attacker attempts... |
| 66 | control | `technique` | `T1078` | ...and protocols (Technique ID: T1078). Since there are no known te... |
| 66 | control | `technique` | `T1059` | ...rized attempts (Technique ID: T1059).... |
| 67 | control | `technique` | `T1057` | ...e incident aligns with stages T1057 (Remote Service Account Creat... |
| 67 | control | `technique` | `T1046` | ...like stage LOW_LEVEL_DNS_ENUM(T1046). However, without additional... |
| 70 | control | `technique` | `T1568` | ...ent progresses through stages T1568 - "Spearphishing: Web" and po... |
| 70 | control | `time` | `20:02:53` | ...1. At precisely 20:02:53 on December 19, 2015, a user... |
| 70 | control | `quantity` | `2` | ...re matched and there are only two events with one source... |
| 72 | control | `time` | `20:32` | ...1. At precisely 20:32 on December 20, 2015, a user... |
| 73 | control | `technique` | `T1046` | ...s and services (Technique ID: T1046 - Unauthorized Access).  3. C... |
| 73 | control | `technique` | `T1056` | ...d attack phase (Technique ID: T1056 - Exploit).... |
| 75 | control | `technique` | `T1367` | ...ent progresses through stages T1367 - Failed Authentication (Prea... |
| 77 | control | `technique` | `T1058` | ...ncident aligns primarily with T1058: Disconnect (D) as it involve... |
| 77 | control | `ip` | `192.168.5.10` | ...stinct source IPs (8): [IPv4] 192.168.5.10 to [IPv6] fc00... |
| 77 | control | `time` | `2015-12-20 23:47:19` | ...ry: - 2 Anomalous events from 2015-12-20 23:47:19 to 2015-12-20 23:47:19 - Dist... |
| 77 | control | `time` | `2015-12-20 23:47:19` | ...s from 2015-12-20 23:47:19 to 2015-12-20 23:47:19 - Distinct usernames involved... |
| 77 | control | `quantity` | `2` | ...idents.   Incident summary: - 2 Anomalous events from 2015-12-20 23:47:19 to 2... |
| 81 | control | `technique` | `T1058` | ...ctic 9: Privilege Escalation (T1058), as the anomaly suggests an... |
| 82 | control | `technique` | `T1093` | ...h stages of 'Reconnaissance' (T1093: Discoverable Service), and p... |
| 83 | control | `technique` | `T1055` | ...2. This incident aligns with T1055: Remote System Shutdown, as i... |
| 84 | control | `technique` | `T1056` | ...nses to find vulnerabilities (T1056), and potentially into a phas... |
| 85 | control | `technique` | `T1509` | ...ecifically techniques such as T1509 (Disconnect Session), which a... |
| 85 | control | `time` | `20:42` | ...1. At precisely 20:42 on December 21, 2015, a user... |
| 88 | control | `technique` | `T1058` | ...e incident aligns with stages T1058: Disconnect, and potentially... |
| 88 | control | `technique` | `T1059` | ...lifecycle such as execution (T1059), persistence, privilege esca... |
| 89 | control | `technique` | `T1568` | ...ent progresses through stages T1568 (Teardrop) since it involves... |
| 89 | control | `quantity` | `10` | ...e span of about two hours and ten minutes; both attempts were unsuccess... |
| 91 | control | `time` | `20:25` | ...1. At precisely 20:25 on December 22, 2015, a user... |
| 93 | control | `time` | `2015-12-23 09:47:28` | ...ry: - 1 anomalous events from 2015-12-23 09:47:28 to 2015-12-23 09:... |
| 93 | control | `time` | `2015-12-23` | ...s from 2015-12-23 09:47:28 to 2015-12-23 09:... |
| 96 | grounded | `technique` | `T1105` | ...s incident progresses through T1105 (Brute Force) and then potent... |
| 96 | grounded | `technique` | `T1105` | ...detected as per MITRE ATT&CK T1105 (Brute Force), then it's like... |
| 96 | grounded | `user` | `root` | ...rect credentials provided for user 'root'. This indicates that at least... |
| 98 | control | `technique` | `T1059` | ...ent progresses through stages T1059: Remote Service, and potentia... |
| 100 | control | `technique` | `T1059` | ...ent progresses through stages T1059: Malicious Software, and poss... |
| 100 | control | `technique` | `T1046` | ...icious Software, and possibly T1046: Exploit Compromise if we ass... |
| 101 | control | `technique` | `T1058` | ...ent progresses through stages T1058: Remote Service Provider - Un... |
| 102 | control | `technique` | `T1059` | ...ent progresses through stages T1059: Failed Logon and potentially... |
| 104 | control | `technique` | `T1048` | ...h the 'Reconnaissance' stage (T1048) and potentially touches upon... |
| 104 | control | `technique` | `T1056` | ...initial access ('Discovery', T1056), as it involves a user from... |
| 105 | control | `technique` | `T1587` | ...T&CK, specifically techniques T1587 and possibly others not ident... |
| 108 | control | `technique` | `T1568` | ...h stages T1 - Initial Access (T1568: Unauthorized Access) as it i... |
| 108 | control | `technique` | `T1053` | ...wards LAE - Lateral Movement (T1053: System Service Downgrade/Mis... |
| 113 | control | `technique` | `T1566` | ...ent progresses through stages T1566 (Command and Control) as it i... |
| 113 | control | `quantity` | `2` | ...nvolves communication between two hosts that could potentially be exc... |
| 114 | control | `technique` | `T1576` | ...ough stages 'Reconnaissance' (T1576) where an attacker might atte... |
| 114 | control | `technique` | `T1058` | ...ally into 'Lateral Movement' (T1058), if the disconnect was a res... |
| 116 | control | `technique` | `T1076` | ...s incident aligns with stages T1076 (Discovery) and possibly T156... |
| 116 | control | `technique` | `T1560` | ...1076 (Discovery) and possibly T1560/T1492 (Execution), as it invo... |
| 116 | control | `technique` | `T1492` | ...Discovery) and possibly T1560/T1492 (Execution), as it involves a... |
| 117 | control | `technique` | `T1078` | ...ent progresses through stages T1078 (Connection Hijacking) and po... |
| 120 | control | `technique` | `T1058` | ...e incident aligns with stages T1058: Disconnect (Pre-execution),... |
| 122 | grounded | `technique` | `T1137` | ...future brute force attempts (T1137 - Account Lockout), and condu... |
| 124 | control | `technique` | `T1055` | ...2. This incident aligns with T1055: Remote Service Hijacking and... |
| 126 | grounded | `technique` | `T1205` | ...of a broader attack campaign (T1205 - Lateral Movement).... |
| 127 | control | `technique` | `T1568` | ...stages 'Pre-Authentication' (T1568) as it happened before authen... |
| 130 | grounded | `technique` | `T1568` | ...ial lateral movement tactics (T1568 - Lateral Movement).... |
| 131 | control | `time` | `21:07` | ...1. At approximately 21:07 on January 1, an attempted re... |
| 133 | control | `technique` | `T1567` | ...ugh stages of Reconnaissance (T1567 - Failed DNS Resolution) and... |
| 134 | control | `technique` | `T1059` | ...ent progresses through stages T1059 (Remote Service Deception) an... |
| 134 | control | `technique` | `T1238` | ...exploitation techniques like T1238/T1247 if the user was trying... |
| 134 | control | `technique` | `T1247` | ...itation techniques like T1238/T1247 if the user was trying to gai... |
| 137 | control | `technique` | `T1587` | ...ent progresses through stages T1587 (Pass-the-Hash and Golden Tic... |
| 139 | grounded | `technique` | `T1109` | ...e incident progresses through T1109 (Brute Force) - Credential Ac... |
| 140 | control | `technique` | `T1046` | ...ough stages of Pre-execution (T1046 - Initial Access) as it invol... |
| 140 | control | `technique` | `T1235` | ...se), and finally Termination (T1235 - Teardown).  3. Confidence l... |
| 140 | control | `time` | `20:13:29` | ...1. At precisely 20:13:29 on January 2, 2016, a user fr... |
| 142 | control | `technique` | `T1568` | ...ent progresses through stages T1568 (Spearphishing Link) or poten... |
| 142 | control | `ip` | `192.168.1.10` | ...el - Distinct source IPs (3): 192.168.1.10, 172.16.17.32, 192.168.1.5  I... |
| 142 | control | `ip` | `172.16.17.32` | ...source IPs (3): 192.168.1.10, 172.16.17.32, 192.168.1.5  Incident events... |
| 142 | control | `ip` | `192.168.1.5` | ...: 192.168.1.10, 172.16.17.32, 192.168.1.5  Incident events (chronologic... |
| 142 | control | `time` | `2016-03-15` | ...ry: - 2 anomalous events from 2016-03-15 to 2016-03-15 - Distinct user... |
| 142 | control | `time` | `2016-03-15` | ...ous events from 2016-03-15 to 2016-03-15 - Distinct usernames involved... |
| 142 | control | `time` | `2016-03-15` | ...nt events (chronological): - [2016-03-15 0... |
| 142 | control | `quantity` | `2` | ...found.   Incident summary: - 2 anomalous events from 2016-03-15 to 2016-03-15... |
| 144 | grounded | `technique` | `T1055` | ...ugh stages of Initial Access (T1055), Privilege Escalation/Persis... |
| 145 | control | `technique` | `T1056` | ...ent progressed through stages T1056 - "Disconnect" as per MITRE A... |
| 147 | control | `quantity` | `3` | ...tedly disconnected after just three seconds without any prior actions or... |
| 149 | control | `technique` | `T1567` | ...ent progresses through stages T1567 - Initial Access, and potenti... |
| 149 | control | `technique` | `T1048` | ...ater-stage techniques such as T1048 - Privilege Escalation (if th... |
| 151 | control | `technique` | `T1059` | ...ent progresses through stages T1059 (Remote System Discovery) and... |
| 151 | control | `technique` | `T1068` | ...ystem Discovery) and possibly T1068 (User Execution), given the u... |
| 151 | control | `time` | `20:20` | ...1. At precisely 20:20 on January 3, a user from an... |
| 152 | grounded | `technique` | `T1075` | ...ent progresses through stages T1075 (Valid Accounts) for Initial... |
| 154 | control | `technique` | `T1059` | ...ent progresses through stages T1059 (Remote Service Deception) be... |
| 154 | control | `time` | `2016-01-04 03:57:18` | ...ry: - 1 anomalous events from 2016-01-04 03:57:18 to... |
| 155 | control | `technique` | `T1560` | ...ent progresses through stages T1560-003 and possibly aligns with... |
| 158 | control | `technique` | `T1567` | ...ent progresses through stages T1567 - Credential Stuffing and Fai... |
| 162 | control | `technique` | `T1059` | ...ent progresses through stages T1059 (Remote Service Connection) a... |
| 162 | control | `time` | `20:18` | ...1. At precisely 20:18 on January 4, an attempt was... |
| 163 | control | `technique` | `T1059` | ...ent progresses through stages T1059: Brute Force Credentials and... |
| 163 | control | `technique` | `T1047` | ...orce Credentials and possibly T1047: Exploitation of Weak, Defaul... |
| 164 | control | `technique` | `T1056` | ...ent progresses through stages T1056 - User Interaction, as it inv... |
| 164 | control | `time` | `20:25` | ...1. At precisely 20:25 on January 4, a user from an... |
| 164 | control | `time` | `21:00` | ...ew related system logs around 21:00-22:00 hours to identify any o... |
| 164 | control | `time` | `22:00` | ...ated system logs around 21:00-22:00 hours to identify any other a... |
| 166 | grounded | `technique` | `T1075` | ...ial targets for exploitation (T1075 - Reconnaissance). The failed... |
| 166 | grounded | `technique` | `T1055` | ...d credential access attempts (T1055 - Exploit Compromise). The di... |
| 166 | grounded | `technique` | `T1206` | ...credential stuffing attacks (T1206 - Account Discovery). Additio... |
| 167 | control | `technique` | `T1567` | ...h the 'Reconnaissance' stage (T1567) as it involves initial unaut... |
| 169 | control | `technique` | `T1560` | ...ent progresses through stages T1560-003 ("Disconnect Session") an... |
| 173 | control | `time` | `5:38 PM` | ...1. At precisely 5:38 PM on January 5th, a user initia... |
| 174 | control | `technique` | `T1055` | ...ncident aligns primarily with T1055: Remote Service Disruption as... |
| 174 | control | `technique` | `T1026` | ...TRE ATT&CK techniques such as T1026: Credential Dumping (if crede... |
| 175 | control | `technique` | `T1059` | ...h stages of 'Reconnaissance' (T1059) and potentially the initial... |
| 180 | control | `technique` | `T1058` | ...ent progresses through stages T1058 (Spearphishing Payload Delive... |
| 181 | control | `technique` | `T1599` | ...h stages of 'Initial Access' (T1599) and possibly 'Execution' if... |
| 184 | grounded | `technique` | `T1029` | ...for signs of compromise using T1029 (Account Discovery), review f... |
| 187 | control | `technique` | `T1562` | ...ing ('Account Discovery', ID: T1562).  3. Confidence level is Low... |
| 191 | control | `technique` | `T1566` | ...through stages 'Pre-session' (T1566 - Initial Access: User Host)... |
| 191 | control | `technique` | `T1071` | ...ost) and 'Post-exploitation' (T1071/T1083 - Privilege Escalation:... |
| 191 | control | `technique` | `T1083` | ...nd 'Post-exploitation' (T1071/T1083 - Privilege Escalation: Explo... |
| 192 | grounded | `quantity` | `5` | ...hort timeframe (approximately five minutes). The anomalous SSH logins su... |

## What this does not measure

Entity groundedness is a floor, not a proof of correctness. A
narrative can name only real IDs, IPs, users and counts and still tell
the wrong story about them -- a causal order the log does not support,
a confidence level nothing justifies, a recommended action the
evidence does not warrant. Judging that needs a human or an LLM judge,
and an LLM judge would put an unmeasured model inside the
measurement.

Generated by `logdet-faithfulness`. Model `phi3` at the pipeline's
own temperature, so numbers move a little run to run; the technique
column is the one that is supposed to be exactly zero.
