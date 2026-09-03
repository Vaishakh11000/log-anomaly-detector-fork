# Narrative faithfulness

Corpus: `/home/shiva/log-anomaly-detector-fork/data/processed/parsed.csv` | model: `phi3` | 94 narratives | median 3.4s each

A claim is **grounded** when the thing it names is in the exact prompt
that produced the narrative. Technique IDs are checked against the
incident's own matched list, not against the prompt text, because that
is the constraint under test.

## Headline

- Narratives with no ungrounded claim: **57/94**
- **Invented technique IDs: 47** of 142 technique mentions

## By claim kind

| kind | claims made | ungrounded | rate |
|---|---|---|---|
| `technique` | 142 | 47 | 33.1% (47/142) |
| `ip` | 61 | 1 | 1.6% (1/61) |
| `user` | 51 | 0 | 0.0% (0/51) |
| `time` | 74 | 8 | 10.8% (8/74) |
| `quantity` | 36 | 4 | 11.1% (4/36) |
| `placeholder` | 0 | 0 | n/a |

## By arm

The `no-technique` arm is the control and it is not synthetic: those
incidents matched nothing, so their prompt carries the *"No known
technique matched"* fallback and **any** technique ID in their
narrative is invented by definition.

| arm | narratives | fully faithful | technique mentions | invented |
|---|---|---|---|---|
| handed >=1 technique | 53 | 39/53 | 118 | **23** |
| handed none (control) | 41 | 18/41 | 24 | **24** |

## Ungrounded claims

| incident | arm | kind | claimed | in the narrative |
|---|---|---|---|---|
| 3 | control | `technique` | `T1569` | ...e incident aligns with stages T1569 (User Credential Use) where a... |
| 4 | control | `technique` | `T1597` | ...ent progresses through stages T1597 (Pass-the-Hash) as it involve... |
| 5 | control | `technique` | `T1503` | ...h the 'Reconnaissance' stage (T1503) as it starts with a user ses... |
| 7 | control | `time` | `2026-07-14 08:59:30` | ...y: - 10 anomalous events from 2026-07-14 08:59:30 to 2026-07-14 08:59:30 - Dist... |
| 7 | control | `time` | `2026-07-14 08:59:30` | ...s from 2026-07-14 08:59:30 to 2026-07-14 08:59:30 - Distinct usernames involved... |
| 7 | control | `quantity` | `10` | ...tation.   Incident summary: - 10 anomalous events from 2026-07-14 08:59:30 to 2... |
| 7 | control | `quantity` | `2` | ...IPs differing between events (2 distinct source IP... |
| 10 | grounded | `technique` | `T1056` | ...efense Evasion, Technique ID: T1056 - Account Lock).... |
| 14 | grounded | `technique` | `T1078` | ...n tactics like port scanning (T1078 - Port Scan) which often prec... |
| 14 | grounded | `technique` | `T1206` | ...calation from initial access (T1206 - Lateral Movement).... |
| 16 | grounded | `technique` | `T1108` | ...g used at this point in time (T1108 - Initial Access).  3. Confid... |
| 16 | grounded | `technique` | `T1058` | ...against brute force attacks (T1058 - Account Discovery), while a... |
| 18 | control | `technique` | `T1059` | ...ent progresses through stages T1059 (User Credential Dumping) and... |
| 19 | control | `technique` | `T1568` | ...ent progresses through stages T1568 - Unauthorized Access (Exploi... |
| 19 | control | `technique` | `T1568` | ...ly managed and authenticated (T1568).  3. Confidence level: Mediu... |
| 20 | control | `technique` | `T1059` | ...ent progresses through stages T1059 (Session Hijacking) and poten... |
| 20 | control | `technique` | `T1046` | ...other ATT&CK tactics such as T1046 (Pass the Hash), given that n... |
| 22 | control | `time` | `2026-07-15 09:30:45` | ...ry: - 1 anomalous events from 2026-07-15 09:30:45 to 2026-07-15 09:30:45... |
| 22 | control | `time` | `2026-07-15 09:30:45` | ...s from 2026-07-15 09:30:45 to 2026-07-15 09:30:45... |
| 24 | grounded | `technique` | `T1140` | ...xecution has taken place yet (T1140 - Privilege Escalation).  3.... |
| 24 | grounded | `technique` | `T1120` | ...n many cyberattack scenarios (T1120 - Validation of Authenticatio... |
| 24 | grounded | `technique` | `T1059` | ...ounts are targeted similarly (T1059 - Account Discovery).... |
| 26 | grounded | `technique` | `T1021` | ...f credential hijacking) using T1021 techniques for Credential Acc... |
| 30 | control | `technique` | `T1059` | ...ent progresses through stages T1059 (Discovery) where an unautner... |
| 30 | control | `technique` | `T1058` | ...ollowed by techniques such as T1058 (Privilege Escalation), which... |
| 31 | grounded | `technique` | `T1563` | ...TT&CK framework; specifically T1563 for Failed Logins which is pa... |
| 31 | grounded | `technique` | `T1563` | ...gain access into the system (T1563 - Failed Logins).   4. The re... |
| 31 | grounded | `technique` | `T1563` | ...r malicious intentions (e.g., T1563 - Failed Logins).... |
| 34 | grounded | `technique` | `T1109` | ...ent progresses through stages T1109 (Brute Force Credential Usage... |
| 38 | control | `technique` | `T1567` | ...ent progresses through stages T1567 (User Credential Access) and... |
| 38 | control | `quantity` | `24` | ...ecent actions within the past 24 hours using automated tools, while... |
| 41 | control | `technique` | `T1048` | ...ent progresses through stages T1048 (User Execution) and potentia... |
| 42 | control | `ip` | `192.168.1.10` | ...t]  Distinct source IPs (2): [192.168.1.10,... |
| 42 | control | `time` | `2026-07-16 05:30:00` | ...:  - 10 anomalous events from 2026-07-16 05:30:00 to 2026-07-16 05:45:00  Disti... |
| 42 | control | `time` | `2026-07-16 05:45:00` | ...s from 2026-07-16 05:30:00 to 2026-07-16 05:45:00  Distinct usernames involved... |
| 42 | control | `quantity` | `10` | ...ivity.   Incident summary:  - 10 anomalous events from 2026-07-16 05:30:00 to 2... |
| 45 | grounded | `technique` | `T1078` | ...oader network reconnaissance (T1078 - Reconnaissance).  4. The re... |
| 45 | grounded | `technique` | `T1206` | ...d or compromised in the past (T1206 - Account Evasion).... |
| 46 | grounded | `technique` | `T1207` | ...have allowed such an attack (T1207 - Account Lock).... |
| 48 | grounded | `technique` | `T1568` | ...al harvesting or enumeration (T1568 - Spearphishing Link).  3. Co... |
| 48 | grounded | `technique` | `T1560` | ...credential stuffing attempts (T1560 - Failed Logins).  4. Recomme... |
| 48 | grounded | `technique` | `T1563` | ...TCHA challenges (MITRE ATT&CK T1563 - Account Manipulation).... |
| 50 | control | `technique` | `T1569` | ...ion techniques (Technique ID: T1569 - Privilege Escalation). 2. T... |
| 50 | control | `technique` | `T1569` | ...ation attempts (Technique ID: T1569 - Privilege Escalation). 3. C... |
| 51 | control | `technique` | `T1059` | ...sses through the "Pre" stage (T1059: Initial Access) since it rep... |
| 53 | control | `technique` | `T1568` | ...ent progresses through stages T1568 - Command and Scripting Inter... |
| 58 | control | `technique` | `T1538` | ...ent progresses through stages T1538 (Administrator Rights Enumera... |
| 61 | control | `technique` | `T1059` | ...specifically techniques like T1059 (Lateral Movement) and potent... |
| 62 | grounded | `technique` | `T1207` | ...further brute force attempts (T1207).... |
| 66 | control | `technique` | `T1560` | ...ent progresses through stages T1560 (User Execution) since Carol... |
| 68 | control | `technique` | `T1568` | ...progresses through stages 1 (T1568 - Admin Shell Discovery) and... |
| 68 | control | `technique` | `T1047` | ...ery) and potentially stage 3 (T1047 - Privilege Escalation), as i... |
| 73 | control | `technique` | `T1567` | ...s incident aligns with stages T1567 - Command and Scripting Inter... |
| 73 | control | `time` | `20:08` | ...1. At precisely 20:08 on July 17, 2026, an individu... |
| 76 | control | `technique` | `T1569` | ...ent progresses through stages T1569 (System Account Manipulation)... |
| 81 | grounded | `technique` | `T1105` | ...g used in subsequent attacks (T1105).  4. Recommended next action... |
| 82 | grounded | `technique` | `T1209` | ...linked back to this incident (T1209 - Lateral Movement).... |
| 83 | control | `time` | `22:31` | ...1. At precisely 22:31 on July 18, an unusual event... |
| 89 | grounded | `technique` | `T1105` | ...ident progresses through the 'T1105: Brute Force' (Credential Acc... |
| 93 | control | `technique` | `T1567` | ...ent progresses through stages T1567 (System Administration) as th... |

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
