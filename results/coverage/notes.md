# Reading the coverage matrix

*Interpretation, kept out of the generator on purpose (same rule as the
bake-off notes): a generator that writes conclusions is scripting the
narrative. `coverage.md` and `coverage.json` are regenerated with
`uv run logdet-coverage --incidents data/processed/incidents.json`; this file is
written by hand.*

## The headline is small, and it should be

ATT&CK 19.2 carries 858 techniques. This system maps **11**. Of the 86
techniques ATT&CK's own detection strategies say are visible from a Linux
syslog stream, we map **1** (T1021.004 Remote Services: SSH); widening to
auditd's authentication events adds one more (T1110 Brute Force).

That is not a bug in the report and not modesty. It is what a small,
deliberately-authored keyword table over one log source looks like when it is
measured against the whole enterprise matrix instead of against itself.

## The interesting number is 9, not 1

**Nine of the eleven techniques the table maps sit outside both denominators** —
ATT&CK does not credit our telemetry with detecting them at all. T1110 Brute
Force is the clearest case: ATT&CK's Linux analytic for it reads
`auditd:USER_LOGIN`, not syslog, and its four sub-techniques (password guessing,
cracking, spraying, credential stuffing) are the ones tagged `linux:syslog`.

Two readings, and both belong in the write-up:

- **In our favour.** ATT&CK's log-source labels describe where *its* published
  analytics look, not the set of things a log line can prove. sshd's
  `Failed password` records the same event auditd's `USER_LOGIN` records. So
  the strict figure understates.
- **Against us.** Nine rows mean the table asserts techniques from telemetry a
  third party would not accept as evidence for them. That is the same class of
  objection §1b removed from the rule baseline, surfacing one layer up in
  enrichment.

The report prints both denominators and never merges them, because choosing one
is choosing the answer.

## Five of eleven are claims with no evidence behind them

| technique | synthetic | OpenSSH (655,147) | incidents |
|---|---|---|---|
| T1110 Brute Force | 78 | **457,880** | 51 |
| T1078 Valid Accounts | 311 | 364 | 3 |
| T1548 Abuse Elevation Control | 6 | 0 | 2 |
| T1136 Create Account | 3 | 0 | 2 |
| T1087 Account Discovery *(signal)* | n/a | n/a | 3 |
| T1021.004 Remote Services: SSH *(signal)* | n/a | n/a | 3 |
| **T1041, T1046, T1053, T1070, T1098** | **0** | **0** | **0** |

The last row is the finding worth acting on: five techniques — exfiltration,
network service discovery, scheduled tasks, indicator removal, account
manipulation — have **never fired on either corpus**. Their keywords (`scp`,
`wget`, `crontab`, `useradd`, `shred`) describe traffic an sshd auth log does
not contain. They are not wrong; they are unexercised, and a coverage claim
that counts them counts decoration.

T1110's 457,880 matched lines on OpenSSH — 70% of the corpus — is the same fact
`corpus_openssh.py` was built around: most of that log *is* internet brute
force, which is why the kill-point background is constructed rather than taken
raw.

## What this does not measure

Whether the mapping is *correct* on the lines it does match. This counts
matches, not true positives; the keyword table can attach T1548 to any line
containing `sudo`, including a benign one. Precision of the enrichment layer is
a separate, unmeasured question — it needs labelled technique-level ground
truth, which no corpus here has.
