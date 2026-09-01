# Drain3 template inventory

Corpus: `/home/shiva/log-anomaly-detector-fork/data/external/SSH.log`

Read-only inspection, run before any detection code reads a mined
template id. Nothing here was fitted, scored, or tuned.

## Corpus

| | |
|---|---|
| Lines read | 655,147 |
| Lines parsed | 655,147 (100.00%) |
| Distinct regex templates (`template_message`) | 5,669 |
| Distinct mined templates (Drain3) | 45 |

Drain3 settings: `sim_th=0.4`, `depth=4`, `max_children=100`, `max_clusters=None`, `parametrize_numeric_tokens=True`, plus IP/PORT/PID/HEX masking (see `logdet/templating.py`).

## Does the vocabulary settle?

Cluster count against lines read. A count still climbing at the end of
the corpus means something variable is leaking into the templates,
which would give a sequence model a vocabulary that never repeats.

| Lines read | Clusters |
|---:|---:|
| 1,000 | 22 |
| 5,000 | 24 |
| 10,000 | 24 |
| 25,000 | 24 |
| 50,000 | 29 |
| 100,000 | 32 |
| 250,000 | 43 |
| 500,000 | 43 |
| 655,147 | 45 |

## The 30 largest templates

| id | lines | share | template |
|---:|---:|---:|---|
| 10 | 140,768 | 21.49% | `Failed password for <*> from <IP> port <PORT> ssh2` |
| 9 | 140,701 | 21.48% | `pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= <*> <*>` |
| 7 | 68,958 | 10.53% | `Connection closed by <IP> [preauth]` |
| 8 | 46,642 | 7.12% | `Received disconnect from <IP>: 11: <*> <*> <*>` |
| 14 | 37,963 | 5.79% | `PAM service(sshd) ignoring max retries; <*> > 3` |
| 12 | 37,298 | 5.69% | `Disconnecting: Too many authentication failures for <*> [preauth]` |
| 13 | 37,029 | 5.65% | `PAM <*> more authentication <*> logname= uid=0 euid=0 tty=ssh ruser= <*> <*>` |
| 11 | 36,967 | 5.64% | `message repeated <*> times: [ Failed password for <*> from <IP> port <PORT> ssh2]` |
| 6 | 20,271 | 3.09% | `Failed <*> for invalid user <*> from <IP> port <PORT> ssh2` |
| 4 | 19,852 | 3.03% | `pam_unix(sshd:auth): check pass; user unknown` |
| 1 | 18,909 | 2.89% | `reverse mapping checking getaddrinfo for <*> [<IP>] failed - POSSIBLE BREAK-IN ATTEMPT!` |
| 2 | 14,581 | 2.23% | `Invalid user <*> from <IP>` |
| 3 | 14,581 | 2.23% | `input_userauth_request: invalid user <*> [preauth]` |
| 5 | 14,356 | 2.19% | `pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= <*>` |
| 18 | 1,289 | 0.20% | `PAM <*> more authentication <*> logname= uid=0 euid=0 tty=ssh ruser= <*>` |
| 24 | 952 | 0.15% | `fatal: Read from socket failed: Connection reset by peer [preauth]` |
| 19 | 932 | 0.14% | `error: Received disconnect from <IP>: <*> <*> <*> <*> <*> <*> <*> [preauth]` |
| 15 | 838 | 0.13% | `Did not receive identification string from <IP>` |
| 17 | 595 | 0.09% | `Received disconnect from <IP>: 11: <*> <*> <*> <*> <*> <*>` |
| 28 | 497 | 0.08% | `Address <IP> maps to <*> but this does not map back to the address - POSSIBLE BREAK-IN ATTEMPT!` |
| 20 | 182 | 0.03% | `Accepted password for <*> from <IP> port <PORT> ssh2` |
| 21 | 182 | 0.03% | `pam_unix(sshd:session): session opened for user <*> by (uid=0)` |
| 22 | 182 | 0.03% | `pam_unix(sshd:session): session closed for user <*>` |
| 16 | 177 | 0.03% | `error: Received disconnect from <IP>: 3: com.jcraft.jsch.JSchException: Auth <*> [preauth]` |
| 29 | 108 | 0.02% | `Received disconnect from <IP>: 11: [preauth]` |
| 44 | 92 | 0.01% | `Received disconnect from <IP>: 11: Normal Shutdown, Thank you for playing [preauth]` |
| 38 | 87 | 0.01% | `Received disconnect from <IP>: 11: <*> <*> <*> [preauth]` |
| 42 | 60 | 0.01% | `Received disconnect from <IP>: 11: disconnect [preauth]` |
| 31 | 14 | 0.00% | `Bad protocol version identification <*> from <IP> port <PORT>` |
| 33 | 13 | 0.00% | `Invalid user from <IP>` |

Those 30 templates cover 99.99% of all matched lines.

## The tail

- Templates matching exactly one line: **5** (11.11% of templates, 0.00% of lines)
- Templates matching 5 lines or fewer: **8** (17.78% of templates)

A rare template is not automatically an attack, but it is where the
rare events are, so a large singleton count is what a sequence model
would spend most of its vocabulary on.

## Agreement with the existing regex templater

The two templaters are compared per line: which regex template the
line got, and which mined cluster. Perfect agreement would be one
cluster per regex template and vice versa.

- Regex templates split across more than one mined cluster: **0**
- Mined clusters covering more than one regex template: **25**

**Merges are the direction that costs detection signal** -- two
distinguishable events becoming one id. Splits cost sharpness, not
distinctions.

### Largest merges (one mined cluster, several regex templates)

| id | lines | regex templates | mined template |
|---:|---:|---:|---|
| 10 | 140,768 | 28 | `Failed password for <*> from <IP> port <PORT> ssh2` |
| 9 | 140,701 | 104 | `pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= <*> <*>` |
| 8 | 46,642 | 4 | `Received disconnect from <IP>: 11: <*> <*> <*>` |
| 12 | 37,298 | 11 | `Disconnecting: Too many authentication failures for <*> [preauth]` |
| 13 | 37,029 | 43 | `PAM <*> more authentication <*> logname= uid=0 euid=0 tty=ssh ruser= <*> <*>` |
| 11 | 36,967 | 2 | `message repeated <*> times: [ Failed password for <*> from <IP> port <PORT> ssh2]` |
| 6 | 20,271 | 1713 | `Failed <*> for invalid user <*> from <IP> port <PORT> ssh2` |
| 1 | 18,909 | 136 | `reverse mapping checking getaddrinfo for <*> [<IP>] failed - POSSIBLE BREAK-IN ATTEMPT!` |
| 2 | 14,581 | 1710 | `Invalid user <*> from <IP>` |
| 3 | 14,581 | 1710 | `input_userauth_request: invalid user <*> [preauth]` |
| 5 | 14,356 | 92 | `pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= <*>` |
| 18 | 1,289 | 34 | `PAM <*> more authentication <*> logname= uid=0 euid=0 tty=ssh ruser= <*>` |
| 19 | 932 | 2 | `error: Received disconnect from <IP>: <*> <*> <*> <*> <*> <*> <*> [preauth]` |
| 17 | 595 | 2 | `Received disconnect from <IP>: 11: <*> <*> <*> <*> <*> <*>` |
| 28 | 497 | 12 | `Address <IP> maps to <*> but this does not map back to the address - POSSIBLE BREAK-IN ATTEMPT!` |

What went into the biggest of them:

- **cluster 10** (`Failed password for <*> from <IP> port <PORT> ssh2`)
  - 139,818 x `Failed password for root from <IP> port <PORT> ssh2`
  - 193 x `Failed password for uucp from <IP> port <PORT> ssh2`
  - 175 x `Failed password for git from <IP> port <PORT> ssh2`
  - 172 x `Failed password for mysql from <IP> port <PORT> ssh2`
  - 154 x `Failed password for ftp from <IP> port <PORT> ssh2`
  - 46 x `Failed password for www-data from <IP> port <PORT> ssh2`
- **cluster 9** (`pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= <*> <*>`)
  - 139,572 x `pam_unix(sshd:auth): authentication failure; logname= uid=<NUM> euid=<NUM> tty=ssh ruser= rhost=<IP>  user=root`
  - 193 x `pam_unix(sshd:auth): authentication failure; logname= uid=<NUM> euid=<NUM> tty=ssh ruser= rhost=<IP>  user=uucp`
  - 157 x `pam_unix(sshd:auth): authentication failure; logname= uid=<NUM> euid=<NUM> tty=ssh ruser= rhost=<IP>  user=git`
  - 153 x `pam_unix(sshd:auth): authentication failure; logname= uid=<NUM> euid=<NUM> tty=ssh ruser= rhost=<IP>  user=ftp`
  - 146 x `pam_unix(sshd:auth): authentication failure; logname= uid=<NUM> euid=<NUM> tty=ssh ruser= rhost=<IP>  user=mysql`
  - 86 x `pam_unix(sshd:auth): authentication failure; logname= uid=<NUM> euid=<NUM> tty=ssh ruser= rhost=<NUM>-<NUM>-<NUM>-<NUM>.rev.cloud.scaleway.com  user=root`
- **cluster 8** (`Received disconnect from <IP>: 11: <*> <*> <*>`)
  - 46,593 x `Received disconnect from <IP>: <NUM>: Bye Bye [preauth]`
  - 34 x `Received disconnect from <IP>: <NUM>: disconnected by user`
  - 8 x `Received disconnect from <IP>: <NUM>: Normal Shutdown [preauth]`
  - 7 x `Received disconnect from <IP>: <NUM>: Session closed [preauth]`

### Merges that may have absorbed a distinction, not an identifier

A merged cluster collapsed some token position. Where that position
takes many values it is an identifier and collapsing it is the point;
where it takes 6 or fewer it is usually a word that changes what
the event *means*, and the mined id can no longer tell the two apart.

| id | lines | position | values absorbed |
|---:|---:|---:|---|
| 8 | 46,642 | token 5 | `Bye`, `Normal`, `Session`, `disconnected` |
| 8 | 46,642 | token 6 | `Bye`, `Shutdown`, `by`, `closed` |
| 8 | 46,642 | token 7 | `[preauth]`, `user` |
| 13 | 37,029 | token 4 | `failure;`, `failures;` |
| 13 | 37,029 | token 11 | `user=curi`, `user=root` |
| 11 | 36,967 | token 8 | `curi`, `root` |
| 6 | 20,271 | token 1 | `none`, `password` |
| 18 | 1,289 | token 4 | `failure;`, `failures;` |
| 19 | 932 | token 6 | `No`, `org.vngx.jsch.userauth.AuthCancelException:` |
| 19 | 932 | token 7 | `User`, `more` |
| 19 | 932 | token 8 | `authentication`, `user` |
| 17 | 595 | token 5 | `Closed`, `Disconnect` |
| 17 | 595 | token 6 | `due`, `requested` |
| 17 | 595 | token 7 | `by`, `to` |
| 16 | 177 | token 8 | `cancel`, `fail` |
| 38 | 87 | token 5 | `Client`, `disconnected` |
| 38 | 87 | token 6 | `by`, `disconnecting` |
| 38 | 87 | token 7 | `normally`, `user` |
| 31 | 14 | token 4 | `''`, `'SSH-<NUM>.0_CoreLab-<NUM>.<NUM>'`, `'SSH-<NUM>.<NUM>'`, `'\<NUM>\<NUM>\001SSH-<NUM>.<NUM>-OpenSSH_6.<NUM>'`, `'\<NUM>\<NUM>\<NUM>\<NUM>"\<NUM>'` |
| 35 | 13 | token 1 | `none`, `password` |
| 32 | 8 | token 4 | `'CONNECT`, `'GET` |
| 32 | 8 | token 5 | `/`, `/manager/html`, `xui.ptlogin2.qq.com:<NUM>` |
| 36 | 6 | token 6 | `Authentication`, `com.jcraft.jsch.JSchException:`, `java.net.SocketTimeoutException:` |
| 36 | 6 | token 7 | `Read`, `cancelled`, `reject` |
| 36 | 6 | token 8 | `HostKey:`, `by`, `timed` |
| 43 | 6 | token 3 | `::`, `<IP>` |

## What this does not say

- No detection code reads `template_id` yet, so no number in
  `results/` moved and CLAUDE.md section 4 was not triggered.
- Cluster ids are only meaningful relative to the miner state that
  produced them: Drain3 is online, so the ids depend on the order the
  lines arrived. A different corpus, or this one shuffled, numbers
  them differently.
- The mined template text a line was given at mining time is not the
  text its cluster carries at the end of the run -- templates widen as
  more lines arrive. Every template printed above is the final one.
