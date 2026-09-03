# CLAUDE.md — AI Development Context (fork)

> **Read this file at the start of every session before writing any code.**
> **Update the Progress Tracker and Decision Log at the end of every session.**
> This file is the single source of truth for project state. If this file and the code disagree, trust the code and fix this file.

---

## 0. What This Fork Is, And What It Is Not

This is the **development fork** of the final-year project
"LLM-Powered Log Anomaly Detector with Attack Narrative & Adversarial Robustness".

### The four folders and their GitHub remotes

**Every folder below is an independent git repository with its own history.** They are
not branches of each other and they share no commits. Established 2026-08-18.

| Local folder (`/home/shiva/…`) | GitHub repo (`Vaishakh11000/…`) | Visibility | Role |
|---|---|---|---|
| `Project` @ tag `v1.0-submission` | `log-anomaly-detector-v1` | 🔒 private | The submitted academic artifact. **12 commits of real development history + the tag.** Frozen — report writing only |
| `log-anomaly-detector` | `log-anomaly-detector` | 🌍 **public** | Polished public release for other people to download and run. No `CLAUDE.md`, no viva material, no mention of the AI assistant. Ships `data/processed/` so it runs immediately |
| **`log-anomaly-detector-fork` (this repo)** | `log-anomaly-detector-fork` | 🔒 private | Real development. Free to break things v1 could not |
| `log-anomaly-detector-demo` | *(none — local only)* | — | Frozen demo-day copy. Holds `DEMO.v1.md`/`RUN.md` viva prep. Largely redundant with the public repo now. Never develop here |

**Footgun that was fixed on 2026-08-18, do not recreate it:** `Project` and
`log-anomaly-detector` were both pointing `origin` at the *same* GitHub repo despite
holding unrelated histories (12 commits vs 1). A `git push` from `Project` would have
been rejected, and a forced one would have destroyed the public repo. Worse, publishing
the public version had overwritten the only remote copy of the v1 development history,
leaving those 12 commits existing solely on the portable SSD. Each folder now has its
own distinct remote. **Before adding a remote to any folder, check no other folder
already claims it:** `git -C <dir> remote get-url origin`.

**The public repo must stay clean.** It carries no `CLAUDE.md` and no reference to the
AI assistant anywhere (verified via GitHub code search). Source docstrings that used to
cite `CLAUDE.md` now cite `docs/DESIGN.md`, which is the decision log rewritten for a
human reader. If v1 code is ever re-synced into it, re-run that check.

### Working with the user — explain everything in plain language

**Stated by the user 2026-08-19: they are not an expert in these subjects and want
every explanation kept as simple as possible.** This applies to all of it — git, the
detection maths, the SIEM comparison, the statistics behind the kill point — not only
to git. It is a standing instruction, not a one-off request.

What that means in practice:

- **Lead with the plain-English meaning, then the number.** "Wazuh missed a third of the
  attacks when we reworded them; we missed almost none" comes before `+31.1pt`.
- **Spell out jargon the first time it appears in a session.** *Instance detection*,
  *differential*, *seed*, *camouflage strategy*, *ambient ratio* — none of these are
  ordinary English, and all of them appear in this file as if they were.
- **Say what a command actually does before running it**, and show the resulting state
  rather than assuming it was understood.
- **Short sentences. No wall of tables without a sentence saying what to look at.**
  A table is fine, but say which row matters and why.
- **Never simplify by leaving out a bad result.** Simple language, complete facts —
  especially where the kill point (§1b) is concerned. Plain language is about
  *wording*, never about softening what the measurement says.

For git specifically, the same rule plus: do not force-push, delete, or repoint a
remote without first inspecting the target and saying what would be lost.

The v1 code, the v1 evaluation results, and the v1 decision log are carried
into `docs/` as **inherited context**:

- `docs/CLAUDE.v1.md` — the original project doc. **Its Decision Log (section 10) is
  still authoritative history** and explains why most of the current code looks the
  way it does. Read it before changing detection code. Never delete it.
- `docs/results.v1/` — the v1 evaluation artifacts. These are the **baseline every
  future change is measured against.** Do not overwrite them; new results go in `results/`.
- `docs/DEMO.v1.md` — the v1 demo runbook, kept for the honest-answers Q&A section.

### The v1 numbers to beat

Everything below is measured on the synthetic corpus (751 lines, 5 users, 9 attack
instances across 3 scenarios). These are the reference points:

| Metric | v1 |
|---|---|
| Line-level precision / recall / F1 | 0.29 / 0.86 / 0.43 |
| Self-written rule baseline (clean) | 0.99 / 0.94 / 0.96 |
| Instance detection, clean | 100% (9/9), in 8 incidents |
| Instance detection, worst camouflage (`slow`) | 80% |
| Recall under `realistic-combo` — system vs baseline | 0.78 vs 0.07 |
| Alert volume | 94 incidents for 9 real attacks |
| Narrative cost | ~40-60s/incident on CPU (phi3) |

**Precision and alert volume are the weakest numbers and the main thing to fix.**
Robustness under camouflage is the strongest and must not regress to get there.

---

## 1. North Star

> A **local-first detection and explanation system that is continuously measured
> under adversarial conditions.**

The detection method is not the novelty — Isolation Forest over sentence embeddings
is standard, and saying otherwise in a write-up would be dishonest. Neither is
"we attached an LLM", which everyone is doing.

What is uncommon: **no open-source SIEM and very little of the published log-anomaly
literature reports how much worse it gets when the attacker actively tries to hide.**
This project does, on every change, as a gate.

Use this to decide what to build. If a proposed feature does not either
(a) improve detection/explanation, or (b) make the adversarial measurement more
credible, it is probably not worth doing.

---

## 1b. The Pre-Registered Kill Point

> **Registered 2026-08-17, before any Stage 1 code was written.**
> **This criterion may not be moved, softened, or reinterpreted after seeing results.**
> A kill point you can move is not a kill point.

The entire roadmap rests on one unverified assumption: **that v1's robustness gap
survives contact with rules the author did not write.** v1's headline collapse
(baseline recall 0.94 → 0.07 under `realistic-combo`, system 0.86 → 0.78) was measured
against *self-written, frequency-threshold* rules, which `slow` defeats almost by
definition. A mature third-party ruleset degrades by a different mechanism, and those
numbers do not transfer. Nobody knows the answer yet — that is the point.

So the assumption gets tested **first, cheaply, before anything is built on it.**

### The experiment

Third-party ruleset (**Sigma** primary, **Wazuh** if it cooperates) vs. this detector,
on a real OpenSSH corpus slice with attacks injected, all seven v1 camouflage strategies
applied, pooled over ≥5 seeds.

**Batch mode. One machine. No streaming, no two-machine split, no GPU dependency.**
Those are amplifiers — they make a good result more impressive and a mushy result
equally mushy. Nothing important may be sequenced behind them.

**Deadline: 4 weeks from the day Stage 1 starts.**

### The measurement

For each camouflage strategy, the drop in instance detection for each system. The
deciding number is the **differential between those drops**.

| Result | Decision |
|---|---|
| **≥25pt** differential on at least one strategy | **Continue.** The thesis survived third-party rules. Build the roadmap — streaming, bake-off, two-machine, GPU |
| **10-25pt** | **Partial.** Real but not dramatic. Cheap stages only; skip the amplifiers |
| **<10pt**, or the SIEM degrades *less* than this system does | **Stop.** Write it up as an honest negative result and move on |

Calibration: v1's differential was 87pt vs 8pt. 25pt is a far lower bar and still
clearly visible in a live demo.

### If it lands in the bottom row, publish that

*"A production SIEM ruleset is more robust to camouflage than an embedding detector"*
is a genuinely useful finding that nobody has written down, and it costs one month
instead of six. The temptation in that case will be to tune until the result looks
better — **that is the single biggest risk to this project's integrity**, larger than
any technical risk in it. v1 already faced this exact choice with the contamination
retune and got it right (see `docs/CLAUDE.v1.md`, 2026-08-16). Do it again.

**Do not script the demo narrative before this measurement exists.** Measure, then
write the story around what actually happened. Scripting first creates pressure to tune
until reality agrees.

---

## 2. Hard Constraints (kept from v1 — do not violate)

These survive the fork because they are physical or because they are genuine design
positions, not timeline excuses.

- **CPU is the supported floor, GPU is an accelerator.** The system must always run,
  end to end, on the CPU-only machine. "Runs on a laptop with no GPU" is a genuine
  differentiator — it is why a team with no SOC budget could deploy this. The moment
  a GPU becomes *required*, this becomes one more ML security tool with infrastructure
  demands. See §2c for hardware tiers.
- **Local-first.** No *required* cloud API. Optional cloud enrichment is acceptable
  only if the system degrades gracefully to fully-local operation.
- **No LLM fine-tuning. No models >8B params.** Training small task-specific models
  (sequence models over template IDs) is now allowed — see §2c. Fine-tuning the
  narrative LLM is not: it does not fix the detection problem, and it makes results
  much harder to reproduce in a write-up.
- **Single-box mode must always work.** The two-machine split (§2c) is a deployment
  *option*, never a requirement. A dead network link must downgrade the demo, not end it.
- **No auto-response / SOAR / blocking actions.** This is a deliberate product
  stance, not a scope cut: the system is decision support for an analyst. It may
  *recommend* actions. It must never take them.
- **Every MITRE technique the system *reports* comes from data**, never from the
  LLM — the keyword table joined to the pinned ATT&CK STIX index, and Sigma tags.
  `mitre_techniques`, the kill chain, the dashboard and the coverage matrix are
  all retrieval output. This is the design decision that stops the headline
  feature from being a hallucination generator. See the v1 `"nan"` incident in
  `docs/CLAUDE.v1.md`.

  ⚠️ **This constraint used to be written as "the LLM never invents MITRE
  technique IDs", and that sentence was measured false on 2026-09-04.** The
  prompt instructs the model not to, and phi3 does it anyway: **47 invented IDs
  on the synthetic corpus and 119 on OpenSSH** (`results/faithfulness/`). The
  architecture protects the *structured* output; the *narrative prose* was never
  protected, because until Stage 5 nothing read it back. An instruction in a
  prompt is not an enforcement mechanism. The constraint as restated above is
  the part that is true and load-bearing; making it true of the prose as well is
  what Stage 5's structured output is for.
- **`uv` only.** Never bare `pip` or `python -m venv`.
  `uv` lives at `~/.local/bin/uv` and is not on `PATH` in non-interactive shells —
  `export PATH="$HOME/.local/bin:$PATH"` if you get `uv: command not found`.

## 2b. Constraints Dropped From v1 (these were timeline cuts)

Explicitly now **allowed**, and mostly required:

- ✅ Live/streaming ingestion (as file tailing + micro-batches, not Kafka)
- ✅ Multi-source correlation (auth + syslog + journald + web)
- ✅ Log formats beyond syslog/auth
- ✅ Real public datasets (LogHub), not just synthetic
- ✅ Third-party rulesets (Wazuh, Sigma) as baselines and as signal
- ✅ A real test suite, CI, packaging, a database, an API
- ✅ Dashboard/UX work

---

## 2c. Hardware Topology

The key fact that shapes everything here: **the whole dev environment lives on a
portable USB SSD, not inside any one laptop.** Verified 2026-08-17 — `sda` (USB) holds
`/boot`, the LUKS root, and `/home`; the analyzer role is therefore *wherever the SSD is
booted*, a boot-time choice rather than a porting problem. This is why there is no
"port it to Windows" work: you boot native Linux on whatever hardware the SSD is in.

Two roles, split by **role, not by clustering.**

| | ANALYZER | ADVERSARY + MONITORED HOST + SIEM |
|---|---|---|
| Hardware | Gaming laptop, **RTX 4060 8GB**, booting the portable SSD | Office laptop, **Kali on its own NVMe** (SSD not needed here) |
| Runs | Embeddings, sequence models, Ollama, dashboard, API, the detector | Real attack tooling (hydra/medusa/nmap), emits `auth.log`/journald, runs Sigma/Wazuh |
| Also is | Primary dev machine for detection work | Generates *authentic* attacks — see §2d |

### Third machine: the day-to-day dev box (added 2026-08-30)

> **Update 2026-09-01: the SSD is now booted on the RTX 4060 machine — the
> final-test/demo box — and the figures in the "Final-test box" column below are
> measured rather than blank.** Development happened on the borrowed 3050 laptop
> up to 2026-08-31.

The SSD boots on a **borrowed laptop of the same model family but a different
GPU**, and that is where development happened up to 2026-08-31. The RTX 4060
machine is reserved for **final testing and the demo**.

| | Dev box (3050) | Final-test / demo box (4060) |
|---|---|---|
| GPU | **RTX 3050 6GB Laptop** (GA107BM) | **RTX 4060 8GB Laptop**, 8188 MiB |
| CPU | i5-13450HX, 10c/16t | **i7-13650HX, 14c/20t** |
| Driver | 610.57.04 | 610.57.04 (same SSD, carried across) |
| Narration, GPU / CPU | 5.2s / 24.2s | **3.9s / 18.2s** |

Verified on first boot 2026-08-30: the SSD booted, `nvidia-smi` reports driver
610.57.04, and `dkms status` shows `nvidia/610.57.04, 7.1.8-arch1-3: installed`.
The driver prep done on 2026-08-20 carried across hardware exactly as intended.

Three consequences, and the middle one is the one that can quietly corrupt a
result:

- **6GB, not 8GB.** phi3-mini q4 (~2.3GB) is comfortable. llama3:8b q4 (~4.9GB)
  fits only barely once KV cache is counted, so **treat it as unverified here**
  and test before designing around it. On the 4060 it is fine.
- **GPU timing numbers do not transfer.** Narration latency measured on a 3050
  is not the 4060 number and must never be quoted as one. §2c already requires
  reporting CPU and GPU figures separately; this adds a third measurement point,
  so label every latency figure with the machine that produced it. **Settled
  2026-09-01 by measuring both on the 4060 box: 3.9s GPU, 18.2s CPU** — the
  direction was as expected (the bigger GPU is faster) but the *size* was not
  guessable from the 3050 figures, which is why it had to be measured rather
  than extrapolated.
- **Developing on the smaller GPU is the safe direction.** Anything that fits
  6GB fits 8GB. The reverse would not hold, which is why the borrowed machine is
  an acceptable dev box but not an acceptable place to measure the demo.

**The RAM squeeze is gone here.** ~11GB available against the ~5GB that forced
the "Wazuh manager only, never the full stack" decision (Decision Log
2026-08-17). That decision is not reversed — the manager-only setup is also the
better comparison and the better demo — but it is no longer *forced* by memory
on this machine. **Re-checked on the 4060 box 2026-09-01: 23GB total, ~18GB
available**, so it is not forced there either. The manager-only setup stays on
its own merits, not on a memory limit.

The **CPU-floor benchmark target** is the same SSD env booted *without* using the GPU
(or on any GPU-less machine) — that is what keeps "runs on CPU" a measured claim.

**Do not cluster the two for compute.** Every model fits on one 8GB GPU (phi3-mini q4
≈ 2.3GB, llama3:8b q4 ≈ 4.7GB, MiniLM ≈ 0.1GB, sequence models negligible). Splitting a
model that already fits, across a link three orders of magnitude slower than on-card
memory, makes inference *slower* while adding `torch.distributed`/Ray complexity and a
new demo-day failure class. Role-splitting is different and worth it: it is the Stage 7
collector/analyzer split pulled forward, and an examiner watching attacks launched on
one physical machine and alerts appear on another is far harder to dismiss than two
panes of one app.

### The SSD is single-occupancy — design for it

The SSD can be in **only one machine at a time.** During the bake-off it is in the
gaming laptop (the analyzer needs the GPU). That means the Kali box must run its share
**without the repo present** — the collector, the SIEM config, and the attack scripts
have to be independently deployable, not "assume the whole project is checked out here."
Build the collector as a small standalone piece from Stage 2 onward; do not retrofit
this later. See §2d.

### When to move the SSD to the gaming laptop

Not yet, and not for a while. Do the move **once, at the start of Stage 2** — that is
the first stage that actually needs the GPU (live narration) and the second machine
(the split). Everything before it is single-box work that is easier on your current
setup:

- **Stages 0-1 (foundation + benchmark + the §1b kill point): stay where you are.**
  These are batch, one-machine, CPU-fine. The kill point is explicitly "one machine,
  batch mode" — do not entangle a hardware migration with the experiment that decides
  whether the roadmap continues at all. If the kill point says stop, you never needed
  the gaming laptop.
- **Prep the gaming laptop *during* Stage 1** (background, low-risk): install the NVIDIA
  driver, test-boot the SSD on it, confirm the 4060 is visible. Details below. Doing
  this early de-risks the Stage 2 move without blocking Stage 1.
- **Move at Stage 2 start**, once the kill point has said "continue." From then on the
  gaming laptop is the dev/analyzer machine.

### Preparing the gaming laptop (do during Stage 1, before the move)

1. **Install the NVIDIA driver now, while this machine has working internet.**
   ✅ **Done 2026-08-20**: `nvidia-open-dkms 610.57.04`, `dkms 3.4.2`,
   `linux-headers 7.1.8.arch1-3`, `nvidia-utils 610.57.04`; `dkms status` reports
   `nvidia/610.57.04, 7.1.8-arch1-3, x86_64: installed`. Note `dkms` and
   `linux-headers` were *both* missing and are not optional — without them the driver
   silently fails to rebuild on the next kernel update. It sits dormant until booted on
   GPU hardware.
2. **`autodetect` is in your HOOKS** — it bakes only *this* laptop's modules into the
   image, so a foreign-hardware boot often can't find root. **Correction to an earlier
   assumption in this file: Arch did _not_ build a fallback image here.** This install
   uses a Unified Kernel Image (systemd-boot, `/boot/EFI/Linux/*.efi`), and both
   `PRESETS=('default' 'fallback')` and `fallback_options="-S autodetect"` ship
   commented out — so there was exactly one boot image, autodetect-built, and no safety
   net for foreign hardware. **Fixed 2026-08-20**: both lines uncommented and
   `mkinitcpio -P` run, producing `arch-linux-fallback.efi` (239MB vs the 47MB default,
   which is the expected size difference — it carries every module).
   **Boot the fallback entry the first time on the gaming laptop.** If that works,
   either leave it, or drop `autodetect` from `HOOKS` for a seamless default boot.
3. **Gaming-laptop UEFI:** disable Secure Boot, enable USB boot, use a USB 3.x port (a
   USB-2 negotiation makes everything crawl). You will enter the LUKS passphrase at boot.
   Booting the SSD does **not** touch the laptop's internal Windows install.
   **Check before moving:** this install has TPM-related boot artifacts
   (`/boot/loader/boot-secret-mixin`, an `nvpcr-anchor` credential), so if LUKS is
   TPM-enrolled it auto-unlocks *on this machine only* — a different laptop has a
   different TPM and will demand the passphrase. Confirm you know it:
   `sudo cryptsetup luksDump /dev/disk/by-partuuid/<root> | grep -iA2 tokens`.
4. **Test-boot well before any demo**, never the night before.

### The link

**Direct gigabit ethernet, one Cat6 cable, no switch.** Both laptops have their own
ports here (the earlier "no ethernet port" note applied only to the old Arch box, which
is no longer in the topology). Auto-MDIX means no crossover cable is needed.

A single USB-C / Thunderbolt cable does **not** carry a network between two laptops
unless *both* ends are Thunderbolt/USB4 host-to-host — a plain USB-C link is not
networking. Ethernet is the reliable choice and loses nothing: **bandwidth is not the
constraint.** 10k log lines/sec at ~200 bytes ≈ 2 MB/s ≈ 1.6% of a gigabit link.
Optimise for reliability, not throughput. If both machines *do* turn out to have real
Thunderbolt/USB4, it works and is faster, but it buys nothing you can use here and adds
setup fragility — prefer ethernet.

Do not build the link on campus/shared WiFi: AP client isolation commonly blocks
laptop-to-laptop traffic entirely and is undebuggable in a demo room.

```bash
# Analyzer (gaming laptop). Find the interface name with: ip -br link
nmcli con add type ethernet ifname enp3s0 con-name direct-link ip4 10.10.10.2/24
nmcli con mod direct-link ipv4.never-default yes   # or WiFi internet dies mid-demo
nmcli con up direct-link
# Kali box: 10.10.10.1/24 the same way. No gateway, no DNS, no DHCP on this link.
```

### Reliability is in the shipping code, not the cable

- Disk-backed buffer on the collector — a 3-second analyzer restart must not silently eat data
- Track a byte offset into the source log so reconnects neither duplicate nor skip
- HTTP POST with retry, never a raw socket: resume is trivial over one and painful over the other
- Link health + lag visible on the dashboard — "is it connected?" must be answerable by
  looking, not by inferring from an absence of alerts
- Test the exact cable you will present with, not an equivalent one

### What the 4060 unlocks, and what it does not

Unlocks: real-time narration (seconds, not 40-60s — this is what makes "explains it as
it happens" honest rather than an apology), llama3:8b instead of phi3, sequence-model
training, full-corpus LogHub runs, Wazuh's full stack alongside Ollama.

Does not: 70B models, full fine-tuning, transformer pretraining. None of which are needed.

Mobile 4060s throttle under sustained load — expect long eval runs to report slower
per-item numbers than short ones, and plug in.

---

## 2d. The Kali Machine — Authentic Attack Generation

Kali is not just "the other laptop"; it is a **methodological upgrade**, and it belongs
in the software as a distinct role.

The credibility problem Kali solves is the twin of the third-party-ruleset problem. v1's
weakness was "you wrote the attacks *and* the rules that catch them." §1b removes the
self-written rules by adopting Sigma/Wazuh. Kali removes the self-written *attacks* for
the un-camouflaged case: instead of injecting fabricated log lines, **run real tooling
against a real sshd and capture the genuine log entries it produces.**

- `hydra` / `medusa` against a local sshd → authentic failed-password bursts (Scenario A)
- `nmap` / scripted multi-user probes → authentic enumeration (Scenario C)
- real logins from a second source → impossible travel (Scenario B), which stays partly
  synthetic because it needs geographically distinct IPs

The base attacks become authentic traffic from standard tools; **only the camouflage
layer remains authored** — and that is exactly the layer the project is *supposed* to
own, because measuring camouflage is the contribution.

### How Kali becomes part of the software (not just a laptop)

A separate, independently deployable component — because §2c's SSD is single-occupancy,
this code cannot assume the repo is checked out on the Kali box:

- **`attack_runner/`** — a small standalone package (its own `pyproject.toml`, or even a
  single script + `requirements`) that: (1) drives the attack tools with known
  parameters, (2) records exact ground truth — which lines each tool produced, with
  timestamps, so scoring stays automatic, (3) applies the camouflage transforms to the
  *real* captured lines, and (4) ships them to the analyzer over the §2c link.
- Ground truth is captured **at generation time on Kali**, then travels with the logs.
  This is the same principle as v1's decision to camouflage the event list rather than
  the finished file (see `docs/CLAUDE.v1.md`) — keep each attack line bound to its
  scenario/instance label through every transformation.
- The camouflage strategies themselves are shared library code, imported by both
  `attack_runner/` (real-log path) and the existing `adversarial.py` (synthetic path),
  so the two evaluation tracks apply *identical* transforms and remain comparable.
- Keep it honest in the write-up: base attacks are real tool output; camouflage is
  authored; impossible-travel's second IP is synthetic by necessity. State all three.

**Land this at Stage 6 (adversarial platform), not before.** Stages 1-5 run fine on the
synthetic corpus and OpenSSH; Kali-generated attacks are the strongest version of the
adversarial track, so they belong with the adaptive adversary, once the kill point has
justified building that far.

---

## 3. Progress Tracker

> **Agent: update this section at the end of every session.**

**Current stage:** Stage 5 — LLM layer maturity (Stage 2b left open, see below; Stage 4 closed 2026-09-04)
**Stage 1 started:** 2026-08-18 → **kill-point deadline 2026-09-15** (4 weeks, §1b)
**Last session:** 2026-09-04 (Stage 5: the **empty-match prompt rewording** and **structured JSON output**, each measured on both corpora — invented technique IDs 47/142 and 119/197 → **0 of 65 and 0 of 58**; the technique-*name* check finds nothing because the invention is whole-cloth. Earlier the same day, Stage 4: **ATT&CK STIX ingest pinned at 19.2**, kill-chain mapping on every incident, and the **detection coverage matrix** — 11 techniques mapped, 1 of 86 inside ATT&CK's own syslog-visible universe, 5 never observed. Enrichment only; 751 → 130 → 94 unchanged)
**Last commit:** _(see `git log`)_

> ## ✅ Kill-point verdict: **CONTINUE** (31.1pt, 5 seeds, 2026-08-19)
>
> `results/killpoint/killpoint_ambient0.05.md`, from a completed 5-seed paired run
> with Wazuh available throughout. The registered ≥25pt bar is cleared, so the
> roadmap continues and the amplifiers (streaming, bake-off, two-machine, GPU) are
> unlocked.
>
> **Read the shape of the result, not just the headline.** Of the five
> timing-independent strategies, exactly **one** produced the gap:
>
> | Strategy | Ours Δ | Wazuh Δ | Differential | |
> |---|---|---|---|---|
> | `rephrase` | +2.2 | +33.3 | **+31.1** | the entire result |
> | `mimicry` / `noise` / `volume` | +0.0 | +0.0 | +0.0 | ties |
> | `ip_rotate` | +11.1 | +0.0 | **−11.1** | **we are the weaker system here** |
>
> §1b says "≥25pt on at least one strategy", so `verdict()` taking the maximum is
> the registered reading and was written before any result existed. But **one win,
> three ties and one loss is a narrower finding than "more robust under
> camouflage", and must be written up that way.** The honest claim is *"against
> reworded attacks, Wazuh's rules break and embeddings do not"* — which is exactly
> what a signature engine would be expected to do, and is therefore a mechanism
> worth stating rather than a surprise.
>
> **`ip_rotate` is a genuine loss and stays in the report.** Spreading an attack
> across many source IPs costs us 11pt and costs Wazuh nothing.
>
> **The three excluded strategies were measured on 2026-08-20 by paced replay
> (6.5h, 5 seeds), and they went against us:**
>
> | Strategy | Ours Δ | Wazuh Δ | Differential | |
> |---|---|---|---|---|
> | `slow` | +8.9 | +0.0 | **−8.9** | loss |
> | `temporal` | +0.0 | +0.0 | +0.0 | tie |
> | `realistic-combo` | +13.3 | +0.0 | **−13.3** | loss |
>
> **The full eight-strategy tally is therefore 1 win, 4 ties, 3 losses.** The
> registered criterion is "≥25pt on at least one strategy", which `rephrase`
> still clears, so **CONTINUE stands and is no longer provisional in scope** —
> but the honest summary of this project's robustness claim is now *one
> mechanism, not a general property*, and `realistic-combo` (the most realistic
> attacker model) is a loss.
>
> **No alert level rescues it, and shopping for one would be dishonest.** At
> Wazuh's L3 it cannot degrade because it starts saturated — a single failed
> login is already a level-5 rule, so it flags every instance without
> correlating anything, at 1,472 alerts for 9 attacks. At L7/L10 it detects
> **11.1% — one instance in nine — on the clean corpus**, so its small drops
> there are a floor effect. Both readings are in
> `results/killpoint/killpoint_paced_ambient0.05.md`.
>
> **Alert volume flipped v1's story:** Wazuh emits ~4,546 alerts on the clean
> corpus against our 1,415 — roughly 3.2× more. Precision is still our known
> weakness in absolute terms, but on this corpus we are not the noisier system.

> **Stage 0 is fully verified.** All three tracks reproduce v1 byte-for-byte after
> the restructure: the pipeline (751 → 130 → 94 incidents, locked in
> `tests/test_pipeline_regression.py`), `results/evaluation.md`, and
> `results/adversarial_results.md`. Nothing about detection changed, which is what
> made it safe to build Stage 1 on top.

### Stage checklist

- [x] **Stage 0 — Foundation.** ✅ 2026-08-18, except the DB (see below).
      Two packages — `src/logdet/` (pipeline) and `src/logdet_eval/` (evaluation) —
      making §5's one-way dependency rule structural and statically enforced in
      `tests/test_layering.py` rather than a convention. Console entry points
      (`logdet-preprocess`, `logdet-pipeline`, `logdet-evaluate`,
      `logdet-adversarial`, `logdet-generate`, `logdet-samples`) replace
      `python src/<module>.py`. 99 pytest tests replace the v1 `__main__` smoke-test
      convention (the smoke blocks stay for debugging). GitHub Actions CI on push/PR.
      Config paths now resolve against the repo root instead of the working directory.
      **Detection behaviour verified unchanged**: 751 lines → 130 anomalies (3 via
      impossible travel) → 94 incidents, identical to v1, and pinned in
      `tests/test_pipeline_regression.py`.
      **Persistence layer deliberately deferred to Stage 2**, where streaming is the
      thing that actually needs a store; Stage 1 writes JSON/Markdown reports, which
      files handle fine. Deferring it puts the §1b kill point a session closer.
- [x] **Stage 1 — Benchmark platform.** ✅ 2026-08-20. ⭐ *Comes before any detection change, and it
      carries the §1b kill point.* Third-party baseline: **Wazuh manager**, run as the
      real engine in Docker (`docker exec wazuh wazuh-logtest`). **Sigma was dropped
      after measurement** — not one of ~3,300 rules matches an sshd auth line; see the
      2026-08-18 Decision Log entry. Real data: **LogHub OpenSSH** (primary, 100% parse)
      + **Linux** (companion, 76% parse) — see §3b for why not HDFS/BGL.
      This is where "rules written by people who never saw my data" replaces the
      self-written baseline — v1's single biggest credibility hole.

      **Built and green (2026-08-19):**
      - `logdet_eval/datasets.py` — Zenodo-pinned, SHA-256-verified LogHub fetch
      - `logdet_eval/corpus_openssh.py` — kill-point corpus: real benign lines + real
        ambient attacker traffic at a declared ratio, attacks injected on top
      - `logdet_eval/wazuh_runner.py` — drives the real manager; note logtest writes
        its analysis to **stderr**
      - `logdet_eval/scoring.py` — one detector-agnostic scorer for both systems, with
        a test asserting it agrees with `adversarial.measure()` on identical input
      - `logdet_eval/killpoint.py` — paired runner, per-condition checkpointing,
        verdict logic; 11 tests pin the §1b thresholds and the exclusion rule
      - 154 tests pass (`-m "not slow"`)
      - ✅ **the 5-seed run completed 2026-08-19 → CONTINUE at 31.1pt** (see the
        verdict box above). Wazuh alert volume is now reported alongside detection.

      **Paced replay — instrument built 2026-08-19, run outstanding:**
      - `logdet_eval/paced_replay.py` — per-source-IP replay schedule, alert
        attribution, correlation-state reset between runs
      - `corpus_openssh.build_paced_corpus()` / `thin_background()` — the same
        real corpus capped at N events per ambient IP, which is what makes it
        replayable
      - probed before building: 15 `Invalid user` lines from one IP fire rule
        5712 at 0.2s spacing and **do not** fire it at 20s spacing, so pacing
        genuinely changes Wazuh's verdict
      - cost brought from **144h → 5.2h** for the full 4-condition 5-seed run
      - 30 new tests; 176 pass (`-m "not slow"`)
      - `logdet_eval/paced_killpoint.py` + `logdet-paced-killpoint` — the runner;
        no exclusion rule, because every strategy in it is one the instrument
        can measure
      - ✅ **the 5-seed paced run completed 2026-08-20** (6.5h): `slow` −8.9,
        `temporal` +0.0, `realistic-combo` −13.3. Two losses and a tie. The
        exclusion is lifted and the CONTINUE verdict is final in scope.

      **Ambient-density sensitivity — done 2026-08-20.** The claim rested on one
      number measured at one arbitrary background density, so the same batch
      experiment was re-run across a 20× range. `rephrase` reads **+31.2 / +31.1
      / +31.1** at ambient 0.01 / 0.05 / 0.20 — a 0.1pt spread, CONTINUE at all
      three. The ties stay ties. `ip_rotate` is the one real result that moves
      (−13.3 → −8.9; a loss throughout, smaller the noisier the background), and
      the write-up should carry that range rather than the friendliest figure.
      `results/killpoint/killpoint_ambient_sensitivity.md`.

      **Merged eight-strategy view — done 2026-08-20.** `logdet-killpoint-summary`
      puts the batch win and the paced losses in one table so neither half can be
      quoted alone. `results/killpoint/killpoint_eight_strategies_ambient0.05.md`.

      **Checkpoints are now resumable** (`--resume`). They had been written since
      2026-08-19 with nothing able to read them; three runs died and redid work
      they had already finished. Refuses a checkpoint whose seeds, seed range,
      ambient ratio, contamination or thinning knobs differ, and one written
      without Wazuh.

      **Carried into Stage 2:** build the harness to run in streaming mode with an
      injector-driven ground-truth feed, not just batch-over-a-file — do that and
      Stage 2b falls out nearly free.
- [ ] **Stage 2 — Live ingestion.** ▶ *in progress, started 2026-08-30.*
      ✅ **Fit/score split and detector persistence** — `PerUserAnomalyDetector.save`/
      `load`/`describe`, and `run_anomaly_detection(df, detector=...)` to score
      without refitting. Provenance is stamped and checked on load: a mismatched
      embedding model, vector width, or format version is refused, because an
      Isolation Forest scores foreign embeddings without complaining and returns
      numbers that look fine and mean nothing. Omitting `detector` keeps v1's
      behaviour, so the 751 → 130 → 94 lock stayed green and §4 did not apply.
      Models go to `models/` (gitignored, regenerable).
      ✅ **File tailer + micro-batch scoring** — `logdet-fit` writes a detector
      from a chosen history slice; `logdet-stream` tails a log and scores it in
      micro-batches against that saved model, never re-fitting. A batch closes on
      whichever comes first, 50 lines or 5 seconds. `--once` replays a whole file
      and exits, which is the demo/replay path.
      **The streaming result is identical to the batch result**: 751 lines → 130
      flagged events → 94 incidents, the same numbers pinned for the batch path,
      locked in `tests/test_stream_regression.py`. That equivalence is the only
      thing that makes streamed numbers comparable to every number in `results/`.
      Three pieces of carried state make it hold, and each has a test that fails
      when it is removed: a rolling context window (impossible travel compares a
      login with the *previous* one, which is usually in an earlier batch),
      incremental incident growth using the batch grouper's own link rule
      (`sequence_grouping.linked`) with merge-on-bridge for transitivity, and a
      byte offset committed only after a batch is scored. 28 new tests; 269 pass
      (`-m "not slow"`), 278 with the slow locks.
      ✅ **journald as a live source** — `logdet-stream --journald` reads this
      machine's own systemd journal instead of a file. Same `read_lines()` /
      `commit()` contract as the file tailer, so nothing below the source
      changed. Defaults to the **authpriv facility** (`SYSLOG_FACILITY=10`:
      sshd, sudo, su, pam), which is the auth.log vocabulary the detector is
      fitted on; `--journald-unit sshd` narrows it further. Resume is by
      journald's own **cursor**, kept in a store separate from the file
      tailer's byte offset and committed only after a batch is scored.
      Verified live on this box, not only in tests: a one-shot run over the
      last 24h scored 22/22 lines; a second run against the same cursor store
      read 0 lines and re-alerted on nothing; and in follow mode six
      `logger -p authpriv.info` failed-password lines arrived through
      `journalctl -f` and grouped into one T1110 incident. 27 new tests, all
      driving an injected chunk reader so CI needs no journal. Note
      **`--since now` does not mean "from this moment"** — journalctl returns
      the whole journal for it, so follow mode uses `-n 0`, which is the
      primitive that actually replays no history.
      **No sshd runs on this dev box** (`journalctl -u sshd` is empty), so the
      live auth traffic available here is sudo/su/pam. Start sshd before using
      journald as the source for anything ssh-shaped.

      ✅ **FastAPI service** -- `logdet-api` owns the stream rather than
      serving a file somebody else wrote. `POST /stream/start` builds a file
      or journald source, loads the fitted detector and runs the same
      `run_stream` loop on a background thread; `GET /incidents` serves what
      it emits, ranked by the *same* triage policy the dashboard uses (moved
      to `logdet/triage.py` so the two interfaces cannot drift apart);
      `GET /events` is a server-sent-event feed one incident at a time;
      `POST /incidents/{id}/narrate` runs the LLM on demand, because
      narrating every incident as it closed would put the scoring thread
      minutes behind the log. `GET /stream/status` reports lines seen/parsed
      and **seconds since the last scored batch**, which is what separates a
      quiet log from a dead reader -- the "link health must be visible, not
      inferred" requirement in section 2c.
      **Nothing here scores anything**: detection, grouping and severity stay
      in `StreamProcessor`, so the streamed-equals-batch lock still holds and
      section 4 did not apply. Incidents are stored as deep copies taken at
      emit time, since the processor rewrites its own dicts in place when an
      incident closes. One stream at a time (a second start is a 409) because
      incident ids come from one processor's counter. `run_stream` gained a
      `stop_fn` so a follow-mode stream can be ended by something other than
      killing the interpreter. No authentication -- binds 127.0.0.1 by
      default. 30 new tests; 337 pass (`-m "not slow"`).

      Verified live, not only in tests: replaying `synthetic.log` through
      `POST /stream/start` produced **751 lines seen, 751 parsed, 94
      incidents**, 19 of them notable -- the same numbers the batch and
      stream paths are pinned to -- and the SSE feed carried every one of
      them. A journald one-shot over HTTP read 28 lines, parsed 28, and
      raised 4 incidents.

      ✅ **Dashboard reads the API** -- the Streamlit page defaults to the
      running service and shows incidents as the stream emits them, with the
      stream's own health above the list (lines seen, lines parsed, seconds
      since the last scored batch, dropped pushes) and start/stop controls in
      the sidebar. Narration is a per-incident button that calls
      `POST /incidents/{id}/narrate`. The old `incidents.json` source is still
      there as the second option, because that file is what a finished
      `logdet-pipeline` run produces and every number in `results/` came from
      it. Ranking and the notable filter come from `logdet/triage.py`, shared
      with the API, so the two interfaces cannot disagree. HTTP lives in
      `logdet/api_client.py` rather than inside the script: a Streamlit file
      cannot be imported without executing, and the branch worth testing is
      what the page does when the service is down, not where the columns sit.
      Auto-refresh reruns the page on a timer **only while a stream is
      running** -- a stopped stream would otherwise redraw the same page
      forever and reset the reader's view of a finished replay.

      ✅ **`logdet-replay` -- paced replay for demos.** Writes a recorded log
      back out in wall-clock time (`--speed 60` = one hour of log per minute)
      into a file the stream or the API tails, so the detector is following
      traffic that is still being written. `--max-gap` clamps the hours of
      silence real logs contain and the run reports how many gaps it clamped,
      because past that point the replay is no longer a faithful time-scaling.
      `--rate N` ignores timestamps for a fixed lines/second. `--restamp`
      rewrites each line's timestamp to now, which reads as live but
      compresses the log's own time by `--speed`, so the 30-minute grouping
      window and 60-minute travel window stop covering what they covered in
      the recording -- off by default, and results produced under it are not
      comparable to `results/`. Distinct from `logdet_eval/paced_replay.py`,
      which schedules per source IP to drive Wazuh's `same_source_ip`
      frequency rules; this one preserves global order and only writes a file.

      Verified live end to end: 80 synthetic lines replayed at 2000x into
      `data/live/demo.log` while the API followed it -- 80 seen, 80 parsed, 12
      incidents, the top one a 10-event T1110 -- and the real dashboard read
      that service and rendered 12 incidents, 3 notable. 41 new tests; 378
      pass (`-m "not slow"`).

      Stage 2 is complete. Stage 2b is in progress — see below.

      **Narration latency**, phi3, the pipeline's own prompt, median of 3 timed
      runs after one warm-up. **The 2026-09-01 row is the demo machine and is the
      one the deck quotes.**

      | Machine | Median per incident | Measured |
      |---|---|---|
      | **GPU, RTX 4060 8GB (demo box)** | **3.9s** | 2026-09-01 |
      | **CPU only, i7-13650HX 14c/20t (demo box)** | **18.2s** | 2026-09-01 |
      | GPU, RTX 3050 6GB (dev box) | 5.2s | 2026-08-30 |
      | CPU only, i5-13450HX 10c/16t (dev box) | 24.2s | 2026-08-30 |
      | v1 CPU, old laptop | 40-60s | v1 |

      This supersedes the "40-60s/incident on CPU is a floor" figure carried from
      v1 — that was *one machine's* number, not a property of CPU inference, and
      each faster CPU has cut it again (40-60s → 24.2s → 18.2s). **Every figure
      must be labelled with the machine that produced it and never blended.** The
      GPU result is the important one: at ~4s, near-real-time narration is honest
      rather than an apology.

      Reproduce it with the module's own smoke-test incident
      (`llm_narrative.__main__`, 4 events, 592 prompt tokens) so the comparison is
      the same prompt on every machine. Generated length varies run to run
      (254-360 tokens), which is why the figure is a median and not a single run.
      To measure the CPU-only side without disturbing the GPU service, start a
      second server rather than stopping the first:
      `CUDA_VISIBLE_DEVICES="" OLLAMA_HOST=127.0.0.1:11435 OLLAMA_MODELS=/var/lib/ollama ollama serve`
      — the systemd unit runs as user `ollama` with its models in
      `/var/lib/ollama`, so a user-run server sees no models without that path.

      **On Arch, `ollama-cuda` is an add-on to `ollama`, not a replacement** — it
      depends on `ollama` and only adds `/usr/lib/ollama/cuda_v13/libggml-cuda.so`
      to the plain package's `libggml-cpu-*.so`. **Having both installed is
      correct**, and is what the demo box has (`ollama` 0.32.9-1 +
      `ollama-cuda` 0.32.15-1, GPU confirmed working despite the version skew).
      What is *not* safe is assuming: `nvidia-smi` looking healthy proves nothing,
      so verify with `ollama ps` and check the `PROCESSOR` column says GPU.
- [ ] **Stage 2b — Live Bake-Off.** ▶ *in progress, started 2026-08-30.* ⭐ *The demo. Depends on Stage 1 + Stage 2.*
      Benign traffic streams continuously into a tailed file; an **injection grid
      (attack type × camouflage level)** lets the audience fire attacks at both
      detectors on the same stream, side by side, with live precision/recall.
      Attack types: v1's brute force / impossible travel / enumeration, plus persistence
      (SSH key, cron), privilege-escalation chain, lateral movement. Levels: none /
      `slow` / `mimicry` / `ip_rotate` / `realistic-combo`.
      **Because the injector generates the attacks, ground truth is automatic** — both
      systems can be scored live. That is what makes it a running experiment rather
      than a slideshow, and it is the reason to build it this way.
      The three-act structure is: quiet baseline → obvious attack, *where the SIEM wins
      and we say so* → camouflaged attack, where the gap shows. **Act 2 is not "we fail
      to detect"** — v1 detects 100% of instances on clean data. It is "we both catch
      it; the SIEM hands you one clean alert, we hand you a pile of noise." That
      admission is what makes Act 3 believable.
      Un-rigging measures, all mandatory: third-party rules only; camouflage strategies
      pre-registered in git before the demo; **the examiner picks** attack and level
      from the grid rather than watching a scripted sequence; and include conditions
      where we lose — a demo that never loses reads as rigged even when it isn't.

      ✅ **The harness (`logdet-bakeoff`, `logdet_eval/bakeoff.py`).** One
      writer appends each line to both sinks in the same call — the file the
      detector service tails, and the file Wazuh's logcollector watches inside
      the container — so neither system can be handed a different corpus.
      Every line written is recorded in a manifest with its 1-based line
      number and its scenario/instance label, so **ground truth is automatic**
      and both systems reduce to a set of flagged line numbers scored by the
      kill point's own `scoring.measure_lines`. Attacks come from the existing
      scenario generators at the kill point's pre-registered magnitudes (15-25
      failures, 10-12 probes), camouflaged by the shared `camouflage_events`,
      then restamped to wall-clock so both systems see the attack *now*.
      Wazuh's alerts attribute by the raw line it echoes in `full_log`; ours
      attribute by `(second, message)`, because incidents carry the parsed
      event and not the raw line.
      Grid: `brute_force` / `impossible_travel` / `enumeration` ×
      `none` / `mimicry` / `rephrase` / `ip_rotate` / `slow` / `realistic-combo`.
      `--benign-only` is Act 1, `--grid` walks the whole thing, `--attack`
      narrows it to one row.

      **What the live instrument may and may not claim.** Wazuh keys its
      correlation on *arrival* time, so a run with time compressed, or a
      timing-based camouflage level, is not a measurement of Wazuh at all —
      its drop would be fixed by the harness. Those conditions are marked
      `measured: false`, rendered as `illustration`, and the report points at
      `results/killpoint/killpoint_paced_ambient0.05.md` for the real figure.
      `--compress` defaults to 1, so the default run is honest. The runner
      also **refuses to start** when the Wazuh container is not answering
      rather than degrading to a one-contestant table.

      ✅ **Pooling over repeats.** `--repeat n` (default 3) now fires each
      instance separately, scores it on its own lines, and pools the runs with
      `scoring.pool_runs` — the kill point's own pooler, which recomputes rates
      from summed counts rather than averaging them. The report prints the
      denominator (`100% (3/3)`, not `100%`) and the finest step the run can
      express (100/n points).

      ✅ **The grid the examiner clicks** —
      `streamlit run src/logdet_eval/bakeoff_dashboard.py`. Three attacks × six
      camouflage levels of Fire buttons, background traffic running on its own
      thread between firings so Act 1 is a *quiet* stream and not a stopped
      one, the firing on a worker thread so the page keeps repainting while an
      attack takes as long as it takes, and the scores plus the report as it
      would be written underneath. It lives in `logdet_eval/` because §5 runs
      the dependency one way only: a Fire button on the detector's own
      dashboard would put the injector inside the thing being measured.

      **Second live firing, 2026-08-30** (`results/bakeoff/bakeoff.md`), brute
      force at `none` then `rephrase`, **three instances each**, benign
      background at 0.5 lines/s:

      | level | ours (inst / lines) | Wazuh (inst / lines) | our alerts | Wazuh alerts |
      |---|---|---|---|---|
      | `none` | 100% (3/3) / 98% | 100% (3/3) / 94% | 179 | 190 |
      | `rephrase` | 100% (3/3) / 100% | 100% (3/3) / **29%** | 467 | 145 |

      **The differential is still +0.0pt, and repeating is not what fixes
      that.** Last session's reading — "instance detection saturates at one
      instance" — was only half the story. Pooling over three instances made
      the metric able to move in 33pt steps, and it did not move, because
      **both systems detected every instance in both conditions**: one
      surviving line is enough to call an instance detected, and at these
      magnitudes (15-25 failures) rewording never removes them all. That is a
      ceiling, not a granularity problem, and no number of repeats touches it.
      The report now says which of the two a `+0.0pt` row is, computed rather
      than asserted.

      **The line rate is what carries the mechanism live**, and it reproduces
      at three instances what it showed at one: rewording drops Wazuh from 94%
      to 29% of the attack's lines while this system stays at 100%. Our alert
      count goes *up* under `rephrase` (179 → 467), which is the documented
      behaviour — novel wording is more anomalous, not less.

      ✅ **Whole grid fired live, 2026-08-30** — all three attacks × six
      camouflage levels, three instances per cell, five `logdet-bakeoff`
      invocations, Wazuh up throughout. `results/bakeoff/bakeoff.md` carries
      the full table, the exact commands and the per-invocation JSON.

      **One cell moved, and it is the only cell that could:**

      | attack / level | ours (inst / lines) | Wazuh (inst / lines) | differential |
      |---|---|---|---|
      | `impossible_travel` / `rephrase` | 100% (3/3) / 100% | **0% (0/3) / 0%** | **+100.0pt** |
      | every other measured cell | 100% (3/3) | 100% (3/3) | +0.0pt |

      Impossible travel is a **two-line** attack, so rewording takes *every*
      line out of Wazuh's sshd decoder. A 15-25 line brute force or a 10-12
      line enumeration always leaves a line behind, and one surviving line is
      enough to call an instance detected — which is why the other eleven
      measured cells sit at the ceiling. This is the same `rephrase` mechanism
      the kill point measured, seen at the one attack size where it can flip an
      instance rather than only a line rate.

      **The line rate reproduces the mechanism on the other two attacks:**
      rewording costs Wazuh 91% → 29% of brute-force lines and 100% → 34% of
      enumeration lines, while ours holds at 97-100%. The brute-force `rephrase`
      figure (29%) is identical to the previous firing's, which is the strongest
      reproducibility check this instrument has had.

      **Wazuh's 100% on impossible travel is level-3 saturation, not
      correlation** — checked, not assumed: 135 of 135 successful-login alerts
      in the container's `alerts.json` are rule **5715 "sshd: authentication
      success", level 3**. It flags every successful login, so it flags the
      attack's two lines without ever knowing the travel was impossible, and
      rewording those two lines is what takes it to 0%.

      **Two rows where we look worse, both kept in the table.** Our line rate on
      `impossible_travel` / `none` is 50% — the known display gap, where only
      the arriving login is carried into the incident (Known Issues; Stage 4
      fixes it), not a detection miss. And the `impossible_travel` /
      `realistic-combo` illustration row is **67% (2/3) for us against Wazuh's
      100%**, the first live cell this system loses, consistent with the paced
      kill point's `realistic-combo` loss.

      **Alert volume rises with every camouflage level on every attack** — 77 →
      436 on enumeration, 404 → 2257 on impossible travel. Novel wording is
      more anomalous, not less, so robustness is paid for in noise. Precision is
      still the weakness.

      ✅ **Grid page hand-checked** by driving the real script through
      Streamlit's `AppTest` — open the stream, fire a cell, worker thread, the
      scored table and the report expander, no exceptions. It found one defect,
      now fixed: the page started the stream *before* `open_session` truncates
      the log, so opening it after any earlier run replayed that run's file and
      Act 1 began with somebody else's incidents on screen (measured: 500 lines
      parsed and 31 incidents against 0 lines written). The CLI had the order
      right; the page did not.

      ✅ **The merged report has a generator.** `logdet-bakeoff --merge <dirs>`
      rebuilds `results/bakeoff/bakeoff.md` from the per-invocation JSON — it
      fires nothing, orders the cells by the grid rather than by the order the
      runs happened, refuses a cell that appears in two runs, and derives each
      source directory's `logdet-bakeoff` command from the rows themselves so
      the printed provenance cannot drift from the data beside it. The
      interpretation is *not* generated: it lives in `results/bakeoff/notes.md`
      and is appended verbatim with `--notes`. Regenerating the committed
      report reproduces every table row unchanged.

      ✅ **Act 1 recorded live, 2026-08-30** (`results/bakeoff/act1_benign/`).
      30 benign lines at 0.5/s, no attack fired, so every alert is a false
      positive by construction:

      | system | lines flagged | share of the stream |
      |---|---|---|
      | this detector | 5 | 17% (in 3 incidents) |
      | Wazuh, level >=3 | 19 | 63% |

      Wazuh's figure is level-3 saturation — a single successful login is
      already an alert (rule 5715) — not a failure of its rules; ours is the
      precision weakness, visible with no attack present at all. One short run
      at one background rate, so it is a demo artifact, not a false-positive
      rate for either system.

      ✅ **Narration latency re-measured on the 4060 demo box, 2026-09-01**:
      **3.9s GPU / 18.2s CPU** (§2c). Every figure in
      `docs/presentation-2026-08-31/` was repointed from the 3050's 5.2s/24.2s
      and the deck rebuilt.

      Still to do: decide whether Stage 2b is finished or wants the
      Kali-generated attacks (§2d, currently Stage 6).
- [ ] **Stage 3 — Detection depth.** ▶ *in progress, started 2026-09-01.*
      **Drain3** online template mining replacing hand-written regex (makes the system
      source-agnostic; it is also what the log-anomaly literature uses).

      ✅ **Mining exists and is inspected; nothing consumes it yet.**
      `logdet/templating.py` wraps Drain3 with the project's config (no stray
      `drain3.ini`), and `LineParser(miner=...)` adds a **`template_id`**
      column beside the existing regex `template`. It is **opt-in**
      (`logdet-preprocess --drain3`), so a default parse still produces exactly
      the columns every number in `results/` came from — verified by SHA-256
      over every parsed record of `synthetic.log` (751) and `SSH.log`
      (655,147): **identical before and after**, so §4 was not triggered.
      Recorded per line is the **cluster id, not the template text**, because
      the text widens as more lines arrive and a text stored per line leaves
      early rows disagreeing with late rows about what one cluster is.

      ✅ **Inspected on LogHub OpenSSH before any detection code reads it** —
      `logdet-templates`, report in `results/templates/`. All 655,147 lines,
      13s:

      | | |
      |---|---|
      | Regex templates (`template_message`) | **5,669** |
      | Mined templates (Drain3) | **45** |
      | Regex templates split across >1 cluster | **0** |
      | Clusters covering >1 regex template | 25 |

      **The vocabulary settles** — 43 clusters by 250k lines, 45 at 655k — so
      it is a vocabulary and not a leak. The 126× reduction is almost entirely
      the regex leaving usernames in: 1,713 regex templates for
      `Invalid user <name> from <IP>` become one cluster.

      **Failed and Accepted password stay in separate clusters (10 vs 20).**
      That is the distinction this project detects on, and it survives.

      **Four merges do lose a distinction, and they are named in the report**
      (computed, not eyeballed: a collapsed position taking ≤6 values is a word,
      one taking hundreds is an identifier):

      | cluster | lines | absorbed |
      |---|---|---|
      | 6 | 20,271 | `Failed password` and `Failed none` — the auth *method* |
      | 8 | 46,642 | four disconnect reasons (`Bye Bye`, `Session closed`, …) |
      | 13 / 18 | 38,318 | `failure;` and `failures;` |
      | 43 | 6 | `<IP>` and `::` — IPv4 and IPv6 |

      None of them merge a success with a failure, so none blocks Stage 3, but
      cluster 6 is the one to watch: `Failed none` is a probe, not a password
      attempt.

      **Gotcha recorded in code:** `TemplateMiner.match` (frozen set, mines
      nothing) only matches a cluster whose template already carries `<*>`
      where the lines differ, so a set frozen after too little traffic reports
      novelty it has not earned.

      ✅ **Sequence model over those ids — `logdet/sequence_model.py`.** A
      first-order Markov transition model per actor, reporting the surprisal
      `-log P(template_i | template_{i-1})` of each observed transition. It
      re-ranks; it never re-flags. `is_anomaly` is untouched, so every number
      §4 asks for — line-level P/R/F1, instance detection clean and
      camouflaged, incident count — is identical with the model on or off, and
      **no camouflage re-run was owed**. Verified rather than argued: a unit
      test asserts `is_anomaly`, `ml_anomaly` and `impossible_travel` are
      unchanged, and the 751 → 130 → 94 batch and stream locks stayed green.

      **Where the signal consumes cleanly was measured, not chosen.**
      `logdet-sequence-report` scores both corpora that have ground truth:

      | | synthetic (751 lines) | kill-point OpenSSH (2,583) |
      |---|---|---|
      | Separation, fit on clean history | AUC **0.856** | AUC **0.912** |
      | Separation, fit on the frame it scores | 0.692 | **0.558** |
      | user key alone | 0.851 | **0.958** |
      | source-IP key alone | 0.230 | 0.758 |

      Three findings, each of which changed the design:

      **Fitting on the traffic being judged destroys the signal** — on the real
      corpus it collapses to 0.558, near a coin flip, because ambient brute
      force teaches the model that brute force is routine. The transition model
      is therefore fitted in `logdet-fit`, on history, exactly like the
      detector, and never inside the scoring path.

      **Keys go in precedence order — user first, source IP only where the
      user key is silent.** What the numbers support is the *ranking* of the
      keys, not the combining rule: the user key is much the stronger signal on
      both corpora. Taking the maximum across keys instead was measured and is
      a wash (0.852 vs 0.856 on synthetic, 0.923 vs 0.912 on the kill-point
      corpus), so precedence is kept for being the simpler rule, **not** for
      scoring better. The fallback earns its place by being the only key with
      anything to say about account enumeration, which varies the username on
      every line by design; the combined row sits below user-alone on the
      kill-point corpus because it adds rows the user key could not score at
      all — coverage bought at lower quality, not a regression.

      **The severity tier is the wrong consumption point, and that is a
      measured negative result.** An incident takes the highest tier of any
      line in it, so demotion is inert (identical notable set on both corpora)
      and promotion lifts a whole incident on one line — the notable set grew
      19 → 48 on synthetic and 72 → 84 on OpenSSH, and it never surfaced an
      attack the baseline missed. No threshold in the swept table beats leaving
      it off, so `SEQUENCE_SEVERITY_SHIFT = False`.

      ✅ **Adopted: the surprisal is the last tiebreaker in `triage.py`**,
      after event count and severity. Precision@5/@10/@20 unchanged on both
      corpora; the rank by which an analyst has seen every attack instance
      moves **16 → 12** (synthetic) and **65 → 39** (OpenSSH). Ranking on
      surprisal alone is not safe — it drops precision@5, because a lone rare
      transition outranks a twenty-event brute force. Incidents with no
      surprisal sort as 0.0, so the streaming path's order is exactly what it
      was.

      **This is a triage improvement, not a detection improvement, and must not
      be written up as one.** The same lines are flagged and the same incidents
      are grouped either way.

      Not done: peer-group baselines. Deferred deliberately — they fix cold
      start, which no number in `results/` measures, and every detection change
      costs the same §4 measurement regardless of how small the code is.

      ✅ **Alert suppression — `logdet/suppression.py`.** The first Stage 3
      change that clears `is_anomaly`, so §4 applied in full and was run in
      full. A flagged line is withdrawn only when **all four** hold: it is not
      an impossible-travel hit, it is **alone in its incident**, the model has
      a transition to score it with, and that transition is **not in the
      rarest tenth** of the fitted history. One pass, and provably
      non-cascading — removing a singleton cannot change any other incident's
      membership, so a second pass is a no-op.

      **The obvious version of the rule is inert, and that is measured.**
      "Suppress a *routine* transition" (at or below the fitted median) clears
      **0 of 59** eligible rows on the synthetic corpus and 13 of 63 on the
      kill-point corpus. The flagged rows already *are* the anomalous tail, so
      a line the embeddings found unusual almost never has a below-median
      transition — the two signals are positively correlated. The threshold
      adopted is the model's existing `rare_threshold`, reused rather than
      introduced.

      **Loneness is the safety guard; the surprisal is only selectivity** —
      computed in the report, not asserted. AUC of the surprisal at separating
      attack from benign:

      | population | synthetic | kill-point |
      |---|---|---|
      | all lines (the published figure) | 0.833 | 0.904 |
      | **flagged rows only** | **0.278** | **0.645** |
      | flagged **and** lone | 0.987 | 0.954 |

      Among flagged rows the signal runs *backwards* on the synthetic corpus,
      so suppressing on surprisal alone would preferentially delete attacks.
      It inverts under the loneness restriction only because the lone attack
      lines that exist are impossible-travel hits, which guard 1 removes
      anyway.

      **§4 items 1, 2, 4 — both clean corpora** (`results/suppression/suppression.md`).
      Zero attack lines suppressed at every threshold on either corpus:

      | corpus | P | R | instance detection | incidents |
      |---|---|---|---|---|
      | synthetic, off → on | 0.300 → 0.310 | 0.867 → **0.867** | 100% → **100%** | 94 → 90 |
      | kill-point OpenSSH, off → on | 0.206 → 0.248 | 0.570 → **0.570** | 100% → **100%** | 194 → **147** |

      **§4 item 3 — camouflage, 5 seeds, 9 conditions**
      (`results/suppression/suppression_adversarial.md`). Instance detection is
      **unchanged on every condition and unchanged seed by seed**: across all
      45 instance-firings suppression never removed the last surviving line of
      an instance. Alert volume falls ~4%.

      **The cost is real and sub-instance, and it lands exactly where it was
      predicted.** Two conditions lose attack lines; every other condition
      loses none:

      | condition | line rate off → on | attack lines removed |
      |---|---|---|
      | `slow` | 0.824 → 0.790 | 8 |
      | `realistic-combo` | 0.776 → 0.741 | 6 |

      The suppression *rate* carries the mechanism: ~3% of flagged lines on
      every condition, rising to 4.3% (`slow`) and 5.0% (`realistic-combo`).
      Spreading an attack in time makes its lines lone, and lone is what puts
      a line in the eligible pool. **`slow` is where any future strengthening
      of this rule breaks first.**

      ⛔ **q0.99 measured and rejected — the entry worth reading.** On clean
      data it is much the best-looking threshold: synthetic F1 0.446 → **0.624**
      and 94 → **44** incidents, against q0.90's 0.456 and 90. Under camouflage
      it surrenders the margin §4 says clean data hides:

      | condition | instance detection | line rate | attack lines removed |
      |---|---|---|---|
      | `slow` | 80.0% → **66.7% (−13.3pt)** | 0.824 → **0.266** | 130 |
      | `ip_rotate` | 84.4% → 80.0% (−4.4pt) | 0.837 → 0.601 | 55 |
      | `realistic-combo` | 91.1% → 88.9% (−2.2pt) | 0.776 → 0.471 | 52 |

      It halves alert volume across the suite (5,083 → 2,927 incidents) by
      deleting detections. This is the 2026-08-16 contamination lesson
      reproduced on a different knob.

      **Batch only, deliberately.** Loneness is not knowable at emit time — a
      line alone in this micro-batch may be joined by the next one — so
      suppressing in the stream would withdraw alerts the batch path keeps and
      break the streamed-equals-batch lock. Making it work there means
      deferring the decision by at least the incident window and re-verifying
      that lock. Not attempted; recorded as the blocker.

      527 tests pass (1 skipped), including both pinned regression locks. The
      locks stay green because neither the batch nor the stream path passes a
      sequence model, and suppression cannot fire without one.

      Next: the entity graph (Stage 4) is the natural follow-on — it makes the
      impossible-travel display gap fixable and gives grouping something better
      than union-find to decide "lone" with. If suppression is to be pushed
      harder first, the honest lever is **not** a looser threshold (q0.99 is
      already measured and rejected) but a *better loneness test*, since that
      is the guard doing the safety work.
      **Sequence modelling** — the highest-value single change available. v1 scores each
      line independently, but attacks are sequences; a single odd line is weak evidence
      and an odd *sequence* is strong evidence. This is the root cause of the 0.29
      precision. Even a Markov transition model over template IDs per user would help.
      Also: peer-group baselines (fixes cold start), score calibration so severity tiers
      mean something numeric, drift handling.
- [ ] **Stage 4 — Correlation & MITRE.** ▶ *in progress, started 2026-09-03.*

      ✅ **The entity graph is in and grouping runs on it** —
      `logdet/entity_graph.py`. Users, source IPs, hosts and processes are
      nodes; events are edges bounded by the incident window;
      `group_anomalies` is now `components()` over that graph rather than a
      pairwise backward scan.

      **The partition is the old partition, and that is asserted rather than
      argued.** Chaining each entity's events consecutively is exact, not an
      approximation: if two events on one entity are within the window, every
      intermediate gap is too, and connectivity is transitive either way. The
      pre-Stage-4 algorithm is kept in `tests/test_entity_graph.py` as an
      oracle and the two are compared on 24 randomised frames and on a
      transitive chain. It is also O(events) per entity instead of
      O(events²).

      **Host and process are nodes but not grouping links.** LogHub OpenSSH is
      a single host (`LabSZ`) running `sshd`, so a host edge joins all 655,147
      lines into one incident — an entity every event shares says nothing
      about which events belong together.

      ✅ **Impossible-travel evidence — the Known Issue carried since v1 is
      closed.** The travel check compares a login with that user's previous
      login; the previous one is benign, so it was never flagged, never
      grouped and never shown, and the incident asserted "impossible travel"
      while displaying one of the two logins the conclusion is about. The
      graph retrieves it (`EntityGraph.preceding` over the user node) and it
      is carried in a new `context_events` field — batch pipeline, stream, the
      API's narrate call, the LLM prompt and the dashboard.

      **Evidence is not a detection, and the separation is structural.**
      `context_events` is not `events`: it does not count towards
      `event_count`, severity or triage, and the bake-off's `ours_flagged`
      walks `events`, so a benign line cannot be attributed to this detector
      as a flagged line. The LLM prompt is **byte-identical** when there is no
      evidence, which keeps the 592-token narration-latency measurement (§2c)
      comparable across the change.

      **§4: nothing detected changed, verified three ways.** The synthetic
      corpus still reads 751 lines → 130 flagged → 94 incidents in both the
      batch and the streamed path (both pinned locks green); all 94 incident
      entries are identical to the previous run on every pre-existing field,
      with `context_events` the only addition; and `is_anomaly` is untouched.
      No camouflage re-run was owed. All 3 travel incidents now carry their
      compared-against login, in batch and in the stream alike. 574 tests
      pass (1 skipped).

      **One stream-only defect found and fixed on the way.** Evidence was
      retrieved from `self.history`, which `_remember` prunes relative to the
      newest line *after* scoring — so a micro-batch spanning more than the
      retention window dropped the very login the hit was compared against, in
      the same call that detected it, and only 1 of 3 travel incidents carried
      evidence. The snapshot now uses the frame the batch was actually scored
      against, and evidence found once is kept when the incident grows.

      ⛔ **Both remaining structural items examined and declined, 2026-09-04**
      (`results/correlation/notes.md`). Neither passes §1's test.

      **Temporal decay on edges is a reparametrisation of the window, not a
      feature.** Grouping needs a hard partition, so a decayed weight has to be
      thresholded — and for any monotone decay `w(gap)` and threshold `t`,
      "edge exists iff `w(gap) >= t`" is exactly "edge exists iff
      `gap <= w⁻¹(t)`", i.e. a plain window of that size. Identical partition
      to `INCIDENT_WINDOW_MINUTES`, at the cost of the full §4 suite. It would
      only be real if something consumed a *continuous* weight, and the one
      candidate consumer — suppression's loneness guard — was measured and
      rejected in both variants the day before, for a reason decay cannot
      touch: the attack lines suppression costs have no benign traffic around
      them at all, recent or old.

      **Multi-source correlation has almost nothing to correlate.**
      `data/external/Linux.log` is the only real corpus here with multi-service
      auth on one host — 9,666 auth events across sshd (5,009), ftpd (3,453),
      su (944), telnetd (179), klogind (50), login (31). Cross-service links
      inside the 30-minute window, using exactly the condition
      `EntityGraph.edges` tests:

      | join key | links | on what |
      |---|---|---|
      | `source_ip` | **2** | one IP, ftpd ↔ klogind |
      | `user` | 70 | **all 70 on `root`** |

      Corpus-wide and ignoring the window: **1 source IP of 331** and 2 users
      of 14 appear in more than one service. `ftpd` and `telnetd` carry no
      username the parser can lift at all. And the user column is worse than it
      looks — every one of the 70 links is `root`, the account every service
      names, which is the same "an entity every event shares carries no
      information" failure the graph already refuses for host and process.
      Fed a second source, the graph would find **one** genuine cross-service
      link in 9,666 events; anything measurable would have to be an attack we
      authored and planted across two logs.

      The structure to support it already exists (`ENTITY_COLUMNS` carries host
      and process as nodes). What is missing is a corpus, not code — so this
      belongs at **Stage 6** (§2d's Kali runner produces real cross-source
      traffic with ground truth captured at generation time) and **Stage 7**
      (ECS normalisation). **Stage 4 is closed.**

      ✅ **ATT&CK STIX ingest, tactic/kill-chain mapping and the detection
      coverage matrix — done 2026-09-04.** `logdet/attack.py` fetches the
      official Enterprise bundle **pinned at ATT&CK 19.2** and verified by
      SHA-256, then projects it to a ~10KB **committed** index
      (`src/logdet/data/attack_index.json`), so the pipeline stays offline and
      deterministic and a version bump is a reviewable diff. Refresh with
      `logdet-attack --refresh`.

      **STIX cannot replace the table, and pretending otherwise would have been
      the mistake.** ATT&CK publishes no keywords for log lines. The split is
      now explicit: *authored* = which message means which technique ID;
      *ATT&CK* = what that ID is. `MITRE_LOOKUP` carries keywords and an ID and
      nothing else — a test fails if a `technique_name` or `tactic` is typed
      back into it.

      **The hand-typed table had already drifted, which is the argument for
      the change**: ATT&CK 19 renamed T1070's tactic from Defense Evasion to
      **Stealth**, T1078 carries **four** tactics where two were typed, and
      T1021.004's STIX name is the bare `SSH` (now displayed ATT&CK's own way,
      `Remote Services: SSH`, by following the sub-technique parent). The index
      builder **refuses** an ID ATT&CK does not carry, or has revoked or
      deprecated.

      **Kill-chain mapping**: each incident gains a `kill_chain` field — the
      tactics its techniques touch, de-duplicated and in ATT&CK matrix order,
      each with the techniques that put it there. The dashboard renders it under
      the technique list. Techniques within an incident are now ordered by
      kill-chain position rather than match order.

      **§4 was not triggered, and that is verified rather than argued.** This is
      enrichment: `is_anomaly`, grouping and severity are untouched. The
      synthetic corpus still reads **751 → 130 → 94** in batch and in the
      stream (both pinned locks green), and all 94 incident entries are
      **identical on every pre-existing field**, with identical technique-ID
      sets — the only change is T1078's tactic string widening to ATT&CK's four
      tactics, plus the new `kill_chain` field. One consequence to record: the
      narration prompt for an incident carrying T1078 grows by 33 characters
      (~8 tokens), so §2c's 592-token smoke incident is now ~600 — latency
      figures across machines stay comparable, but a re-measure at that
      precision would not.

      ✅ **Detection coverage matrix — `logdet-coverage`,
      `results/coverage/`.** Answers "which techniques can this system even
      see?" with a denominator computed from ATT&CK rather than chosen here: a
      technique is visible when one of ATT&CK's *own* detection strategies has
      an analytic whose log source is one we read (three hops through the
      bundle: `detects` → strategy → analytic → log source).

      **Two denominators, reported separately and never merged.** Strict =
      ATT&CK's syslog sources (`linux:syslog`, `linux:auth`, `linux:cron`): 86
      techniques. Wider = plus auditd's authentication events, which record the
      same events from another subsystem: 89. The second half is an authored
      claim and is labelled as one.

      | | |
      |---|---|
      | Techniques the table maps | **11** |
      | ...inside the strict universe | **1 of 86** (T1021.004) |
      | ...inside the wider universe | 2 of 89 (adds T1110) |
      | ...**outside both** | **9** |
      | Mapped and observed on a corpus | 6 |
      | Mapped but **never** observed | **5** |

      **The number worth reading is 9, not 1.** ATT&CK's Linux analytic for
      T1110 Brute Force is `auditd:USER_LOGIN`, not syslog — so nine of our
      eleven techniques are asserted from telemetry a third party would not
      credit for them. That cuts both ways and both readings are in
      `results/coverage/notes.md`.

      **Five of eleven have never fired on either corpus** — T1041, T1046,
      T1053, T1070, T1098, whose keywords (`scp`, `wget`, `crontab`, `useradd`,
      `shred`) describe traffic an sshd auth log does not contain. They are
      unexercised claims, not misses. T1110 matches **457,880 of 655,147**
      OpenSSH lines (70%), the same fact `corpus_openssh.py` was built around.
      The matrix counts *matches*, not true positives: whether the enrichment is
      correct on the lines it does match is unmeasured and needs
      technique-level ground truth no corpus here has.

      604 tests pass (`-m "not slow"`), plus both pinned regression locks.

      ✅ **Graph loneness for suppression — built, measured on the full §4
      suite, and both graph tests rejected** (`results/suppression/loneness/`).
      This is the question the graph was retained for: `EntityGraph` can say how
      much traffic, flagged *or benign*, an alert's user and IP account for,
      which union-find could not. Two tests were built beside the shipped one
      (`SUPPRESSION_LONENESS` in config): **`quiet`** (lone only when nothing at
      all touches the entities — the safety end) and **`share@r`** (lone when
      the *flagged* share of the neighbourhood is ≤ r — the selectivity end,
      with r=0.0 reproducing the shipped test).

      **§4 items 1, 2, 4 — both clean corpora** (`results/suppression/suppression.md`).
      Recall 0.570 and instance detection 100% on every arm; kill-point OpenSSH:

      | loneness | P | incidents | suppressed (attack) | attack lines in the lone pool |
      |---|---|---|---|---|
      | off | 0.206 | 194 | — | — |
      | `quiet` | 0.218 | 179 | 15 (0) | **0** |
      | `incident` (shipped) | 0.248 | 147 | 47 (0) | 3 |
      | `share@0.50` | 0.260 | 142 | 58 (0) | **9** |

      **§4 item 3 — camouflage, 5 seeds, 9 conditions, four arms.** Instance
      detection is **unchanged on every arm and every condition** (100% except
      `slow` 80.0%, `ip_rotate` 84.4%, `realistic-combo` 91.1%). The decision is
      in the columns beside it:

      | | `slow` attack lines lost | `realistic-combo` | `baseline` incidents | `slow` incidents |
      |---|---|---|---|---|
      | off | — | — | 519 | 656 |
      | `incident` | 8 | 6 | **497** | **626** |
      | `quiet` | **8** | **6** | 503 | 632 |
      | `share@0.50` | 8 (+1 `temporal`, +1 `volume`) | 6 | 497 | 626 |

      **`quiet` is strictly dominated, and that is the finding.** It costs the
      *same* attack lines as the shipped test while cleaning up fewer benign
      ones. The attack lines suppression loses are **genuinely isolated**, so a
      test demanding total isolation does not protect them — seeing the benign
      traffic around an alert does not help, because on the conditions that cost
      evidence there is none. The intuition the graph was built on was wrong,
      and only the camouflage suite could say so.

      **`share@0.50` buys nothing under camouflage and costs evidence**:
      identical incident counts to the shipped test on all nine conditions, plus
      one attack line on `temporal` and one on `volume`, both previously free.
      It looks good on clean data — kill-point 147 → 142 incidents, precision
      0.248 → 0.260 — which is the q0.99 mistake on the guard instead of the
      threshold.

      **What the graph did earn**: `share@0.00` reproduces `incident` exactly on
      both real corpora (84/84 lone rows on synthetic, 158/158 on kill-point),
      so the graph path and the grouper agree outside the unit test. The
      neighbourhood counts stay as an instrument. `SUPPRESSION_LONENESS` stays
      `"incident"`, pinned by a test. 573 tests pass (`-m "not slow"`), and both
      pinned regression locks — batch and streamed 751 → 130 → 94 — stay green.
- [ ] **Stage 5 — LLM layer maturity.** ▶ *in progress, started 2026-09-04.*

      ✅ **Automated faithfulness evaluation — `logdet-faithfulness`,
      `results/faithfulness/`.** The first measurement of the claim §2 makes.
      Every narrative is checked against **the exact prompt that produced it**;
      a claim is grounded when the thing it names is in that prompt. Five claim
      kinds are extractable deterministically — `technique`, `ip`, `user`,
      `time`, `quantity` — plus a hard regression on the literal token `nan`.
      **No LLM judge**, deliberately: one would put an unmeasured model inside
      the measurement.

      **The control arm is free and it is the deployed system.** 41 of 94
      synthetic incidents and **150 of 193** OpenSSH incidents match no
      technique, so their prompt carries the *"No known technique matched"*
      fallback and **any** technique ID in their narrative is invented by
      definition. Without that split, a low invention rate could not be told
      apart from a model that simply copies what it is handed.

      ⛔ **The headline is a failed constraint.** §2 said *"the LLM never
      invents MITRE technique IDs"*. phi3 does:

      | | synthetic (94) | kill-point OpenSSH (193) |
      |---|---|---|
      | Fully faithful narratives | 57/94 | 94/193 |
      | Technique mentions | 142 | 197 |
      | **...invented** | **47 (33.1%)** | **119 (60.4%)** |
      | invented, handed ≥1 technique | 23/118 (19%) | 12/90 (13%) |
      | invented, handed none (control) | **24/24 (100%)** | **107/107 (100%)** |
      | `nan` leaks | **0** | **0** |

      **Grounding helps and does not suffice**, and the failure concentrates
      where the detector has least to say: handed a technique list phi3 mostly
      stays inside it, handed none it fills the hole every time. All 24 distinct
      invented IDs on the synthetic corpus are **real ATT&CK identifiers**
      (checked against the pinned 19.2 bundle), **6 of them revoked or
      deprecated** — exactly what `attack.py` refuses to carry — and several
      impossible on an sshd log (T1047 WMI, T1207 Rogue Domain Controller). The
      names are often wrong too: *"T1567 - Failed Authentication"* (it is
      Exfiltration Over Web Service).

      **The worst failures are not technique IDs.** Seven narratives across the
      two corpora fabricate an entire **incident summary block in the voice of
      the system** — incident 7 was one event at 08:21:00 with no user and no
      IP, and its narrative opens *"Incident summary: - 10 anomalous events from
      2026-07-14 08:59:30 ... Distinct source IPs (2): [192.168.1.10, ...]"*.
      That is the failure that would survive a demo unchallenged.

      **What held**: `nan` never appeared on either corpus (first evidence, not
      assertion, that `_field` works); IPs invented 1/61 and 5/193; no
      misattribution to a real account.

      **The checker's own precision was measured before its output was quoted.**
      phi3 rewrites 13:38 as "1:38 PM", which is a correct restatement — before
      that was handled the `time` column read **57.3%** ungrounded on synthetic
      and it now reads 10.8%. The user check trades recall for precision (a name
      counts only when quoted or when the corpus contains it, because prose puts
      English words in username position constantly); a stopword list was tried
      first and measured failing on the first three real narratives. Both limits
      are stated in `results/faithfulness/notes.md`.

      **`--rescore` re-checks saved narratives without calling the model**, so
      fixing an extraction rule costs nothing and cannot change the narratives
      under itself. 28 new tests, most asserting a *planted* hallucination is
      caught; 634 pass (`-m "not slow"`), plus both pinned regression locks. §4 did not apply — nothing here
      touches detection, grouping or scoring.

      ✅ **All three follow-ons built and measured on both corpora, 2026-09-04**
      (`results/faithfulness/arms/`). Two fixed the failure; the third found
      nothing to fix, and that is the finding in it.

      | arm | invented IDs, synthetic | OpenSSH | fully faithful, syn / OpenSSH |
      |---|---|---|---|
      | prose, original prompt | **47 of 142** | **119 of 197** | 57/94 / 94/193 |
      | prose, reworded empty-match | 12 of 101 | 6 of 79 | 78/94 / 174/193 |
      | **structured JSON, validated** | **0 of 65** | **0 of 58** | **88/94 / 187/193** |

      **The empty-match prompt was most of the failure, and it was a wording
      bug.** The fallback said "No known technique matched" while instruction 2
      still asked *which ATT&CK stage the incident progresses through* — the
      prompt demanded a stage with nothing to answer from. Stating that no
      technique applying **is** the correct answer takes that arm from
      **24/24 and 107/107 invented to 0 and 0**, with narrative length
      unchanged (median 1261 characters against 1287), so the model answers
      rather than refuses. The grounded arm's prompt is **byte-identical**
      across those two runs, so it doubles as a variance control: it moved
      23/118 → 12/101 and 12/90 → 6/79 on identical input, which puts
      run-to-run noise at ~10 mentions.

      ✅ **Structured JSON output is now the default** (`LLM_STRUCTURED_OUTPUT`,
      pinned by a test). The technique claim moves into a named field that
      `validate_structured` checks against the grounded list, and a rejected ID
      is dropped before rendering. **0 invented IDs on both corpora, 0 replies
      that would not parse, 0 invented IPs or usernames, and the fabricated
      incident-summary block is gone** (7 → 2 → 0). Validation fired **once in
      287 narratives**, so most of the gain is the clearer task, not the
      enforcement catching a determined hallucinator — the enforcement's worth
      is that it does not depend on that compliance holding for another model.
      **The cost is brevity**: ~546 characters against prose's ~1287, because a
      model answering in JSON writes one or two sentences where it wrote four.
      It is also faster, 2.0s against 3.4s per incident on the 4060.

      ⛔ **The technique-*name* check finds nothing — 0 wrong of 43 and 0 of 33.**
      Not a checker that fails to fire: measured against the full 54MB bundle,
      names beside an **invented** ID are wrong **39 of 40** and **61 of 64**
      (`invented_name_check.py`) — *"T1046: Pass the Hash"*, *"T1078: Port
      Scan"*. The invention is **whole-cloth**, an ID and a name made up
      together; handed a real technique, phi3 names it correctly every time in
      this sample. The check stays as a regression guard on a failure that does
      not currently occur.

      Two limits carried forward. A **dropped ID is invisible to the reader** —
      it is recorded in `StructuredNarrative.dropped` and in the harness, but
      nothing surfaces it in the dashboard or the API. And this still measures
      **entities, not stories**: a structured narrative can ground every ID, IP
      and count and still assert a causal order the log does not support.

      §4 did not apply to any of it — nothing here touches detection, grouping
      or scoring, and both pinned regression locks (batch and streamed
      751 → 130 → 94) stay green. 657 tests pass (`-m "not slow"`).

      Still to do: model routing (small/fast for triage lines, larger for full
      narratives); retrieval over ATT&CK text; and deciding whether a dropped
      technique should be shown to the analyst rather than only logged.
- [ ] **Stage 6 — Adversarial platform.** ⭐ *The differentiator.* More strategies; an
      **adaptive adversary** that queries the detector and optimises against it (far
      stronger than v1's seven fixed transformations); **Kali-generated authentic
      attacks** (§2d) replacing injected synthetic lines for the un-camouflaged case;
      independent red-teaming by other people. Long-term this is the publishable part.
- [ ] **Stage 7 — Multi-source & deployment.** Auth + syslog + web + journald normalised
      onto a common schema (**ECS** is the standard; adopting it buys interop).
      Collector/analyzer split, Docker compose. This is where the project outgrows the
      hardware — it is last for that reason.

### Known issues / TODO carried over from v1

- **Precision 0.29 / 94 incidents for 9 real attacks** is the headline weakness.
  `CONTAMINATION=0.10` was tested as a fix and **rejected on adversarial evidence**
  (`docs/results.v1/contamination_retune.md`) — it degrades `mimicry` 100%→93% and
  `realistic-combo` 91%→87%. Contamination is not the lever. Sequence modelling
  (Stage 3) is the real fix. Untried cheap wins: suppress singleton incidents with no
  MITRE match, recalibrate `SEVERITY_THRESHOLDS`.
- ~~**The narrative prose invents MITRE technique IDs — 33% of technique
  mentions on the synthetic corpus, 60% on OpenSSH.**~~ **Fixed 2026-09-04** by
  the reworded empty-match prompt plus structured JSON output with the technique
  field validated against the grounded list: **0 invented IDs on both corpora**,
  and the fabricated incident-summary block is gone (`results/faithfulness/arms/`).
  Two things still hold from the original entry. Narratives produced *before*
  this change (`results/faithfulness/`, `results/sample_narratives.md`, any
  committed `incidents.json`) still carry invented IDs, several of them revoked
  or deprecated ATT&CK identifiers rather than fabricated strings, so **do not
  quote a stored narrative's technique IDs — quote `mitre_techniques`**. And the
  enforcement covers the technique field only: prose fields are still prose, and
  faithfulness is still measured on entities rather than on the story.
- **Scenario B (impossible travel) is detected entirely by the hand-written rule** —
  the embeddings contribute nothing, because both login legs are identical vectors after
  IP masking. Never claim "embedding-based detection catches impossible travel."
- ~~**Impossible-travel incidents show the conclusion without the evidence.**~~
  **Fixed 2026-09-03** by the entity graph (Stage 4): the compared-against login
  is retrieved via the user node and carried in `context_events`, kept out of
  `events`/`event_count` so it is evidence and never a detection. Verified a
  no-op on every measured number — 751 → 130 → 94 unchanged in batch and stream.
- **The v1 rule baseline is near-oracle by construction** — the corpus is built from the
  same three attack templates the rules encode. Stage 1's third-party rulesets are the
  honest fix.
- `preprocessing.py`'s `__main__` is a required-args CLI, so it has no no-arg smoke test.
  Moot once pytest lands in Stage 0.
- ~~**`Linux.log` parses at only 76%.**~~ **Fixed 2026-08-30.** The process
  field now accepts parentheses (`[\w\-/.()]+`), so `su(pam_unix)[2077]:` and
  journald's `(systemd)` / `(sd-pam)` parse. Linux.log went **75.98% → 99.37%**
  and the live journal on this box went 11/22 → 22/22. Verified a no-op where
  it matters: the parsed output of `synthetic.log` (751 lines) and `SSH.log`
  (655,147 lines) is **byte-identical before and after** — SHA-256 over every
  parsed record — so no number in `results/` moved and §4 was not triggered.
- **Alert volume is worse on real data than the v1 headline.** The clean
  kill-point corpus (2,532 lines, 9 attack instances) produces **193 incidents**
  against v1's 94 on 751 synthetic lines. Instance detection is still 100%. More
  evidence that precision, not recall, is the problem to solve — and that
  synthetic data was flattering it.
- **Only one bake-off session may write the live log at a time.** A grid page
  left open with its stream running keeps a background-traffic thread writing to
  `data/live/bakeoff.log`; starting a second bake-off (another tab, or the CLI)
  puts two writers on one file and the run then reports **0% for this detector**
  while Wazuh looks normal. Nothing is broken — the same condition on an unused
  log path scores 100%. Close the stream on any page you are not using before
  firing. Found 2026-08-31 while capturing demo screenshots.
- **After any reboot the Wazuh container comes back `Exited (255)` and must be
  restarted (`docker start wazuh`), and `wazuh-analysisd` needs ~20-30s before
  `wazuh-logtest` will answer.** `killpoint.py` probes availability *once at
  startup* and silently proceeds detector-only if the container is down — which
  yields an `INCOMPLETE` run after ~40 minutes of compute. **Check
  `docker ps --filter name=wazuh` and confirm the log's first lines carry no
  "Wazuh container unavailable" warning before walking away from a run.**
- **A kill-point run is ~40 min of saturating CPU (~14W).** Two runs were lost to
  a machine reboot mid-flight; per-condition checkpointing to
  `killpoint_ambient0.05.partial.json` now bounds that loss to one condition.
  Do not run the test suite concurrently — it competes for the same cores and
  measurably slows the measurement.
- v1's severity tiers do not cleanly separate precision by tier (medium is noisier than
  low). Informal calls against a 45-line ground truth, never calibrated. Stage 3.
- **The committed 2026-08-18 `results/adversarial_results.json` no longer reproduces
  exactly at HEAD.** A fresh 5-seed control run (2026-09-03) matches it on 8 of 9
  conditions; `realistic-combo` reports **673 incidents against the committed 670**,
  with **line and instance detection rates identical**. That artifact predates the
  2026-08-30 preprocessing widening, which was verified byte-identical only on
  `synthetic.log` and `SSH.log` — never on a camouflaged corpus, and `noise`/
  `realistic-combo` inject `CRON`/`systemd` filler the original corpora do not
  contain. Not caused by suppression: control and treatment arms were run in the
  same session on the same code. Worth an hour to confirm the cause and re-cut the
  artifact; until then quote the fresh control in `results/suppression/adv_off/`,
  not the committed file.
- **Alert suppression is batch-only and must stay that way until the stream can
  defer.** Loneness is not knowable at emit time, so suppressing in
  `StreamProcessor` would withdraw alerts the batch path keeps and break the
  streamed-equals-batch lock. Nothing in the stream passes a sequence model, so it
  cannot fire there by accident today — but wiring one in without a deferral window
  would silently break the equivalence that makes streamed numbers comparable to
  `results/`.

---

## 3b. Dataset Strategy

**Note:** HDFS and BGL *are* LogHub datasets — LogHub is the collection containing HDFS,
BGL, Thunderbird, OpenSSH, Linux, Hadoop and others. The choice is *which corpus*, and
it splits along a line that matters enormously here.

| Corpus | Size (verify before use) | Labels | Contains attacks? | Use here |
|---|---|---|---|---|
| **OpenSSH** | ~655k lines | none | **Yes** — real brute force / enumeration from the open internet | ⭐ **primary** |
| **Linux** | ~25k lines | none | some real auth events | companion |
| **BGL** | ~4.7M lines | per **line** | no — hardware/kernel faults | optional, secondary |
| **HDFS** | ~11M lines | per **block** | no — disk/replication faults | **skip** |
| v1 synthetic | 751 lines | full ground truth | yes, authored | keep as regression corpus |

### Why not HDFS or BGL as primary

They are labelled, which is why the literature uses them. But their "anomalies" are
**system faults, not adversarial behaviour** — no attacker chose to be there. Three
consequences, all fatal to this project's actual contributions:

- **MITRE mapping has nothing to map.** There is no technique ID for a failed block replication.
- **Attack narrative has no attacker.** Novelty pillar #1 goes dark.
- **Camouflage is meaningless.** You cannot hide a disk failure — there is no adversary
  making choices. The north star (§1) goes dark too.

Running on HDFS/BGL would benchmark the *anomaly detection layer* — the layer this
project explicitly does not claim as its contribution — while switching off both things
that make it distinctive.

If literature comparability is later wanted, prefer **BGL over HDFS**: its per-line
labels drop straight into the existing line-level P/R/F1 harness, whereas HDFS's
block-level labels force restructuring the entire evaluation to block granularity for
no gain to any claim this project makes.

### Evaluating OpenSSH without labels

OpenSSH has no ground truth and 655k lines cannot be hand-labelled. Two complementary
methods, neither requiring full labelling:

1. **Precision@k with manual verification** — run the pipeline, take the top 20-50
   ranked incidents, verify each by hand, report what fraction are genuine. A legitimate
   and commonly used method for unlabelled corpora, costs an afternoon, and *"it found
   real attacks in real logs nobody labelled for it"* is a stronger claim than any F1 on
   authored data.
2. **Inject v1's attack scenarios into the real benign traffic** — gives exact ground
   truth for the injected instances against a realistic background, which is what the
   §1b kill-point experiment needs.

### Note for Stage 3

Sequence modelling **cannot be trained on the 751-line synthetic corpus** — it is far
too thin. It depends on real data landing first, which is another reason Stage 1
precedes Stage 3.

---

## 4. Benchmark Discipline (the rule that makes this project mean anything)

**No change to detection, grouping, or scoring lands without re-running the evaluation
suite and recording the delta.** Not "it looks better." Numbers.

Every such change must report, at minimum:

1. Line-level P/R/F1 vs `docs/results.v1/`
2. Instance detection on the clean corpus
3. **Instance detection under camouflage** — pooled over ≥5 seeds
4. Alert volume (incident count)

Item 3 is not optional and it is the one people skip. The single hardest-won lesson
from v1:

> **Any tuning validated only on clean data must be re-validated under camouflage.
> Clean instance detection saturates at 100% and hides exactly the safety margin that
> camouflage eats first.**

This was learned the expensive way — see the 2026-08-16 contamination entry in
`docs/CLAUDE.v1.md`. A change that improves clean precision and quietly costs 7 points
of mimicry robustness is a **bad change**, and without item 3 you cannot see it.

Single-seed results are also not admissible for instance detection: with 3 instances per
scenario a single seed moves the number in 33% steps. v1 observed `ip_rotate` reading
100% at one seed and 84% pooled over five.

---

## 5. Target Architecture

Where this is going. Not all of it exists yet — build toward it stage by stage.

```
  ingestion            journald · file tail · replay · (later: web/syslog/multi-host)
      ↓                normalise → ECS-style common event schema
  parsing              Drain3 online template mining  (replaces v1 hand regex)
      ↓
  storage              SQLite/DuckDB: events, templates, entities, incidents, scores
      ↓
  detection            per-line: embeddings + Isolation Forest   (v1, kept)
                       per-sequence: Markov/DeepLog over template IDs   (Stage 3)
                       peer-group baselines · physics rules · calibration
      ↓
  correlation          entity graph (user/IP/host/process), temporal decay  (Stage 4)
      ↓                → incidents
  enrichment           ATT&CK STIX mapping · Sigma tags · coverage matrix
      ↓
  explanation          LLM narrative, structured output, grounded-only   (Stage 5)
      ↓
  interfaces           FastAPI service · Streamlit dashboard · CLI

  evaluation/          ⭐ runs against ALL of the above, every commit
    benchmark harness  · synthetic corpus (v1) · LogHub OpenSSH/Linux
    baselines          · Wazuh manager · Sigma rules · v1 self-written rules
    adversarial        · fixed strategies (v1) · adaptive adversary (Stage 6)
```

**Architectural rule inherited from v1 and still binding:** the evaluation track must
never be imported by the pipeline, and baseline rule implementations must never leak
into detection. Measuring yourself with code you also depend on is how benchmarks lie.

---

## 6. Coding Conventions

Changed from v1 where noted.

- Python 3.11+. Type hints on function signatures.
- **CHANGED: real tests.** `pytest` under `tests/`, not v1's `if __name__ == "__main__"`
  smoke-test convention. That convention existed because v1 had no time for a test
  suite; this repo does. Keep modules runnable standalone where it is genuinely useful
  for debugging, but correctness is asserted in `tests/`.
- Docstring at the top of every module explaining its role in the pipeline.
- Config in `src/<pkg>/config.py`, never magic numbers scattered through modules.
- New dependencies go in `pyproject.toml` via `uv add` **and** get a Decision Log entry.
- Keep functions small enough to paste into a chat for debugging.
- Prefer readable over clever.
- **Never overwrite `docs/results.v1/`.** New results go to `results/`.

---

## 7. Session Protocol

**At session start:**
1. Read this file
2. `git log --oneline -5`
3. Check the Progress Tracker → identify current stage
4. Confirm the session goal with the user before writing code

**During:**
- One stage at a time. Do not jump ahead.
- Detection changes → run the benchmark suite (section 4). No exceptions.
- Something breaks outside the session goal → log it under Known Issues, do not rabbit-hole.

**At session end:**
1. Run tests + the relevant benchmarks
2. Commit (conventional prefixes: `feat: fix: chore: docs: eval: refactor:`)
3. Update the Progress Tracker
4. Append to the Decision Log if a technical decision was made
5. Tell the user in one line what the next session should tackle

**At every milestone, offer to start a fresh chat — do not wait to be asked.**
Requested by the user 2026-08-19. A milestone means: a kill-point or benchmark run
finished and written up, a stage checked off, a decision logged, work committed, or a
long debugging thread resolved. When one lands:

1. Finish the durable write-up **first** — commit, Progress Tracker, Decision Log.
   The point of a fresh chat is that nothing important lives only in the conversation,
   so suggesting one before the files are updated defeats it.
2. Then say plainly that this is a good place to start a new chat or compact, and give
   the one-line handoff of what the next session picks up.

Never suggest it mid-task, mid-run, or while something is unresolved — a fresh chat in
the middle of a 40-minute measurement loses the thread for no saving.

---

## 8. Anti-Goals — push back before proceeding

Revised for the fork. Several v1 anti-goals are gone (see section 2b); these remain,
plus new ones that only become risks now that the timeline pressure is off.

- ❌ **Moving, softening, or reinterpreting the §1b kill point after seeing results.**
  The most important rule in this file.
- ❌ **Scripting the demo narrative before the measurement exists** — it creates
  pressure to tune until reality agrees with the script.
- ❌ **Fine-tuning the narrative LLM.** QLoRA on a 3-8B model is technically possible
  on the 4060, which is exactly why this needs to stay an explicit anti-goal rather
  than a hardware limitation. It does not fix the detection problem, and it makes
  results much harder to reproduce.
- ❌ **Clustering the two laptops for compute** — every model fits on one 8GB GPU;
  splitting across a gigabit link makes inference slower and adds a demo-day failure
  class. Split by *role* (§2c), never by compute.
- ❌ **Making the GPU or the two-machine link required** — CPU single-box is the floor
  and must always work.
- ❌ **Auto-response / blocking (SOAR)** — deliberate product stance. Recommend, never act.
- ❌ **Letting the LLM choose MITRE technique IDs** — the whole grounding design.
- ❌ **Hand-writing detection rules for attacks you also authored** — this is the subtle
  one, and v1's biggest methodological trap. Rules are fine, but they must come from a
  third party (Sigma, Wazuh) or be genuine physics/impossibility checks. The moment you
  write a rule for your own synthetic attack, your evaluation stops meaning anything.
- ❌ **Changing detection without re-running the adversarial suite** — see section 4.
- ❌ **Overwriting or "updating" the v1 results** — they are the historical baseline.
- ❌ **Chasing a 0% adversarial gap** — an honest measured gap beats a suspicious zero.
- ❌ **Rewriting from scratch** — the v1 detection code is proven and its evaluation
  artifacts are the most valuable thing here. Evolve it.
- ❌ **Building on this machine what this machine cannot run** — check free RAM and
  free VRAM before adding a stack. The figure in this file was ~5GB free; on the
  2026-08-30 dev box it is ~11GB, so verify on the machine in front of you rather
  than trusting either number. VRAM is now the tighter budget: 6GB on the dev box.
- ❌ **Assuming any of the above is a moral judgement about v1.** v1 was scoped for a
  2-3 week solo deadline and made the right calls for that. This is a different repo
  with different constraints.

---

## 9. Environment & Commands

```bash
export PATH="$HOME/.local/bin:$PATH"   # uv is not on PATH in fresh shells
uv sync
```

Since Stage 0 the code is two packages -- `src/logdet/` (pipeline) and
`src/logdet_eval/` (evaluation) -- with console entry points. The old
`python src/<module>.py` invocations no longer work.

```bash
uv run pytest                                   # ~30s, no model download
uv run pytest -m "not slow"                     # skip anything needing the embedding model

uv run logdet-preprocess --input data/raw/synthetic.log --output data/processed/parsed.csv --year 2026
uv run logdet-pipeline --input data/processed/parsed.csv --no-llm
uv run logdet-adversarial                       # robustness eval, 5 seeds, ~8 min
uv run logdet-adversarial --seeds 1             # quick pass while iterating
uv run logdet-evaluate                          # baseline comparison, ~5 min
uv run logdet-generate                          # regenerate the synthetic corpus
uv run logdet-samples                           # export sample narratives

# Stage 2 (live). Fit once on history, then score the stream against it.
uv run logdet-fit --input data/processed/parsed.csv          # -> models/detector.joblib
uv run logdet-stream --input /var/log/auth.log               # follow and alert
uv run logdet-stream --input data/raw/synthetic.log --once   # replay a file, then exit
uv run logdet-stream --input /var/log/auth.log --narrate     # + LLM narrative on close
uv run logdet-stream --journald                             # this machine's live auth journal
uv run logdet-stream --journald --journald-unit sshd        # one unit instead of authpriv
uv run logdet-stream --journald --once --journald-since=-24h   # replay a journal window

# Stage 2 (HTTP). The service owns the stream: start it, then read incidents.
uv run logdet-api                                            # 127.0.0.1:8000, /docs for the schema
curl -s localhost:8000/health
curl -s -X POST localhost:8000/stream/start -H 'content-type: application/json' \
     -d '{"source":"file","path":"data/raw/synthetic.log","once":true,"from_start":true}'
curl -s -X POST localhost:8000/stream/start -H 'content-type: application/json' \
     -d '{"source":"journald"}'                              # the live auth journal
curl -s 'localhost:8000/incidents?notable=true&limit=5'
curl -s localhost:8000/incidents/42
curl -s -X POST localhost:8000/incidents/42/narrate          # on-demand LLM, needs Ollama
curl -N localhost:8000/events                                # live push feed (SSE)
curl -s -X POST localhost:8000/stream/stop

# Stage 2 (demo). Replay a recorded log in wall-clock time into a tailed file.
uv run logdet-replay --input data/raw/synthetic.log --output data/live/demo.log
uv run logdet-replay --input data/raw/synthetic.log --output data/live/demo.log \
     --speed 600 --max-gap 1 --truncate      # faster, no long silences
uv run logdet-replay --input data/raw/synthetic.log --output data/live/demo.log \
     --rate 5                                # fixed 5 lines/second

# Stage 1 (kill point). Wazuh must be up: docker start wazuh  (see Known Issues)
uv run logdet-fetch-data openssh                # Zenodo LogHub fetch, SHA-256 verified
uv run logdet-corpus --ambient-ratio 0.05       # build the kill-point corpus + manifest
uv run logdet-killpoint --seeds 5               # THE measurement, ~40 min, saturates CPU
uv run logdet-killpoint --seeds 1               # smoke pass only -- NOT admissible (§4)
# The dashboard reads the API by default (start logdet-api first); the sidebar
# switches it back to a finished run's incidents.json.
uv run streamlit run src/logdet/dashboard.py

# Stage 3 (template mining). Adds a template_id column; nothing reads it yet.
uv run logdet-preprocess --input data/raw/synthetic.log --output data/processed/parsed.csv \
     --year 2026 --drain3 --template-state models/drain3_state.json
# Inspect the mined vocabulary (default corpus: LogHub OpenSSH, ~13s for 655k lines)
uv run logdet-templates --output results/templates --state models/drain3_openssh.json
uv run logdet-templates --input data/external/Linux.log --limit 50000   # any raw log

# Stage 3 (sequence model). Fit on history, never on the traffic being judged.
uv run logdet-fit --input data/processed/parsed.csv --sequence-model   # -> models/sequence_model.json
uv run logdet-pipeline --input data/processed/parsed.csv --no-llm --sequence-model
# Stage 3 (alert suppression). ON by default when a sequence model is passed.
uv run logdet-pipeline --input data/processed/parsed.csv --no-llm \
     --sequence-model --suppress
# Section 4 items 1/2/4 on both corpora with ground truth (~4 min, needs embeddings)
uv run logdet-suppression-report
# Section 4 item 3 -- instance detection under camouflage. NOT optional (~12 min/arm)
uv run logdet-adversarial --seeds 5 --output-dir results/suppression/adv_off
uv run logdet-adversarial --seeds 5 --suppress --output-dir results/suppression/adv_q090
uv run logdet-adversarial --seeds 5 --suppress --suppression-quantile 0.99 \
     --output-dir results/suppression/adv_q099        # the rejected arm
uv run logdet-suppression-report --merge-adversarial off=results/suppression/adv_off \
     q0.90=results/suppression/adv_q090 q0.99=results/suppression/adv_q099
# The other guard: which loneness test (Stage 4 entity graph). Both graph tests
# were measured on the full suite and rejected -- results/suppression/loneness/
uv run logdet-adversarial --seeds 5 --suppress --suppression-loneness quiet \
     --output-dir results/suppression/adv_quiet
uv run logdet-adversarial --seeds 5 --suppress --suppression-loneness share \
     --suppression-share 0.50 --output-dir results/suppression/adv_share050
uv run logdet-suppression-report --output results/suppression/loneness \
     --merge-adversarial off=results/suppression/adv_off \
     incident=results/suppression/adv_q090 quiet=results/suppression/adv_quiet \
     share@0.50=results/suppression/adv_share050
# Kill point with suppression (Wazuh must be up; NOT comparable to a run without it)
uv run logdet-killpoint --seeds 5 --suppress

# What the signal separates, and where it consumes cleanly (~1 min, needs embeddings)
uv run logdet-sequence-report                                          # synthetic corpus
uv run logdet-sequence-report --input data/processed/killpoint/corpus.log \
     --ground-truth data/processed/killpoint/ground_truth.csv \
     --output results/sequence/killpoint --year 2026

# Stage 4 (ATT&CK). The index is committed; --refresh re-downloads the 54MB bundle.
uv run logdet-attack                              # show the indexed techniques
uv run logdet-attack --refresh                    # rebuild after bumping ATTACK_VERSION
# Detection coverage matrix (~30s: parses both corpora, no embeddings)
uv run logdet-coverage --incidents data/processed/incidents.json
uv run logdet-coverage --openssh-limit 50000      # quicker pass while iterating
# Why Stage 4's two remaining structural items were declined (~10s, no models)
uv run python results/correlation/cross_source_overlap.py

# Stage 5 (narrative faithfulness). Needs Ollama; ~4s per incident on the 4060.
uv run logdet-faithfulness                        # synthetic corpus, all 94
uv run logdet-faithfulness --limit 5              # quick pass while iterating
uv run logdet-faithfulness --narrate-policy       # only what the pipeline narrates
uv run logdet-faithfulness --input data/processed/killpoint/parsed.csv \
     --output results/faithfulness/killpoint
# The arms. --structured is the JSON path: the technique field is validated
# against the grounded list and a rejected ID is dropped rather than printed.
uv run logdet-faithfulness --structured --output results/faithfulness/arms/structured
uv run logdet-faithfulness --rescore results/faithfulness/faithfulness.json  # no model
# Why the technique-name check reads 0 wrong names (needs the 54MB bundle)
uv run python results/faithfulness/invented_name_check.py

# Stage 2b (the bake-off). Wazuh must be up; logdet-api is started by the runner.
uv run logdet-bakeoff --benign-only --duration 60 --output results/bakeoff/act1_benign
uv run logdet-bakeoff --attack brute_force --level rephrase --repeat 3
uv run logdet-bakeoff --grid --repeat 3                  # every attack x level
# Rebuild the merged 18-cell report from the per-invocation JSON (fires nothing):
uv run logdet-bakeoff --merge results/bakeoff/bf_measured2 results/bakeoff/bf_measured \
     results/bakeoff/enum_measured results/bakeoff/it_measured results/bakeoff/illustration \
     --notes results/bakeoff/notes.md --output results/bakeoff
# The grid the examiner clicks (start logdet-api first, and docker start wazuh):
uv run streamlit run src/logdet_eval/bakeoff_dashboard.py
```

Paths in `config.py` resolve against the repo root, so every command works from any
directory. `LOGDET_PROJECT_ROOT` overrides the root for scratch runs.

Ollama (separate terminal, required for narrative steps):
```bash
ollama serve
ollama pull phi3
```

**Note:** `data/processed/` IS gitignored in this repo (it is regenerable output).
The frozen demo folder deliberately commits it instead — do not copy that choice here.

---

## 10. Decision Log

> **Agent: append here whenever a technical decision is made. Never delete entries.**
> **Inherited entries live in `docs/CLAUDE.v1.md` section 10 and remain authoritative
> for anything predating the fork.**

| Date | Decision | Rationale |
|---|---|---|
| 2026-08-17 | Forked rather than continuing in `Project`; v1 frozen at tag `v1.0-submission` | The submitted artifact must keep reproducing the numbers in the report. Development that is free to break detection cannot share a repo with that. A third folder (`log-anomaly-detector-demo`) carries the runnable demo with `data/processed/` committed, so the demo survives a clone |
| 2026-08-17 | Fork by copy-and-evolve, not clean rewrite | The detection code is proven and the evaluation artifacts are the most valuable asset in the project — they are the baseline every future change is measured against. A rewrite discards exactly the part that gives the work credibility |
| 2026-08-17 | Benchmark platform (Stage 1) is sequenced **before** any detection change (Stage 3+) | Without automated measurement you cannot tell whether a change helped, and detection work "feels" better far more often than it measures better. Front-loading it also delivers the third-party SIEM baselines early, which is the fastest available credibility win |
| 2026-08-17 | Third-party rulesets (Wazuh manager / Sigma) replace the self-written rule baseline as the primary comparison | v1's baseline scored F1 0.96 partly because the same author wrote the attacks and the rules that catch them — near-oracle by construction, and the write-up had to concede it. Rules authored by people who have never seen this corpus remove that objection entirely |
| 2026-08-17 | Wazuh is to be run as **manager/analysis-engine only**, offline, with alerts exported for comparison — not as the full indexer+dashboard stack, and not live during a demo | The full stack wants ~6GB; this machine has ~5GB free with Ollama also needing a large share. Comparing exported alerts inside our own dashboard is both memory-safe and a better demo than alt-tabbing between two web UIs |
| 2026-08-17 | Sequence modelling identified as the highest-value detection change, ahead of any embedding or threshold work | v1 scores every line independently, which is the structural cause of precision 0.29 — one unusual line is inherently weak evidence. The contamination sweep already proved thresholds cannot fix this without costing robustness. Modelling *order* changes what evidence is available rather than re-weighting the same evidence |
| 2026-08-17 | "Real-time" is defined as file-tail + micro-batch scoring against pre-fitted models, and LLM narration stays **on-demand** | Honest scoping. Tailing with micro-batches is genuinely how many detection deployments work, and splitting fit-from-score ("fit on history, score on stream") is better engineering than v1's single-pass fit-and-score. But phi3 at 40-60s/incident on CPU is a floor, not a tuning problem — claiming real-time narration would be a lie the demo itself would expose |
| 2026-08-17 | **A kill point was pre-registered (§1b) before any Stage 1 code was written**: ≥25pt robustness differential against a third-party ruleset → continue; 10-25pt → cheap stages only; <10pt → stop and publish the negative result. 4-week deadline, batch mode, one machine | The entire roadmap rests on one unverified assumption — that v1's gap survives rules the author did not write. v1's 0.94→0.07 collapse was against *self-written frequency-threshold* rules that `slow` defeats by construction; a mature third-party ruleset degrades by a different mechanism and those numbers do not transfer. The failure mode for a project like this is not the tech failing, it is spending months building infrastructure around an assumption nobody checked in month one. Registering the criterion in advance is what makes it binding — after seeing results, any threshold becomes negotiable |
| 2026-08-17 | **OpenSSH (+ Linux) chosen as the real-data corpus; HDFS rejected and BGL demoted to optional** | HDFS and BGL are labelled, which is why the literature uses them, but their anomalies are *system faults, not adversarial behaviour*. With no attacker there is nothing for MITRE to map, no narrative to tell, and camouflage is semantically undefined — so both novelty pillars go dark, and what remains is a benchmark of the one layer this project does not claim as its contribution. OpenSSH has real internet brute-force and enumeration in the same log format the preprocessing already handles. Its lack of labels is solved with precision@k plus manual verification, not by switching corpus. BGL over HDFS if comparability is later wanted: per-line labels fit the existing harness, block-level labels would force restructuring the whole evaluation |
| 2026-08-17 | Two laptops split by **role** (monitored host + SIEM / analyzer), explicitly **not clustered for compute**; direct gigabit ethernet, not Thunderbolt or WiFi | Clustering solves "the model does not fit", which is not a problem here — phi3 q4 ≈ 2.3GB and llama3:8b q4 ≈ 4.7GB both fit an 8GB 4060 with headroom, so splitting across a link three orders of magnitude slower than on-card memory makes inference *slower* while adding distributed-training complexity and demo-day failure modes. Role-splitting instead resolves the RAM squeeze, is the Stage 7 collector/analyzer split pulled forward, and is visibly harder to dismiss than two panes of one app. Thunderbolt is not merely unnecessary but *impossible* — machine A has no TB/USB4 controller (verified: Alder Lake PCH, plain USB 3.2 xHCI, no JHL chip) and no ethernet port at all. Bandwidth was never the constraint: 10k lines/sec ≈ 2 MB/s ≈ 1.6% of gigabit. Campus WiFi is excluded because AP client isolation commonly blocks peer-to-peer traffic and is undebuggable in a demo room |
| 2026-08-17 | GPU is an **accelerator, never a requirement**; CPU single-box remains the supported floor and machine A is kept as the CPU benchmark target | "Runs on a laptop with no GPU" is a genuine differentiator — it is the reason a team with no SOC budget could deploy this. Requiring a GPU turns the project into one more ML security tool with infrastructure demands. Keeping both machines as benchmark targets also turns "runs on CPU, much faster on GPU" from a claim into a measured result on two real machines |
| 2026-08-17 | Bake-off Act 2 is framed as **"we both detect it, but we bury you in noise"**, not "we fail to detect it" | The user's original framing had the system failing on the obvious attack. It does not — v1 detects 100% of instances on clean data; what it fails at is precision (94 incidents for 9 attacks). The accurate admission is also the more useful one: it names the real weakness, and conceding a loss before showing a win is what makes the win credible rather than staged |
| 2026-08-17 | Topology revised: the dev environment is on a **portable USB SSD** (verified: `sda` USB holds boot+LUKS-root+home), so the analyzer role is *wherever the SSD boots*. Roles are now **analyzer = gaming laptop/4060 booting the SSD**, and **adversary+monitored+SIEM = office laptop running Kali on its own NVMe** | The SSD being the environment makes "which laptop" a boot choice, not a port — which kills the Windows/WSL option outright (boot native Linux instead; more moving parts, zero gain). The Kali box already has attack tooling and its own disk, so it is the natural adversary/monitored host. The single-occupancy SSD forces the collector/SIEM/attack code on Kali to be independently deployable rather than assuming the repo is present — a Stage 2 design constraint, not a retrofit |
| 2026-08-17 | **Move the SSD to the gaming laptop at the start of Stage 2, not before**; prep the gaming laptop (NVIDIA driver, fallback-initramfs test-boot) *during* Stage 1 as background work | Stages 0-1 are batch/one-machine/CPU-fine, and the §1b kill point is explicitly one-machine — entangling a hardware migration with the experiment that decides whether the roadmap continues would be a mistake, and if the kill point says stop, the gaming laptop was never needed. Stage 2 is the first stage that needs the GPU (live narration) and the second machine (the split). Prepping early (driver install while internet works, `-fallback` boot because `autodetect` is in HOOKS and bakes in host-specific modules) de-risks the move without blocking Stage 1 |
| 2026-08-18 | **Four independent repos with four distinct remotes** (§0): `Project`→`log-anomaly-detector-v1` (private archive), `log-anomaly-detector`→`log-anomaly-detector` (public release), this fork→`log-anomaly-detector-fork` (private), demo folder local-only | Publishing the polished public version force-pushed over the repo `Project` was still pointing at, which both destroyed the only remote copy of the 12-commit v1 history and left two folders aimed at one remote — a `git push` from `Project` would have been rejected or would have wiped the public repo. Splitting the remotes makes the failure structurally impossible rather than something to remember. The v1 history is genuinely valuable (it is the provenance behind every decision in `docs/CLAUDE.v1.md`) and had been surviving only on the portable SSD |
| 2026-08-18 | The public repo is kept **free of any reference to the AI assistant**, with the decision log rewritten as `docs/DESIGN.md` for a human reader rather than deleted | The user asked for a version friends could download without the AI-development framing. Deleting the rationale outright would have thrown away the most useful documentation in the project — the `"ssh"` keyword bug, the `"nan"` hallucination, and the contamination-retune rejection all explain *why* the code looks as it does. Rewriting preserves that value; five source docstrings were repointed from `CLAUDE.md` to `docs/DESIGN.md` so no dangling references remain |
| 2026-08-17 | **Kali is a role in the software, not just hardware** — a standalone `attack_runner/` that drives real tools (hydra/medusa/nmap) against a real sshd, captures ground truth at generation time, applies shared camouflage code, and ships to the analyzer. Lands at Stage 6 | Twin of the third-party-ruleset decision: §1b removes self-written *rules*; this removes self-written *attacks* for the un-camouflaged case, leaving only the camouflage layer authored — which is the layer the project is supposed to own. Real tool output as the attack base is a materially stronger claim than injected synthetic lines. Kept for Stage 6 because Stages 1-5 run fine on synthetic + OpenSSH, and authentic attacks are the strongest form of the adversarial track. Camouflage transforms are shared library code imported by both the real-log and synthetic-log paths so the two tracks stay comparable |
| 2026-08-18 | Code split into two packages, `logdet` (pipeline) and `logdet_eval` (evaluation), with the one-way import rule enforced by a static test | §5's "the evaluation track must never be imported by the pipeline" was a convention a single careless import could break silently, and the thing it protects — every number this project reports — is the whole point of the repo. A layout that makes the violation visible, plus an AST test in CI, converts a rule you have to remember into one you cannot break by accident. The eval-only config knobs (`BASELINE_*`, `SYNTHETIC_*`, `CAMOUFLAGE_*`, `EVAL_*`) moved to `logdet_eval/config.py` for the same reason — the test caught them sitting in the pipeline's config, which is where leakage starts |
| 2026-08-18 | Stage 0's persistence layer (SQLite/DuckDB) deferred to Stage 2 rather than built now | Stage 1 produces JSON and Markdown reports, which files serve perfectly well; the first thing that genuinely needs a store is Stage 2's streaming ingestion. Building it now would delay the §1b kill point — the measurement that decides whether any of the later stages are worth building — by a session, to serve a need that does not yet exist. If the kill point says stop, the DB was never needed |
| 2026-08-18 | Config paths anchored to the repo root via `PROJECT_ROOT`, overridable with `LOGDET_PROJECT_ROOT` | v1's bare relative strings (`"data/raw"`) silently resolved against the working directory, so any command run from elsewhere wrote its output somewhere unexpected — and pytest runs from wherever it is invoked. The env override exists so an eval run can be pointed at a scratch tree without editing config |
| 2026-08-18 | v1's headline numbers pinned in an end-to-end test (`tests/test_pipeline_regression.py`, marked `slow`, skipped in CI) | 751 lines → 130 anomalies → 94 incidents is what "the refactor changed nothing" means, and asserting it is cheaper than re-deriving it by hand each time. Marked `slow` because it downloads the sentence-transformer. The test's docstring states the rule explicitly: if a number changes, that is a detection change and §4 applies — re-run the adversarial suite over ≥5 seeds and record the delta *before* touching the expected value. A green test bought by editing the constant is worse than no test |
| 2026-08-18 | **Sigma dropped as the third-party ruleset; Wazuh promoted to primary.** The §1b criterion (≥25pt / 10-25pt / <10pt) is unchanged | Measured, not assumed: across all ~3,300 rules in the official SigmaHQ repo (`rules/`, `rules-emerging-threats/`, `rules-threat-hunting/`, `deprecated/`, `unsupported/`) **not one matches `Failed password`, `Accepted password`, `Invalid user` or `pam_unix`**. Sigma's 210 Linux rules are 122 process_creation + 53 auditd + 8 file_event + 5 network_connection, all needing auditd/Sysmon-for-Linux telemetry this project does not have; the single `service: sshd` rule matches libssh crypto-exploit strings, not authentication. **Zero Linux rules use a frequency/threshold condition** — precisely the rule class `slow` camouflage is built to defeat. Sigma would therefore score ~0 recall *before* any camouflage, and a system that detects nothing cannot exhibit a measurable degradation. §1b chose Sigma on packaging convenience ("pure Python, no daemon"), which is not a reason that survives the rule inventory. Wazuh's `0095-sshd_rules.xml` has 7 frequency rules written for exactly these lines (e.g. 5712: `frequency=8 timeframe=120 same_source_ip`, tagged T1110). Only the ruleset identity changed — §1b already named Wazuh as an option, and the deciding threshold was not touched. The Sigma coverage gap is itself worth reporting |
| 2026-08-18 | Wazuh runs as the **real manager in Docker**, not as a reimplementation of its rule semantics | Third-party rules executed by a third-party engine is the strongest available answer to "you graded your own homework". Writing our own evaluator for Wazuh's XML would keep the rules third-party but make the *matching* ours — reintroducing author influence at exactly the layer the kill point is measuring, and Wazuh's decoder chain plus `if_matched_sid`/`frequency`/`same_source_ip` semantics are intricate enough that a faithful reimplementation is its own research project |
| 2026-08-18 | Kill-point background = **real benign OpenSSH lines + real attacker traffic downsampled to a declared `ambient_ratio`**, attacks injected on top | §3b assumed OpenSSH could supply "real benign traffic". Measured, it cannot: 66-83% of *every day* is internet brute force and only ~2.4k of 655k lines are genuinely benign. Injecting into the raw corpus would make brute force the statistical majority of "normal", so an injected brute force scores as an *inlier* — the resulting differential would measure base-rate contamination rather than camouflage robustness, invalidating the experiment rather than failing it honestly. Building the background explicitly keeps every line real (2,483 background lines, 9 real users at their genuine home subnets, host `LabSZ`) while making the ambient-attack density a parameter to report sensitivity across rather than a hidden default. Real: background lines, usernames, host, vocabulary. Authored: the injected instances and the camouflage layer — which is the layer this project is supposed to own |
| 2026-08-18 | Year-rollover inference added to `preprocess_file` (default on, no-op on single-month corpora) | The OpenSSH corpus runs Dec 10 → Jan 07 and syslog carries no year, so a fixed year places January *before* December and silently corrupts every window-based computation — incident grouping, impossible travel, and any SIEM frequency rule compared against them. Silent time-scrambling would have produced a kill-point number that looked plausible and meant nothing. Verified a no-op on the v1 synthetic corpus (single month): all 99 tests including the 94-incident regression lock stayed green |
| 2026-08-19 | Kill-point results are **checkpointed after every condition** to `killpoint_<tag>.partial.json`, deleted on successful completion | The runner wrote results only at the very end, so two separate mid-flight machine reboots discarded every completed condition — ~40 min of compute each. Conditions are independent, so there was no reason for the loss to be all-or-nothing: a crash at condition 6 now still leaves `rephrase` and `mimicry`, which is enough for a genuine verdict. The partial is deleted on success specifically so a stale partial from a killed run can never be mistaken for a finished measurement — an incomplete file that *looks* complete is worse than no file |
| 2026-08-19 | `killpoint.py`'s verdict logic pinned by 11 tests, including both directions of the timing-exclusion rule | This module computes the one number the entire roadmap turns on, and it had zero test coverage. The two tests that matter assert the exclusion cannot be subverted either way: a timing-dependent strategy showing a 100pt gap must not inflate the verdict to CONTINUE, and `slow` reading −22pt as a pure arrival-time artefact must not depress it to STOP. The §1b thresholds are also pinned at their exact boundaries (25.0→CONTINUE, 24.0→PARTIAL, 10.0→PARTIAL, 9.0→STOP), a SIEM degrading *less* than us is asserted to be STOP, and a detector-only run is asserted to return `INCOMPLETE` rather than any verdict. A refactor that quietly changed a roadmap decision would now fail CI instead of being believed |
| 2026-08-18 | **Wazuh's correlation windows are keyed on arrival time, not the log's own timestamp** (verified on both `wazuh-logtest` and the real `analysisd`: 15 `Invalid user` lines from one IP fire rule 5712 identically at 3-second and 1-hour spacing). Consequence: batch replay cannot measure timing-based camouflage against Wazuh. The kill point is therefore measured in **two instruments** — batch for the timing-independent strategies (`mimicry`, `rephrase`, `ip_rotate`, `volume`, `noise`), and real-time-paced replay over a time-compressed corpus for `slow`, `temporal` and `realistic-combo`. **The §1b thresholds are unchanged** | §1b pre-registered *both* "batch mode" and all seven camouflage strategies, and this measurement shows those two clauses cannot both hold: replayed at machine speed every event is simultaneous to Wazuh, so its drop under `slow` is 0pt **by construction**. Since `slow` costs this system ~20pt, the differential would compute to −20pt and return a STOP verdict that is an artefact of the instrument rather than a property of either system. Fixing the instrument is not the same as moving the criterion, and the distinction is the whole reason this entry exists: the thresholds, the strategies and the deciding quantity all stand exactly as registered. Note the finding does not flatter this project either — Wazuh firing a "brute force" rule on 15 events spread over 15 hours is not robustness but *indiscriminacy*, i.e. a false positive, so the comparison must report Wazuh's alert volume alongside its detection rate |
| 2026-08-30 | **Development moved to a borrowed laptop with an RTX 3050 6GB; the RTX 4060 machine is reserved for final testing.** Narration measured at **5.2s on GPU vs 24.2s on this CPU**, against v1's 40-60s | The SSD booted foreign hardware first try and the 2026-08-20 driver prep carried across, which is what the fallback initramfs was for. Three things follow. First, `ollama` on Arch is a **CPU-only package** — it ran 100% CPU while `nvidia-smi` reported a perfectly healthy driver, so a loaded driver proves nothing and `ollama ps` must be checked; `ollama-cuda` is the one with a CUDA backend. Second, the "40-60s per incident on CPU is a floor, not a tuning problem" line inherited from v1 is **not a property of CPU inference** — it was one laptop's number, and a 10-core i5-13450HX roughly halves it. Every latency figure now has to be labelled with the machine that produced it, and there are three such machines. Third, at ~5s the GPU makes near-real-time narration an honest claim rather than an apology, and it was measured on the *smaller* GPU, so the 4060 is at least this good — but that also means the demo number must be re-measured there rather than quoted from here. VRAM is now the binding budget (6GB, with phi3 resident at 3.8GB), not system RAM, which went from ~5GB free to ~11GB |
| 2026-08-30 | **Streaming carries three pieces of state — a rolling context window, incrementally grown incidents, and a committed byte offset — and is verified by reproducing the batch numbers exactly (130 events, 94 incidents) rather than by inspection** | The tempting version of "live mode" is to re-run the batch pipeline over a growing file, and the cheap version is to score each micro-batch on its own. Both are wrong in the same direction and neither fails loudly. A batch of five lines has no history inside it, so impossible travel — which compares a login against that user's *previous* login — silently never fires, and a brute-force burst spanning a batch boundary reads as two smaller incidents. Nothing errors; the numbers just quietly stop meaning what the batch numbers mean, and every result in `results/` is a batch result. So the processor keeps a rolling window (the larger of the incident and travel windows) and grows incidents event by event using the batch grouper's own link rule, merging incidents when a new event bridges two so transitivity matches union-find. The check that this is right is not an argument, it is `tests/test_stream_regression.py`: same corpus, same detector, streamed in 25-line batches instead of one pass, and the same 130 flagged events in the same 94 incidents. Both mechanisms were mutation-tested — disabling the context window or the cross-batch link makes four tests fail, so the tests are load-bearing rather than decorative. Two smaller decisions follow the same logic: the offset is committed only *after* a batch is scored, so a crash replays that batch instead of skipping it, and a partial trailing line is left unconsumed until its newline arrives, because splitting one log line in two parses as garbage and drops an event. Batches close on 50 lines **or** 5 seconds, whichever first — count alone strands a half-full batch on a quiet log until the next burst, time alone gives up the embedding model's batching during one |
| 2026-08-30 | **A persisted detector carries a provenance stamp, and `load` refuses to score across a mismatch** | Splitting fit from score is the prerequisite for streaming, and the obvious failure of a saved model is not that it fails to load but that it loads *fine* against embeddings it was never fit on. Sentence embeddings from a different model have the same width and a completely different geometry, so an Isolation Forest would score them, return plausible values, and quietly invalidate every downstream number — precisely the class of silent-wrongness this project's benchmark discipline exists to catch, except no benchmark would catch this one. The stamp records the embedding model, vector width, hyperparameters, sklearn version and fit time; `load` rejects an embedding-model or format-version mismatch, `score` rejects a width mismatch, and both reject an unfitted detector. `run_anomaly_detection` keeps refitting by default so the batch path and its pinned regression are untouched; passing a detector is opt-in and is what the stream will use. joblib promoted from a transitive scikit-learn dependency to a declared one, since it is now imported directly |
| 2026-08-20 | **`ambient_ratio` sensitivity settled: `rephrase` reads +31.2 / +31.1 / +31.1 across a 20× range of background density, so the one surviving win is a mechanism and not an artefact of the corpus. Stage 1 closed** | The single most available objection to this project's result was that `ambient_ratio=0.05` had been chosen with no justification, and that the entire claim rested on one number measured at that one setting — an objection that costs two 40-minute runs to answer and would have been fatal to leave open. It does not survive: a 0.1pt spread across 0.01→0.20 is what a mechanism looks like, and the reason is legible rather than statistical — Wazuh's sshd decoder matches literal strings, so rewording drops a line out of it regardless of what else is in the log. The ties hold at every density too. The one real result that moves is `ip_rotate`, from −13.3 in the quietest background to −8.9 in the noisiest: still a loss everywhere, but its size depends on how much ambient traffic there is to hide in, so the write-up must carry the range rather than the single friendliest figure. Timing-dependent rows are rendered in the sweep but explicitly marked artefacts, because batch replay pins Wazuh's drop at 0pt by construction and their apparent sensitivity is only *our* drop moving. Also closed a standing infrastructure defect found while recovering the 0.20 run: checkpoints had been written since 2026-08-19 and nothing could read one, so three separate runs discarded completed conditions — `--resume` now reuses them, and refuses any checkpoint whose parameters differ, because splicing two experiments into one reported result would be worse than losing the compute |
| 2026-08-20 | **The paced measurement returned two losses and a tie (`slow` −8.9, `temporal` +0.0, `realistic-combo` −13.3), recorded exactly as computed. The §1b verdict is unchanged: CONTINUE, on `rephrase` alone** | The instrument was built specifically because three strategies could not be measured against an arrival-time-keyed SIEM, and the honest outcome of building it is that this project *loses* on two of them. Wazuh replayed at true speed does not degrade at all under slowed-down or combined camouflage, while this system drops 8.9 and 13.3 points. The temptation this creates is exactly the one §1b names as the biggest risk to the project's integrity, and it takes a specific form here: **the alert level is a knob that changes the answer, and there was a ready-made argument for turning it.** `killpoint.py` justifies `PRIMARY_LEVEL=3` on the grounds that higher levels "a 7-second replay cannot exercise" — an argument that genuinely no longer applies to a 6.5-hour paced replay, and which would have licensed moving to L7/L10 after seeing the result. It was not moved, for two reasons: changing the deciding threshold *after* seeing results is the thing the kill point exists to prevent regardless of how good the reason sounds, and the higher levels do not actually favour us anyway — Wazuh detects 11.1% at L7/L10 on the *clean* corpus, so its drops there are a floor effect, and the best differential across every level is +11.1pt, still under the registered bar. All three levels are now rendered in the report so the reader can see the shape rather than take the primary on trust. Net effect on the roadmap: none — `rephrase` at +31.1pt clears "≥25pt on at least one strategy" as registered — but the claim this project may make has narrowed to *"signature rules break when you reword an attack; embeddings do not"*, and the eight-strategy tally (1 win, 4 ties, 3 losses, including `realistic-combo`) belongs in the write-up beside it |
| 2026-08-19 | **Paced replay is scheduled per source IP with gaps clamped at 75s, and global line order is deliberately not preserved.** Nothing about Wazuh — ruleset, engine, or container clock — is modified | Replaying the corpus at true speed costs 144h for a 5-seed run, which is not a measurement anyone will make. Two properties *of the shipped rules* make a far cheaper schedule equivalent rather than approximate, and both were read off the ruleset rather than assumed: the sshd frequency rules are **rate limits**, so a real gap only has to be honoured up to `timeframe/frequency` (60s, binding case 5703/5705 at 360/6) and any larger real gap is indistinguishable past that; and they carry **`same_source_ip`**, so spacing is per-IP and unrelated sources replay concurrently. Dropping global order is the single largest lever (~3x) and is sound only when no frequency rule can fire without a source key — the three such rules (5705, 5714, 5719) need `Timeout before authentication`, a CRC-32 attack, or a denied user, and the corpus contains **zero** of all three, checked by `verify_order_relaxation_safe` rather than asserted. The two alternatives that would have made runs *minutes* were both rejected for the same reason: **time dilation** (compressing the clock and dividing Wazuh's `timeframe`/`ignore` by the same factor) and **`libfaketime` on analysisd** each alter the third party we are being compared against, which is precisely what §1b exists to prevent — and dilation is capped at ~12x anyway by the ~2s ingestion latency. The instrument was probed *before* being built: 15 `Invalid user` lines from one IP fire 5712 at 0.2s spacing and do not at 20s spacing. Thinning the ambient layer (`max_events_per_ip`) is the remaining cost lever and is a declared parameter, because one real attacker IP with 88 events costs 10h on its own |
| 2026-08-30 | **journald is a second source behind the same interface, resumed by journald's own cursor rather than a byte offset; and the process-field regex was widened to accept parentheses after the live journal proved it was dropping half its auth lines** | A tailed file is a replay of traffic somebody already wrote down, so "live ingestion" was not yet demonstrably live. `journalctl -f` on this Arch box is the machine's own auth stream, and making it a source that implements `read_lines()`/`commit()` means nothing below the source — batching, scoring, incident growth, the offset discipline — had to change or be re-verified. Three things were measured rather than assumed. **`-o json`, not `-o short`**: the short form parses but carries no cursor, and the cursor is the only honest equivalent of the byte offset, so the syslog-shaped line is rebuilt from the JSON fields instead. **`--since now` does not restrict journalctl to new entries** — it returned all 28 journal entries, so a first follow run would have re-alerted on the entire history; `-n 0` is the primitive that means what follow means, and the test now pins that finding rather than the intention. **The cursor lives in its own store**: a byte offset is meaningful only with an inode and a cursor only with the journal filter it was taken from, so one file holding both would let a file run and a journald run silently overwrite each other's resume point — and a cursor taken under `-u sshd` is refused for an authpriv run for the same reason. The regex fix was not planned work: the first live run read 22 lines and parsed 11, and the 11 failures were `(systemd)` and `(sd-pam)` — journald's names for user-session pam, the same defect already logged against LogHub's `su(pam_unix)`. This is a preprocessing change, so §4 was the question. It is a **strict no-op on every corpus any published number came from**: SHA-256 over every parsed record of `synthetic.log` and `SSH.log` is identical before and after, both still 100%, and the pinned 751 → 130 → 94 locks stayed green on both the batch and stream paths — so no adversarial re-run was owed. What it does change is corpora nobody has reported on yet: Linux.log 75.98% → 99.37%, live journal 11/22 → 22/22 |
| 2026-08-30 | **The FastAPI service owns the stream rather than serving the incident file, and scores nothing itself; the triage policy moved to `logdet/triage.py` so the two interfaces cannot disagree** | The cheap version of "add an API" is to serve `incidents.json`, which is an interface without a capability -- the dashboard already reads that file, and a file written when a batch run ends cannot be subscribed to while an attack is happening. Stage 2b puts this detector and Wazuh side by side on one live stream with the audience choosing what to fire, so something has to expose incidents *as they are emitted*; and once alerts leave the process over HTTP, the thing reading them stops having to be on the same machine, which is the Stage 7 collector/analyzer split starting early. What the service deliberately does **not** do is compute anything: detection, grouping and severity stay in `StreamProcessor`, so `test_stream_regression.py`'s streamed-equals-batch lock still covers the numbers the API serves, and section 4 was not triggered -- confirmed by replaying the synthetic corpus through HTTP and getting 751/751 lines and the pinned 94 incidents. Four smaller decisions, each one a failure that would not announce itself. **Incidents are stored as deep copies taken at emit time**, because the processor rewrites its own dicts in place when an incident closes, and serialising one mid-rewrite would hand a client an incident that never existed. **One stream at a time, a second start being a 409**, because incident ids come from a single processor's counter and two streams would make `/incidents/7` mean two different things. **A dead worker records its exception into the status** instead of leaving the service claiming to stream over a source that stopped producing. **A slow SSE subscriber drops events rather than blocking**, because the alternative is an HTTP client backpressuring the detector, and a dropped push costs a refresh while a stalled detector costs detection. `run_stream` gained a `stop_fn`: follow mode has no natural end, so a caller that does not own the process had no way out but killing the interpreter. The status endpoint reports **seconds since the last scored batch** rather than only a line count, since a line count stops moving both when the log is quiet and when the reader has silently died, and section 2c asks for link health to be visible instead of inferred from an absence of alerts. Narration is on demand, one incident at a time, because at 5s per incident on this GPU and 24s on its CPU, narrating each one as it closed would put the scoring thread minutes behind the log it is following. There is **no authentication**, so the default bind is 127.0.0.1 and exposing it on the demo link has to be a deliberate act. One testing note worth keeping: **Starlette's TestClient runs an app to completion before returning a response**, so an endpoint that streams until the client disconnects cannot be exercised through it at all -- the test hangs rather than fails. The SSE generator is therefore module-level and driven directly by the tests |
| 2026-08-30 | **The dashboard's default source is the running service, not `incidents.json`, and the HTTP client is a separate module from the Streamlit script.** A demo replay tool (`logdet-replay`) paces a recorded log into a tailed file rather than the stream replaying it at read speed | Pointing the page at the API is what makes the live path visible: a file written when a batch run ends cannot show an incident while an attack is happening, and Stage 2b puts this detector and Wazuh side by side on one live stream with the audience choosing what to fire. Keeping the file source is not sentiment -- it is the output of `logdet-pipeline`, and every number in `results/` came from that path, so removing it would strand the batch story. Three things were decided against the obvious version. **The HTTP calls live in `logdet/api_client.py`**, because a Streamlit script executes on import and is therefore untestable by construction, while the part most likely to break is not the layout but what the page does when the service is down, still starting, or answering 503 because Ollama is not running -- those branches are now asserted against a stub transport with no server and no Streamlit involved. **Auto-refresh only runs while a stream is running**: the first version rebuilt the page on a timer unconditionally, which burns a thread redrawing a stopped stream and resets the reader's view of a finished replay under them; a timer *fragment* was tried before the sleep-and-rerun and is worse, because it fires once on the initial script run and turns "refresh every 5s" into a rerun loop with no delay in it. **Ranking and the notable filter stay in `logdet/triage.py`**, so the dashboard and the API cannot drift into disagreeing about which incidents matter. As for the replay tool: `logdet-stream --once` reads a file as fast as the disk allows, which is right for a regression lock and useless for a demo -- 751 lines land in one breath, every incident closes before anyone looks, and nothing distinguishes a streaming detector from a batch one. Pacing puts the original spacing back. Two knobs needed an honest boundary drawn around them. `--max-gap` clamps the hours of silence real logs contain, which means the replay stops being a faithful time-scaling, so the run reports how many gaps it clamped instead of quietly compressing them. `--restamp` rewrites each line's timestamp to now, which is what makes a demo read as live, but it also compresses the log's own time by the speed factor -- a brute force spread over 40 minutes becomes 40 seconds of log time at 60x, so the 30-minute grouping window and the 60-minute travel window no longer cover what they covered in the recording; it is off by default and its output is explicitly not comparable to `results/`. Without it, the detector reads the original timestamps and every window means exactly what it means in batch mode. The tool lives in `logdet/` rather than the evaluation package because it measures nothing -- it is a tap, lines in and the same lines out later -- and it is deliberately not the same thing as `logdet_eval/paced_replay.py`, which schedules per source IP to exercise Wazuh's `same_source_ip` frequency rules and talks to a container. Nothing in this session touched detection, grouping or scoring, so §4 did not apply; the live check was 80 lines replayed at 2000x into a file the API was following, giving 80 seen, 80 parsed and 12 incidents, with the real dashboard reading that service |
| 2026-08-30 | **The bake-off writes one stream to both systems from a single call, records every line it writes as its own ground truth, and marks any time-compressed or timing-based firing as an illustration rather than a measurement** | Stage 2b's claim is that both detectors saw the *same* traffic, and the cheapest way to break that claim is to give each sink its own writer: two writers interleave differently, and the comparison quietly becomes a property of the harness. So `Fanout.write` appends the line to the tailed file and to the container's watched file before returning, and attack and background traffic are merged into one offset-ordered schedule instead of running on two threads. Ground truth is free here in a way it never was in batch — the injector generated the attack, so every line is recorded with its line number and scenario/instance label as it goes onto the wire, which is what lets both systems be scored live by the kill point's existing `scoring.measure_lines` rather than by a second scorer that could drift. Attribution differs by system for a reason worth writing down: Wazuh echoes the whole matched line in `full_log`, but our incidents carry the *parsed* event and not the raw line, so ours attribute by `(second, message)`; both indexes hand out one line number per alert, because a brute force is the same line twenty times and collapsing duplicates would score a twenty-line burst as one detected line. The honesty boundary is the important part. Wazuh correlates on arrival time (Decision Log 2026-08-18), so compressing time or firing `slow` pins its drop at zero by construction — exactly the artefact that forced the kill point into two instruments. Those runs are therefore flagged `measured: false`, rendered as `illustration`, and the report cites the paced run for the real number; `--compress` defaults to 1 so the default is a measurement. The runner also refuses to start without Wazuh instead of silently producing a one-contestant table, which is the failure the kill point kept hitting (Known Issues). One thing the first live firing exposed: **instance detection saturates at one instance**, reading 0% or 100%, so the registered differential is +0.0pt and uninformative live — the line rate is reported beside it as evidence of the same firing, and it reproduces the mechanism (Wazuh 92% → 27% of attack lines under `rephrase`, ours 100% → 100%). Pooled figures still come only from the kill-point runs. Nothing in this session touched detection, grouping or scoring, so section 4 did not apply. A testing note worth keeping: the paging bug that crashed the first live run had a green test, because the stub returned the service's raw payload dict while `ApiClient.incidents` returns a list — a stub of the wrong shape tests nothing, and the fix was to make the stub match the real signature |
| 2026-08-30 | **`--repeat` pools instances through the kill point's own pooler, and the report distinguishes a `+0.0pt` differential caused by too few instances from one caused by both systems catching everything.** The grid page lives in `logdet_eval/`, not on the detector's dashboard | Last session's live table read `+0.0pt` on every row and the diagnosis written down was "instance detection saturates at one instance". Pooling was built to fix that, and it did what it was supposed to do — three instances make the metric able to move in 33pt steps — but the number still came out `+0.0pt`, which means the diagnosis was incomplete. Both systems detect **every** instance in both conditions, because one surviving line is enough to call an instance detected and 15-25 failures never all get reworded out of Wazuh's decoder. That is a ceiling, and no number of repeats moves a ceiling. The two causes produce an identical cell in the table, so the report now computes which one it is looking at and says so, rather than leaving a reader to assume the systems tied on robustness. The scoring path itself is not new code: each instance is scored on its own lines and the runs go through `scoring.pool_runs`, the same pooler the kill point uses, which recomputes rates from summed counts rather than averaging them so a firing that produced fewer attack lines does not get equal weight. Denominators are now printed beside every percentage, because "100%" over one instance and over five are the same string and completely different evidence. As for the page: the grid drives the injector, the Wazuh container and the scorer, so putting a Fire button on `logdet/dashboard.py` would have put the evaluation track inside the pipeline and broken §5's one-way rule — `tests/test_layering.py` would have failed, and the rule is there because measuring yourself with code you depend on is how benchmarks lie. Three smaller decisions, each a failure that would not announce itself. **The firing runs on a worker thread**: a real-time condition takes minutes, and a Streamlit script that blocks stops repainting, so the live incident count and the stream health would freeze at exactly the moment somebody is watching them. **One firing at a time**, because a condition is scored by line number over the range it wrote, and two overlapping attacks would each count the other's lines as undetected. **Background traffic runs on a second thread with a lock held across "take the next line number" and "write the line"** — the manifest *is* the ground truth, so a line numbered on one thread and written after a line numbered later on another would score both systems against a stream neither of them read. Nothing in this session touched detection, grouping or scoring, so §4 did not apply |
| 2026-08-30 | **The live grid was fired whole (18 cells) and the one cell whose instance detection moves is `impossible_travel` under `rephrase`, at +100pt. The grid page was hand-checked by driving the real Streamlit script, which found and fixed a stale-log defect** | The previous two firings both reported +0.0pt everywhere and the diagnosis had moved once already — first "one instance is too few", then "both systems are at a ceiling". Firing every cell shows the second diagnosis was right but incomplete, and the missing piece is a property of the *attack*, not of the metric: an instance counts as detected if one line survives, so whether rewording can flip an instance depends entirely on how many lines the attack has. Impossible travel has two, and rewording removes both — Wazuh detects 0 of 3 where it detected 3 of 3 clean. Brute force has 15-25 and enumeration 10-12, so the same rewording only moves their line rates (Wazuh 91% → 29% and 100% → 34%), which is why eleven of twelve measured cells read +0.0pt. That reading is worth more than the headline number, because it says when the registered instance-detection metric is informative and when it is saturated, and the answer is not something more repeats can change. Three things were checked rather than asserted. Wazuh's 100% on impossible travel is **rule 5715 'sshd: authentication success', level 3** — 135 of 135 successful-login alerts in the container's `alerts.json` — so it flags the attack's two lines by flagging every successful login, never correlating anything, which is the same level-3 saturation the paced kill point recorded and is exactly why rewording those two lines takes it to zero. Our 50% line rate on `impossible_travel` / `none` is the display gap already in Known Issues (only the arriving login is carried into the incident), not a miss. And brute force `rephrase` reproduced the previous firing's Wazuh figure to the point — 29% both times — which is the only reproducibility evidence this live instrument has. The rows where this system looks worse stay in the table: `impossible_travel` / `realistic-combo` is 67% for us against Wazuh's 100%, and alert volume climbs with every camouflage level on every attack (77 → 436 on enumeration, 404 → 2257 on impossible travel), because novel wording is more anomalous, not less. The six timing rows ran at `--compress 600` and are marked `illustration`, since compressing time fixes Wazuh's score by construction (Decision Log 2026-08-18); `slow` spans up to 22 hours per instance, so there is no honest real-time version of that row on this instrument. The grid page was checked with Streamlit's `AppTest` driving the real script rather than by reading it, which is what caught the defect: `build_runner` started the stream **before** `open_session` truncates the log, so opening the page after any earlier run replayed that run's file — 500 lines parsed and 31 incidents against 0 lines written, and Act 1 opening with somebody else's incidents on screen. The CLI already did it in the right order. There is no unit test for it, because a Streamlit script executes on import and cannot be imported (Decision Log 2026-08-30); the check is the AppTest run, repeated after the fix with 41 stale lines in the log and reading 0/0/0/0. Nothing in this session touched detection, grouping or scoring, so §4 did not apply; 397 tests pass. |
| 2026-08-19 | **The §1b kill point returned CONTINUE: best measurable differential 31.1pt on `rephrase`, 5 seeds, Wazuh available throughout.** Recorded exactly as computed, including the `ip_rotate` loss. The roadmap continues; the amplifiers (streaming, bake-off, two-machine, GPU) are unlocked | The assumption the whole roadmap rested on — that v1's robustness gap survives rules the author did not write — held, but *narrowly and by one mechanism*. Wazuh loses 33.3pt under `rephrase` while this system loses 2.2pt: sshd rules match on literal strings (`Failed password`, `Invalid user`), so rewording the message drops them out of the decoder entirely, whereas a sentence embedding of a reworded line stays near the original in vector space. That is a real and explainable property, not luck. It is also the *only* strategy that produced a gap: `mimicry`, `noise` and `volume` are 0.0pt ties, and **`ip_rotate` goes the other way — we lose 11.1pt, Wazuh loses nothing**, because rotating source IPs defeats per-user embedding context while Wazuh's per-IP frequency rules simply fire on whichever IP still crosses the threshold. §1b's registered wording is "≥25pt on at least one strategy", so `verdict()` taking the maximum is the reading as registered rather than a post-hoc choice — the function is a hard-coded literal ladder written before any result existed and pinned by 11 tests. The write-up must therefore claim the mechanism ("signature rules break when you reword; embeddings do not"), never the broad claim ("more robust to camouflage"), and must carry the `ip_rotate` loss in the same table. Three strategies stay excluded pending paced replay, so this verdict is provisional in scope even though it is final in force |
| 2026-08-30 | **The merged bake-off report is generated by `logdet-bakeoff --merge`, with the interpretation kept in a separate `--notes` file; and Act 1 is now a recorded artifact rather than a line on a terminal** | The 18-cell table was assembled by a script written in a scratch directory and then thrown away, which left `results/bakeoff/bakeoff.md` as the one artifact in `results/` whose numbers were reproducible but whose file was not — every per-invocation JSON was committed and the commands were written into the prose, so nothing was lost, but nobody could rebuild it. The merge orders cells by the grid rather than by the order the evening's runs happened, so two merges of the same runs cannot produce two different-looking reports, and it derives each source directory's invocation from the rows it contains rather than from a recorded string, so the provenance cannot drift away from the data beside it. A cell present in two source directories is **refused** rather than resolved by argument order: two firings of one cell are two measurements, the table holds one row, and choosing between them is the operator's call — silently reporting whichever sorted first would put a number in the report nobody picked. The reading of the table is deliberately not generated. A generator that wrote conclusions would be scripting the demo narrative, which §8 names as an anti-goal, so the prose lives in `results/bakeoff/notes.md` and is appended verbatim. Regenerating the committed report changed no table row. As for Act 1: the quiet baseline is the act the demo opens with and it had never been recorded, because `--benign-only` printed a line count and returned. It now scores both systems on traffic containing no attack at all, which is the one act where the number needs no camouflage level attached — every alert is a false positive by construction. Measured live: 30 benign lines, ours 5 flagged in 3 incidents (17%), Wazuh 19 (63%) at level >=3, which is the same rule-5715 saturation the grid firing found and is worth showing precisely because Act 1 is where this project's own precision weakness is most visible. Nothing in this session touched detection, grouping or scoring, so §4 did not apply; 436 tests pass. |
| 2026-08-31 | **A merge inside one micro-batch crashed the stream worker (`KeyError`), and the fix follows a merged incident id instead of assuming it still exists.** The presentation folder for the 31 Aug review is built as its own directory with its own generators | Found the expensive way: a live bake-off firing scored this detector at 0% while Wazuh scored 100%, and the reason was not detection at all — `/stream/status` carried `error: "KeyError: 4"`. Inside one batch, `StreamProcessor.process` collects the incident id each event lands in, then snapshots them; but a later event in the same batch can bridge two incidents, and `IncidentTracker.add` merges one into the other and pops it, so the snapshot pass looked up an id that no longer existed and killed the worker thread. Everything downstream then behaved exactly as if the log had gone quiet — the service still reported a running stream, the dashboard still showed its last incidents, and the bake-off scored a detector that had stopped reading two minutes earlier. That silence is the real defect; the `KeyError` was merely where it started. The tracker now records `merged_into` and exposes `survivor()`, `process` maps its collected ids through it, and an incident that was already emitted before being merged is marked `status: "merged"` with the id it went into, so a client is told where its events moved rather than being left with a stale open incident. The regression test is load-bearing rather than decorative: it reproduces `KeyError` on the unfixed code, and it only does so because the bridging event arrives last **in timestamp order** — the processor sorts a batch by time before filing it, so the obvious version of the test files the bridge first and never merges anything. Behaviour is otherwise unchanged: 449 tests pass, including both slow locks (751 → 130 → 94 in batch and streamed), so §4 was not triggered. A second, non-code finding from the same session is in Known Issues: two bake-off sessions writing one log file silently produce a 0% score for this detector, which is a demo hazard rather than a bug. As for the deck, it lives in `docs/presentation-2026-08-31/` with the slide text in Markdown and `build_deck.py` rendering it to PDF through headless Chromium, because a deck whose content is only inside a binary cannot be reviewed line by line or regenerated when a number changes. The three diagrams are hand-laid-out SVG rather than Mermaid — measured, not assumed: `render_diagrams.py` reports Mermaid's automatic layout of the same graphs at 6.9:1 and 0.6:1 against a slide area of 1.9:1, which scales the labels to about 7px, and Mermaid drops a subgraph's `direction` as soon as an edge crosses its boundary, so the two-row layout the pipeline needs cannot be expressed at all. Screenshots are captured from the running system by Playwright rather than mocked, and the eight references are journal-only with author-version PDFs, because the panel asked for indexed journals and the previous deck's literature table contained a row that was not a published paper |
| 2026-09-01 | **Narration latency re-measured on the RTX 4060 demo box — 3.9s GPU, 18.2s CPU — and every deck figure repointed to it. Having both `ollama` and `ollama-cuda` installed on Arch turns out to be correct, not the CPU-only trap the 2026-08-30 entry warned about** | The deck was quoting 5.2s/24.2s from the borrowed 3050 laptop while being presented from the 4060 machine, which §2c forbids in as many words — "GPU timing numbers do not transfer" — so this was a correctness fix to the presentation, not a nice-to-have. The numbers moved in the expected direction and by an amount nobody could have guessed: the GPU figure fell only 25% (5.2s → 3.9s, because phi3-mini is small enough that neither card is the bottleneck) while the CPU figure fell 25% too (24.2s → 18.2s) purely from a wider CPU (i5-13450HX 10c/16t → i7-13650HX 14c/20t). That is the third consecutive machine to cut the CPU number, which retires v1's "40-60s on CPU is a floor" claim for good. Two method points are now written down, because the 2026-08-30 measurement did not record them and this one had to guess at reproducing it: the input is `llm_narrative.__main__`'s own 4-event smoke incident (592 prompt tokens, so the prompt is identical on every machine), and the figure is a median of 3 timed runs after a warm-up, because generated length varies 254-360 tokens run to run and a single run is therefore not a machine property. Measuring the CPU side does **not** require stopping the GPU service: a second `ollama serve` with `CUDA_VISIBLE_DEVICES=""` on port 11435 does it, but it needs `OLLAMA_MODELS=/var/lib/ollama` because the systemd unit runs as user `ollama` and a user-run server otherwise reports an empty model list and returns 404, not a useful error. The package finding corrects the previous entry rather than repeating it: `ollama-cuda` on Arch **depends on** `ollama` and only adds `cuda_v13/libggml-cuda.so` beside the plain package's `libggml-cpu-*.so`, so both being installed is the normal, working configuration — verified here at `100% GPU` and 3734 MiB of VRAM despite a version skew (binary 0.32.9-1, CUDA libs 0.32.15-1). What stands from 2026-08-30 is the *check*, not the diagnosis: `nvidia-smi` looking healthy proves nothing and `ollama ps`'s `PROCESSOR` column is the only evidence. Nothing here touched detection, grouping or scoring, so §4 did not apply |
| 2026-09-01 | **Drain3 mining lands as an opt-in `template_id` column that no detection code reads, and the mined vocabulary is inspected before anything consumes it** | Stage 3's first move is a parser change, and a parser change is the one place where §4's benchmark rule can be satisfied *structurally* rather than by re-running eight hours of camouflage runs: the column is additive and off by default, so a default parse is byte-identical to HEAD's — checked, not asserted, by SHA-256 over every parsed record of `synthetic.log` (751 lines) and `SSH.log` (655,147), both identical, with the 751 → 130 → 94 batch and stream locks green. Mining and consuming are deliberately separate steps so each can be checked apart; the second one is what will trigger §4. Three design points, each a silent failure otherwise. **The cluster id is recorded per line, never the template text** — Drain3 widens a template as more lines arrive, so the first `Failed password` line is stored with the whole line as its template and the second turns it into `Failed password for <*> from <IP> port <PORT> ssh2`; storing the text per line would leave a corpus whose early rows and late rows disagree about what one cluster is. **IP/PORT/PID/HEX are masked explicitly rather than left to the similarity threshold**, because Drain only collapses a position once it has seen it vary, so an unmasked corpus containing a single IP mines that IP into the template and the whole numbering ends up depending on how varied the traffic happened to be instead of on the log's grammar. **`max_clusters` stays unbounded**: a bound turns the cluster table into an LRU, so a rare template evicted and later seen again comes back with a *new* id, silently renumbering the vocabulary under any model keyed on it. The inspection is the point of the session, and it is a good result with four caveats. On all 655,147 OpenSSH lines, **5,669 regex templates collapse to 45 mined ones**, the count settles (43 by 250k lines, 45 at the end) so it is a real vocabulary rather than something variable leaking in, and **no regex template is split across two clusters at all** — the 126× reduction is the regex leaving usernames in, with 1,713 `Invalid user <name>` templates becoming one. Critically, **failed and accepted password stay in separate clusters**, which is the distinction this project detects on. The caveats are the merges that absorbed a *word* rather than an identifier, separated from the harmless ones by a computed rule (a collapsed position taking ≤6 values is a word; one taking hundreds is an identifier) rather than by reading the table: `Failed password` and `Failed none` share cluster 6, four disconnect reasons share cluster 8, `failure;`/`failures;` share 13 and 18, and IPv4/IPv6 share 43. None merges a success into a failure, so none blocks the stage, but `Failed none` is a probe rather than a password attempt and a sequence model keyed on cluster 6 cannot tell the two apart. One property found by a failing test rather than by reading the docs, and now pinned: **`match` is stricter than `add`** — a frozen template set only matches lines whose differing positions the template already marks `<*>`, so a set frozen after too little traffic reports unmatched lines that read as novelty when they are really an under-trained miner. `drain3` added via `uv add` (§6); it pins `cachetools==4.2.1` and `jsonpickle==1.5.1`, which nothing else here uses. 468 tests pass (`-m "not slow"`), plus both slow locks |
| 2026-09-01 | **The sequence model over template ids re-ranks and never re-flags, so it landed without a camouflage re-run; and the consumption point was chosen by measurement, which rejected the obvious one.** The severity tier is out, the triage tiebreaker is in | The question this session had to answer was not "does a Markov model over template ids separate attacks" — it does, at AUC 0.912 on the kill-point OpenSSH corpus — but *where detection is allowed to spend that*, and the answer had to survive §4. Keying `is_anomaly` on a discrete cluster id was ruled out first and on principle: rewording a line moves it to a different cluster, which is precisely how Wazuh's rules break under `rephrase`, and that one mechanism is the entire kill-point result. So the model is confined to ranking, `is_anomaly` is untouched, and every §4 number is identical with it on or off — asserted by a unit test over `is_anomaly`/`ml_anomaly`/`impossible_travel` and by the 751 → 130 → 94 batch and stream locks, not by argument. Three design calls were then made against measurement rather than intuition, and two of them overturned the intuition. **Fitting the transition model on the frame it scores collapses it to AUC 0.558 on the real corpus** — a coin flip — because ambient brute force teaches it that brute force is routine; on the synthetic corpus the same mistake costs 0.856 → 0.692, so the effect is larger the more realistic the data. That is the sequence-model form of the discipline `fit.py` already enforces for the detector, with sharper consequences, and it is why the model is fitted in `logdet-fit` on history. **The two sequence keys go in precedence order, and the honest reason is simplicity rather than score.** The user key is much the stronger signal (0.958 alone on the kill-point corpus against source IP's 0.758), so the ranking of the keys is well supported; the *combining rule* is not, because taking the maximum across keys measures as a wash — 0.852 against precedence's 0.856 on synthetic, 0.923 against 0.912 on the kill-point corpus, i.e. each rule wins one. Precedence is kept for being the simpler rule and the claim in the artifact says exactly that rather than dressing a tie as a win. The fallback still earns its place: it is the only key with anything to say about account enumeration, which varies the username on every line by design, and the combined row sitting below user-alone is coverage bought at lower quality, not a regression. **The severity tier turned out to be the wrong place to spend the signal, and that is the session's real finding.** An incident takes the highest tier of any line in it, so demotion is inert — the notable set is bit-identical on both corpora — and promotion lifts a whole incident on one promoted line, growing the notable set 19 → 48 (synthetic) and 72 → 84 (OpenSSH) while never surfacing an attack the baseline missed. Thresholds were swept at p90/p95/p99 and none beats leaving it off, so this is a property of the aggregation and not a tuning problem; `SEQUENCE_SEVERITY_SHIFT = False`, with the numbers recorded in config beside it so nobody re-derives it. What *was* adopted is the modest thing the measurement supports: the surprisal as the **last tiebreaker** in `triage.py`, after event count and severity. Precision@5/@10/@20 is unchanged on both corpora and the rank by which an analyst has seen every attack instance moves 16 → 12 and 65 → 39. Ranking on surprisal alone is explicitly unsafe — it drops precision@5, because one lone line with a rare transition outranks a twenty-event brute force, and event count remains the stronger evidence. **This is a triage improvement and must never be written up as a detection one**: the same lines are flagged and the same incidents are grouped either way, and the report generator says so in the artifact rather than leaving it to the reader. Peer-group baselines were deferred rather than built: they fix cold start, which no number in `results/` measures, and since every detection change costs the same §4 measurement regardless of code size, the cheap-looking change is not the cheap change. The next step is the expensive one — suppression, using the surprisal to *clear* `is_anomaly` on lone routine-transition lines, which is the only lever that can reduce 94/194 incidents rather than reorder them. It moves every §4 number and owes the full camouflage suite including the 6.5h paced run, because a change that suppresses lone flagged lines is most likely to hurt `slow`, where the attack *is* a series of lone lines. 495 tests pass (`-m "not slow"`), plus both slow locks |
| 2026-09-01 | **The 31 Aug review deck moved out of the repo to `~/presentation-2026-08-31/`** | The review is over, and the folder was 48MB of deck, screenshots and reference PDFs that no code imports and no result depends on — carrying it in the repo taxes every clone for a one-off artifact. It is kept whole, generators included (`build_pptx.py`, `make_diagrams.py`, `capture_screenshots.py`), so it can be rebuilt or moved back if a later review wants it; the earlier entries describing it stay as written, and the paths in them now refer to that directory. Nothing about detection, evaluation or the results in `results/` changed. Note the three dev dependencies the deck pulled in — `playwright`, `markdown`, `python-pptx` — were deliberately **not** removed here, because `pyproject.toml` had uncommitted Stage 3 work in it at the time; drop them whenever that work lands if nothing else has picked them up |
| 2026-09-03 | **Alert suppression adopted at q0.90 and rejected at q0.99, on the full §4 suite. Loneness turned out to be the safety guard and the surprisal only the selectivity — the reverse of the intended design** | This is the first Stage 3 change that clears `is_anomaly`, so unlike the severity shift and the triage tiebreaker it moved every number §4 asks for, and it owed the whole suite rather than an argument. Three things were measured that overturned the plan the session started with. **The rule as specified is inert.** "Clear `is_anomaly` on lone flagged lines whose transition is *routine*" reads naturally as "at or below the fitted median", and at that threshold it suppresses **0 of 59** eligible rows on the synthetic corpus and 13 of 63 on the kill-point corpus. The cause is structural rather than a tuning miss: the flagged rows already *are* the anomalous tail, and a line the embedding detector found unusual almost never has a below-median template transition, because the two signals are positively correlated. The rule became "survives only if the transition is genuinely rare", using `rare_threshold` — a value the model already carried and the severity shift already used, so no new knob was invented to make the result work. **The guard doing the safety work is not the one the design was built around.** Restricted to flagged rows, the surprisal separates attack from benign at AUC **0.278** on the synthetic corpus and 0.645 on the kill-point corpus — at or below a coin flip, with attack lines scoring *lower* than benign ones — so suppressing on the surprisal alone would preferentially delete attacks. It reads 0.987 and 0.954 once restricted to lone rows, and the reason is worth stating plainly rather than banking: the lone attack lines that exist are impossible-travel hits, which the first guard removes from the pool anyway. So loneness and the travel exclusion are load-bearing and the threshold is not; any future change weakening the first two has to be re-measured from scratch, while relaxing the threshold is comparatively safe. Those AUCs are computed by the report rather than written into it, so they cannot drift from the code. **The threshold that measures best on clean data is the one that surrenders the camouflage margin, and both were run rather than one.** q0.99 is far the better-looking value on clean corpora — synthetic F1 0.446 → 0.624 and 94 → 44 incidents against q0.90's 0.456 and 90 — and under camouflage it costs `slow` **13.3pt of instance detection** (80.0% → 66.7%), drops its line rate from 0.824 to **0.266**, and removes 130 attack lines; it halves suite-wide alert volume (5,083 → 2,927 incidents) by deleting detections. That is the 2026-08-16 contamination lesson reproduced on a different knob, and the q0.99 arm was run *specifically* so the rejection would be a measurement instead of a claim of restraint. What was adopted, q0.90, leaves instance detection unchanged on all nine camouflage conditions and unchanged **seed by seed** — across 45 instance-firings it never removed the last surviving line of an instance — while cutting the kill-point corpus from 194 incidents to 147 and lifting its precision 0.206 → 0.248 with recall untouched at 0.570. **The cost is real, sub-instance, and exactly where it was predicted to be**: `slow` loses 8 attack lines (line rate 0.824 → 0.790) and `realistic-combo` 6 (0.776 → 0.741); every other condition loses none. The suppression rate carries the mechanism legibly — ~3% of flagged lines everywhere, rising to 4.3% and 5.0% on precisely the two timing-spread conditions — because spreading an attack in time is what makes its lines lone, and lone is what puts a line in the eligible pool. A +0.0pt row on the registered metric therefore does **not** mean nothing was paid, and the report prints the line rate beside it for that reason. Three design points are recorded in code because each is a silent failure otherwise. The model is fitted on a **separate benign-only corpus** at a disjoint seed (`logdet_eval/history.py`), never on the frame being scored (measured elsewhere at AUC 0.912 → 0.558) and never on ground-truth-selected benign rows, which is legitimate for a diagnostic but unavailable to a rule that must run at inference time. The **miner state travels with the model**, since cluster ids mean nothing across two independent miners; every condition mines from a restored copy so none mutates the state the next one loads, and mining continues rather than freezing so a genuinely new template gets an id the model does not know — which scores as silence, and silence never suppresses. And **suppression is batch-only**: loneness is not knowable at emit time, so applying it in `StreamProcessor` would withdraw alerts the batch path keeps and break the streamed-equals-batch lock, which is the only thing making streamed numbers comparable to `results/`. Making it work there means deferring by at least the incident window and re-verifying that lock — a separate piece of work, not a parameter. Two smaller decisions: `suppression` was added to the kill-point checkpoint resume guard, because a run half-suppressed and half-not would produce one reported differential describing neither system; and `ml_anomaly` is left untouched by a withdrawal, with the withdrawal recorded in its own `suppressed` column, so evaluation can still tell that a row was flagged and then retracted. The default flip is pinned by a test, so reverting it is a deliberate edit with a failing test attached. 527 tests pass (1 skipped), including both pinned regression locks — which stay green because neither the batch nor the stream path passes a sequence model, and suppression cannot fire without one. **This one is a detection change and must be written up as one**, unlike the triage tiebreaker: fewer lines are flagged and fewer incidents are grouped |
| 2026-09-03 | **Grouping moved onto an entity graph, and the move was made a verified no-op rather than an improvement.** The first thing the retained structure buys is evidence: an impossible-travel incident now carries the benign login it was compared against, kept structurally out of the flagged set | The tempting version of Stage 4 is to build the graph *and* change what it groups, and it would have been unfalsifiable: incident count is one of the four numbers §4 asks for, so a grouping change and a structural change landing together leaves no way to say which moved it. So the link rule is untouched and the partition is asserted to be the old partition — the pre-Stage-4 pairwise scan is kept in the test file as an oracle and compared on 24 randomised frames, a transitive chain, and the two pinned corpora. The equivalence is exact rather than empirical, and the argument is worth recording because it is also why the graph is faster: two events on one entity that are within the window have every intermediate gap within the window too, so chaining an entity's events consecutively connects exactly what the all-pairs scan connected, at O(events) per entity instead of O(events²). Host and process are recorded as nodes but are **not** grouping links, and that is not caution — LogHub OpenSSH is one host running one process, so a host edge merges all 655,147 lines into a single incident; an entity every event shares carries no information about which events belong together. What the structure makes askable is the point of keeping it. Union-find only ever held the *flagged* rows, so "this alert is alone" could not distinguish an IP seen once from a busy known host that also logged one odd line, and `neighbours`/`degree` now answer that over the whole frame — which is the guard doing the safety work in suppression (Decision Log 2026-09-03, first entry) and the honest lever for pushing it harder, in place of the threshold that has already been measured and rejected. The first *consumption* is deliberately the one that moves no number: the travel check compares a login with that user's previous login, the previous login is benign, so it was flagged nowhere, grouped nowhere and shown nowhere, and the incident asserted "impossible travel" while displaying one of the two logins the conclusion is about — the least defensible thing an analyst can be handed, and a Known Issue since v1. It is retrieved by a graph query and carried in `context_events`. **Evidence must not become a detection, and the separation is structural rather than promised**: `context_events` is not `events`, so it cannot reach `event_count`, severity, triage, or the bake-off's `ours_flagged`, which walks `events` — putting a benign line there would have converted a display fix into a false positive nobody would have looked for. The prompt is byte-identical when there is no evidence, so the 592-token narration-latency baseline (§2c) still compares. §4 was satisfied by verification, not by re-running the suite: 751 → 130 → 94 in batch and in the stream, all 94 incident entries identical on every pre-existing field, `is_anomaly` untouched. One defect surfaced only because the live check was run rather than trusted — the stream carried evidence on 1 of 3 travel incidents, because `_remember` prunes history relative to the newest line *after* scoring, so a micro-batch spanning more than the retention window drops the compared-against login in the same call that detects the hit; the snapshot now uses the frame the batch was actually scored against, and evidence found once survives a later update to the same incident. 574 tests pass (1 skipped) |
| 2026-09-04 | **Graph loneness for suppression: built, measured on the full §4 suite, and rejected. The shipped test stays. The reason it fails is the finding — the attack lines suppression costs are genuinely isolated, so seeing the benign traffic around an alert cannot protect them** | This was the question the entity graph was retained for. The 2026-09-03 measurement had established that loneness is the guard doing the *safety* work in suppression while the surprisal is only selectivity (among flagged rows the surprisal separates attack from benign at AUC 0.278 on the synthetic corpus, i.e. backwards), and that the honest lever for pushing suppression harder is therefore a better loneness test rather than a looser threshold, q0.99 having already been measured and rejected. Union-find could only see the flagged rows, so "this alert is alone" could not distinguish an unknown IP appearing exactly once from a busy known host that also logged one odd line; `EntityGraph.neighbours` answers that over the whole frame. Two tests were built either side of the shipped one and both were run through the entire section 4 suite — both clean corpora plus nine camouflage conditions over five seeds — because this guard clears `is_anomaly`. **`quiet`** (lone only when nothing at all shares the line's user or source IP inside the window) is **strictly dominated**: it removes the *same* attack lines as the shipped test, 8 on `slow` and 6 on `realistic-combo`, while suppressing fewer benign ones, so alert volume goes back up (626 → 632 incidents on `slow`, 497 → 503 on `baseline`) and nothing is bought. That is the result worth recording, because it refutes the reasoning the work was started on: the lines suppression costs are lone in the strongest sense already — on the timing-spread conditions there is no benign traffic around the alert either — so a stricter isolation test has nothing to grip. **`share@0.50`** (lone when the flagged share of the neighbourhood is at or below 0.5, i.e. a line grouping corroborates is still called lone when its entity is overwhelmingly benign) fails the other way and fails in the shape this project has now seen three times. On clean data it is the best-looking arm — kill-point OpenSSH 147 → 142 incidents and precision 0.248 → 0.260 with recall untouched at 0.570 — and under camouflage it has **identical incident counts to the shipped test on all nine conditions** while removing one attack line on `temporal` and one on `volume`, two conditions that previously cost zero (line rates 0.858 → 0.854 and 0.847 → 0.841). The clean corpora also show the mechanism directly: raising the share triples the attack lines admitted into the eligible pool, 3 → 9, leaving only the weak guard holding them back. That is the 2026-08-16 contamination lesson and the 2026-09-03 q0.99 lesson a third time, now on the guard rather than the threshold, and it is why both arms were run rather than only the one expected to win. Instance detection, the registered metric, is unchanged on every arm and every condition (100% except `slow` 80.0%, `ip_rotate` 84.4%, `realistic-combo` 91.1%), so nothing moved it in either direction and the rejection rests on evidence retained and alert volume — the two columns a `+0.0pt` row hides. What the graph did earn is an equivalence check rather than a gain: `share@0.00` reproduces `incident` exactly on both real corpora (84 of 84 lone rows and 4 suppressed on synthetic, 158 of 158 and 47 on the kill-point corpus), so the graph query and the grouper's own components agree outside the unit test that asserts it, and the neighbourhood counts stay in the module as a measurement instrument. Three smaller decisions are recorded in code. The loneness sweep runs at the *adopted* threshold only, because crossing it with the quantile sweep would move two knobs at once and the threshold is already settled. `share` above 0 is applied in **one pass against the pre-suppression grouping**, deliberately: it can withdraw a row from a multi-row incident, which can leave another row alone, and iterating would let suppression eat a whole incident one line at a time — precisely the failure the loneness guard exists to prevent (under `incident` and `quiet` one pass is exact rather than a choice, since removing a singleton cannot change any other incident's membership). And `SUPPRESSION_LONENESS` is pinned by a test at `"incident"`, so changing it is a deliberate edit with a failing test attached, the same protection the suppression default already had. The interpretation lives in `results/suppression/loneness/notes.md` rather than in a generator, following the bake-off precedent — a generator that writes conclusions is scripting the narrative |
| 2026-09-04 | **ATT&CK technique metadata comes from the pinned STIX bundle, not from the author; the keyword table survives because STIX has nothing to replace it with. The coverage matrix's denominator is computed from ATT&CK's own detection strategies, and reported twice** | The enrichment layer was the last place in the project where the author was still the authority on a third-party fact: every technique name and tactic in `mitre_mapping.py` was hand-typed, which is exactly the objection §1b removed from the rule baseline. It had already drifted, and the drift is the evidence rather than the worry — ATT&CK 19 renamed T1070's tactic from Defense Evasion to **Stealth**, T1078 carries **four** tactics where two were typed, and T1021.004 is a sub-technique whose STIX name is the bare `SSH`. So names, tactics, kill-chain position, deprecation status and declared log sources now come from Enterprise ATT&CK **19.2**, pinned by version and verified by SHA-256. What STIX cannot supply is the part people assume it can: **there are no keywords for log lines in ATT&CK**, so "ingest the bundle instead of the hand-written table" is not literally possible, and the honest form of the change is a split — *authored*: which message means which technique ID; *ATT&CK*: what that ID is. `MITRE_LOOKUP` now holds keywords and a join key, and a test fails if a name or tactic is typed back into it. Two deployment decisions follow from the local-first constraint. The 54MB bundle is **not** what the pipeline reads: a ~10KB projection of it is **committed** (`src/logdet/data/attack_index.json`), so an incident's technique description is deterministic, works with no network, and a version bump arrives as a reviewable diff rather than as results quietly changing under a `latest` URL. And the index builder **refuses** an ID ATT&CK does not carry, or has revoked or deprecated — an incident citing a withdrawn technique is a wrong answer delivered with a citation, which is worse than no citation. §4 did not apply and that was verified rather than argued: `is_anomaly`, grouping and severity are untouched, 751 → 130 → 94 holds in batch and in the stream, and all 94 incident entries are identical on every pre-existing field with identical technique-ID sets — the only movement is T1078's tactic string widening and the new `kill_chain` field. One measurement note: the prompt for an incident carrying T1078 grows 33 characters (~8 tokens), so §2c's 592-token smoke incident is now ~600. As for the coverage matrix, its whole difficulty is the denominator, because a coverage figure over a denominator the author picked measures nothing. It is computed by walking ATT&CK's own `detects` relationships to detection strategies, then to their analytics, then to the log sources those analytics name — a technique is visible when ATT&CK itself says it is detectable from a log source we read. That produces an **uncomfortable and therefore useful** result: **1 of 86** strictly-visible techniques mapped, and **9 of our 11 outside the universe entirely**, because ATT&CK's Linux analytic for T1110 Brute Force is `auditd:USER_LOGIN` rather than syslog. Both denominators are printed and never merged — strict is ATT&CK's, wider (adding auditd's authentication events) is an authored claim about *events* rather than files, and merging them would be choosing the answer. The third column is the one that bites hardest: **5 of 11 mapped techniques have never fired on either corpus**, their keywords (`scp`, `wget`, `crontab`, `useradd`, `shred`) describing traffic an sshd auth log does not contain, so counting them as coverage counts decoration. The report also states what it does **not** measure — it counts matches, not true positives, and enrichment precision needs technique-level ground truth no corpus here has. Interpretation lives in `results/coverage/notes.md` rather than in the generator, following the bake-off precedent |
| 2026-09-04 | **Stage 4's two remaining structural items were examined and declined rather than built, and the reason each fails is a measurement rather than a preference. Stage 4 is closed** | Both items were carried in the tracker as "still to do", which reads as work outstanding; neither survives contact with what can actually be measured here, and recording *why* is worth more than the code would have been. **Temporal decay on graph edges is a reparametrisation of the window, not a feature.** Grouping consumes edges through `components()`, which needs a hard partition, so any decayed weight has to be thresholded -- and for any monotone decreasing `w(gap)` and threshold `t`, "edge exists iff `w(gap) >= t`" is exactly "edge exists iff `gap <= w^-1(t)`", i.e. a plain window of that size. The partition is bit-identical to the one `INCIDENT_WINDOW_MINUTES` already produces, and landing it would cost the full section 4 suite because incident count is one of the four numbers section 4 asks for. It becomes a real feature only if something consumes a *continuous* weight, and the codebase has exactly one candidate consumer: suppression's loneness guard. That was measured the previous day in both graph variants and both were rejected, `quiet` being *strictly dominated* -- and the reason it failed is the reason decay cannot rescue it. The attack lines suppression costs (8 on `slow`, 6 on `realistic-combo`) are lone in the strongest sense already: on the timing-spread conditions there is no benign traffic around the alert at all, so a guard that weights neighbours by recency has the same nothing to weigh. **Multi-source correlation has almost nothing to correlate, and that was measured before the plumbing was written.** `data/external/Linux.log` is the only real corpus available here with genuine multi-service auth on one host (`combo`): 9,666 auth events across sshd 5,009, ftpd 3,453, su 944, telnetd 179, klogind 50, login 31, parsed by this project's own `LineParser`. Applying exactly the condition `EntityGraph.edges` tests -- two events from *different* services sharing a user or source IP inside the 30-minute incident window -- yields **2** links on `source_ip` (one IP, ftpd/klogind) and 70 on `user`, of which **all 70 are `root`**. Corpus-wide, ignoring the window entirely, **1 source IP of 331** and 2 users of 14 appear in more than one service, and ftpd and telnetd carry no username the parser can lift at all. The user column is worse than it looks rather than better: `root` is the account every service names, so joining services on it is the same failure `entity_graph` already refuses for host and process -- an entity every event shares carries no information about which events belong together. It is a legitimate join key *within* one service (a root brute force is a real attack), which is why this is a finding about cross-source joining and not a bug in `normalise_identity`. So the graph fed a second source would find **one** genuine cross-service link in 9,666 events, and any measurable cross-source correlation would have to come from an attack we authored and planted across two logs -- a correlation the author planted, found by the author's grouper, scored against the author's ground truth, which is the trap section 1b and section 8 exist to keep out of this project's claims. The structure is already there (`ENTITY_COLUMNS` carries host and process as nodes); what is missing is a corpus, not code, so it belongs at Stage 6 where section 2d's Kali runner produces real cross-source traffic with ground truth captured at generation time, and Stage 7 where ECS gives more than one source a common schema. The measurement is reproducible (`results/correlation/cross_source_overlap.py`, ~10s, no models) and the reading lives in `results/correlation/notes.md` rather than in a generator, following the bake-off precedent. Nothing here touched detection, grouping or scoring, so section 4 did not apply |
| 2026-09-04 | **Narrative faithfulness measured for the first time, and it failed a hard constraint: phi3 invents MITRE technique IDs in 33% of technique mentions on the synthetic corpus and 60% on OpenSSH. The constraint in section 2 was rewritten to say what is actually true rather than softened, and the checker's own precision was measured before its output was quoted** | Section 2 has said since v1 that *"the LLM never invents MITRE technique IDs"*, and section 8 lists letting it do so as an anti-goal, but the evidence for the claim was that nobody had seen it break since the v1 `"nan"` incident -- which is not a measurement, and is exactly the kind of asserted property this project's benchmark discipline exists to distrust. Measured on both corpora with every narrative checked against the exact prompt that produced it, the claim is false: **47 invented IDs on the synthetic corpus and 119 on OpenSSH**, in 33 of 94 and 87 of 193 narratives. The precise split matters and is now written into section 2 rather than around it: the *retrieval* is grounded and always was -- `mitre_techniques`, the kill chain, the dashboard and the coverage matrix are all `mitre_mapping` output joined to the pinned ATT&CK index, and `attack.py` refuses revoked or deprecated IDs -- while the *prose* was never protected by anything but a sentence in the prompt saying "do not invent new ones". An instruction is not an enforcement mechanism, and a 3.8B model does not treat it as one. The design decision stands; the sentence describing it was wrong and is corrected, with a Known Issue saying plainly that a demo must quote `mitre_techniques` and never a narrative's IDs. **The control arm was free and is the deployed system, which is why the result can be read at all.** 41 of 94 synthetic and 150 of 193 OpenSSH incidents match no technique, so their prompt carries the "No known technique matched" fallback and every technique ID in their narrative is invented by definition -- 24/24 and 107/107. Against 19% and 13% in the arm that was handed a list. So grounding genuinely reduces invention and does not prevent it, and the failure concentrates exactly where the detector has least to say, which is the opposite of what a reader wants. Without that split a low rate would not have distinguished "the grounding works" from "the model copies what it is given", and building an ablation would have cost a second run; the deployed fallback is both cheaper and more honest. Three findings sharpen it. All 24 distinct invented IDs on the synthetic corpus are **real ATT&CK identifiers**, checked against the pinned 19.2 bundle -- **6 revoked or deprecated**, precisely what the index builder refuses to carry -- so they are harder to catch than fabricated strings, and several are impossible on an sshd log (T1047 WMI, T1207 Rogue Domain Controller, T1538 Cloud Service Dashboard). The names are often wrong beside the right ID (*"T1567 - Failed Authentication"*; T1567 is Exfiltration Over Web Service), which a reader checking the ID would find contradicted. And the worst failures are not techniques at all: seven narratives fabricate an **entire incident summary block in the voice of the system** -- incident 7 was one event at 08:21:00 with no user and no source IP, and its narrative opens with "10 anomalous events" and two RFC1918 source IPs. That reads like tool output rather than prose and would survive a demo unchallenged. Two method decisions are recorded because each would otherwise be a silent way to report a nicer number. **No LLM judge**: judging whether a *story* is faithful needs one, and it would put an unmeasured model inside the measurement, so the harness checks only entities that can be extracted deterministically and the report states in its own text that entity groundedness is a floor rather than proof of correctness. **The checker's precision was measured before its output was quoted**, and it was wrong twice: phi3 rewrites 13:38 as "1:38 PM", a correct restatement that read as invention and put the `time` column at 57.3% ungrounded until it was handled (now 10.8%); and a stopword list for username claims was measured failing on the first three real narratives ("the user attempted", "account discovery") and was replaced by a plausibility rule -- a name counts as a claim only when quoted or when the corpus contains it -- which trades recall for precision deliberately, because a user check with false positives pollutes every other figure in the report. `--rescore` re-checks saved narratives without calling the model, so fixing an extraction rule costs nothing and, more importantly, cannot regenerate the narratives under the fix and make before and after uncomparable. Section 4 did not apply -- nothing here touches detection, grouping or scoring -- and the interpretation lives in `results/faithfulness/notes.md` rather than in the generator, following the bake-off precedent. The fix the data supports is Stage 5's structured output with the technique field validated against the grounded list; two cheaper things are worth measuring with this harness first, rewording the empty-match prompt so that "no technique applies" is stated as the correct answer, and checking the technique name against the bundle as well as the ID |
| 2026-09-04 | **The narrative hallucination is fixed and the fix is two changes, not one: a reworded empty-match prompt did most of it, and structured JSON output with a validated technique field did the rest. The technique-*name* check was built, found nothing, and the reason it finds nothing is the useful part** | The previous entry recorded a hard constraint failing -- phi3 inventing MITRE technique IDs in 33% of technique mentions on the synthetic corpus and 60% on OpenSSH -- and named structured output as the fix the data supported, with two cheaper things worth measuring first. All three were built and all three were measured on both corpora, which is what makes the ordering claim testable rather than a preference, and the cheap one turned out to carry most of the result. **The empty-match prompt was a wording bug with a large effect.** The fallback line said "No known technique matched; treat as a novel/unclassified anomaly" while instruction 2 continued to ask *"Which MITRE ATT&CK stage(s) this incident progresses through"* -- so the prompt demanded a stage while handing over nothing to name one from, and the model filled the hole every single time it mentioned a technique at all (24/24 synthetic, 107/107 OpenSSH). Stating instead that no technique applying **is** the correct answer, and dropping the demand, takes that arm to **0 mentions and 0 inventions on both corpora**. Zero mentions rather than zero errors is the honest description: told that "none applies" is an answer, the model stops naming techniques rather than naming correct ones -- and it does not go quiet, since narrative length is unchanged at a median 1261 characters against 1287. That arm is 41 of 94 synthetic incidents and **150 of 193** OpenSSH ones, i.e. the deployed system's commonest case, which is why a wording change moved the headline further than the architectural one did. An accidental control makes the attribution safe: the grounded arm's prompt is **byte-identical** across the two runs, and it moved 23/118 to 12/101 and 12/90 to 6/79 on identical input, so ~10 mentions is run-to-run noise at temperature 0.2 and only the control-arm change is attributable. **Structured output is the enforcement and is now the default.** The technique claim moves out of the prose into a named JSON field that `validate_structured` checks against the incident's grounded list, dropping any ID the lookup did not hand over before rendering; Ollama's `format: "json"` constrains the decoder so this does not rest on the model closing a brace. Measured: **0 invented IDs on both corpora**, 0 replies that would not parse, 0 invented IPs or usernames, and the failure the previous entry called the worst -- seven narratives fabricating an entire incident-summary block in the system's own voice -- goes 7 to 2 to **0**, because a fixed output schema leaves nowhere to put it. Two honest qualifications travel with those numbers. The **denominator changed**: the rendered narrative carries a `MITRE ATT&CK:` line built from the grounded list, so 65 and 58 mentions are not the same population as 142 and 197, and the number that means something is that no invented ID survives anywhere in the text (counted directly, 4 IDs appear outside that line on synthetic, all grounded, and 0 on OpenSSH). And **validation fired once in 287 narratives**, so most of the gain is again a clearer task rather than the guard catching a determined hallucinator -- the guard's worth is that it is a guard, holding for a model or a corpus where compliance does not. The cost is **brevity**: ~546 characters against ~1287, because a model answering in JSON writes one or two sentences where it wrote four despite the schema asking for 4-6. It covers all four requested items and reads as a structured briefing rather than a story, and whether that is a loss is a judgement about the audience, not a measurement -- the one thing here that was not measured. It is also faster, 2.0s against 3.4s per incident on the 4060. The default is pinned by a test, like the suppression default and `SUPPRESSION_LONENESS`, so reverting to prose is an edit with a failing test attached. **The name check found nothing, and that is a result rather than a dud.** `technique_name` validates a delimited name cited beside an ID against ATT&CK's own name, its sub-technique halves and its tactics -- the last because the prompt hands over `- T1110 (Brute Force) - Credential Access`, so writing "T1110: Credential Access" restates the prompt. It reads **0 wrong of 43** and 0 of 33. The shipped check only covers names beside an ID the incident was **handed**, because the committed index carries just the 11 techniques this system can emit and there is nothing offline to check a foreign ID's name against; measured against the full 54MB bundle instead, names beside an **invented** ID are wrong **39 of 40** and **61 of 64** ("T1046: Pass the Hash", "T1078: Port Scan", "T1059: Session Hijacking"). So the invention is **whole-cloth** -- an ID and a name made up together -- and phi3 names a technique correctly every time it is actually given one. The check ships anyway as a regression guard on a failure that does not currently occur, which is cheap; the diagnostic that explains the zero lives in `results/faithfulness/invented_name_check.py` rather than in the pipeline, since it needs a gitignored 54MB file. Two limits are carried forward rather than closed. A **dropped ID is invisible to the reader**: it is recorded in `StructuredNarrative.dropped` and in the harness, but nothing surfaces it in the dashboard or the API, so nobody looking at an incident can tell the model tried to cite a technique and was overruled. And this still measures **entities, not stories** -- a structured narrative can ground every ID, IP and count and still assert a causal order the log does not support, which needs a human or an LLM judge, and an LLM judge would put an unmeasured model inside the measurement. Section 4 did not apply to any of it: nothing here touches detection, grouping or scoring, and both pinned regression locks (batch and streamed 751 to 130 to 94) stay green. The interpretation lives in `results/faithfulness/arms/notes.md` rather than in a generator, following the bake-off precedent |
