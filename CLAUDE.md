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
- **The LLM never invents MITRE technique IDs.** Techniques come from data
  (lookup table, ATT&CK STIX, Sigma tags); the LLM only writes prose about matches
  it is handed. This is the design decision that stops the headline feature from
  being a hallucination generator. See the v1 `"nan"` incident in `docs/CLAUDE.v1.md`.
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

The SSD now boots on a **borrowed laptop of the same model family but a different
GPU**, and that is where development happens for now. The RTX 4060 machine is
reserved for **final testing and the demo**.

| | Dev box (this one) | Final-test box |
|---|---|---|
| GPU | **RTX 3050 6GB Laptop** (GA107BM) | RTX 4060 8GB |
| CPU | i5-13450HX, 10c/16t | — |
| RAM | 15GB total, ~11GB available | — |

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
  so label every latency figure with the machine that produced it.
- **Developing on the smaller GPU is the safe direction.** Anything that fits
  6GB fits 8GB. The reverse would not hold, which is why the borrowed machine is
  an acceptable dev box but not an acceptable place to measure the demo.

**The RAM squeeze is gone here.** ~11GB available against the ~5GB that forced
the "Wazuh manager only, never the full stack" decision (Decision Log
2026-08-17). That decision is not reversed — the manager-only setup is also the
better comparison and the better demo — but it is no longer *forced* by memory
on this machine, and it may still be forced on the 4060 box. Re-check there.

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

**Current stage:** Stage 2 — live ingestion
**Stage 1 started:** 2026-08-18 → **kill-point deadline 2026-09-15** (4 weeks, §1b)
**Last session:** 2026-08-30 (Stage 2: FastAPI service owning the live stream -- start/stop, ranked incidents, status/lag, SSE feed, on-demand narration)
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

      Still to do: paced replay for demos (the eval track already has
      `paced_replay.py`); point the dashboard at the API instead of at a JSON
      file.

      **Narration latency, measured 2026-08-30** on the dev box (§2c), phi3, the
      pipeline's own prompt, median of 3 runs:

      | Machine | Median per incident |
      |---|---|
      | GPU, RTX 3050 6GB | **5.2s** |
      | CPU only, i5-13450HX 10c/16t | **24.2s** |
      | v1 CPU, old laptop | 40-60s |

      This supersedes the "40-60s/incident on CPU is a floor" figure carried from
      v1 — that was *one machine's* number, not a property of CPU inference, and a
      faster CPU roughly halved it. **All three figures must be labelled with the
      machine that produced them and never blended.** The GPU result is the
      important one: at ~5s, near-real-time narration is honest rather than an
      apology, and it was measured on the *smaller* GPU, so the 4060 is at least
      this good. Re-measure there before quoting a demo number.

      **Ollama needs the `ollama-cuda` package on Arch, not `ollama`** — the plain
      package ships only `libggml-cpu-*.so` and runs 100% CPU while `nvidia-smi`
      looks perfectly healthy. Verify with `ollama ps` and check the `PROCESSOR`
      column says GPU; a loaded driver proves nothing.
- [ ] **Stage 2b — Live Bake-Off.** ⭐ *The demo. Depends on Stage 1 + Stage 2.*
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
- [ ] **Stage 3 — Detection depth.**
      **Drain3** online template mining replacing hand-written regex (makes the system
      source-agnostic; it is also what the log-anomaly literature uses).
      **Sequence modelling** — the highest-value single change available. v1 scores each
      line independently, but attacks are sequences; a single odd line is weak evidence
      and an odd *sequence* is strong evidence. This is the root cause of the 0.29
      precision. Even a Markov transition model over template IDs per user would help.
      Also: peer-group baselines (fixes cold start), score calibration so severity tiers
      mean something numeric, drift handling.
- [ ] **Stage 4 — Correlation & MITRE.** Replace union-find grouping with an **entity
      graph** (users/IPs/hosts/processes as nodes, events as edges, incidents as
      temporally-decayed connected subgraphs) — this is what makes multi-source
      correlation possible. Ingest the official **ATT&CK STIX bundle** instead of the
      hand-written table; add tactic and kill-chain mapping; produce a **detection
      coverage matrix** (which techniques can this system even see?).
- [ ] **Stage 5 — LLM layer maturity.** Structured JSON output instead of free prose;
      model routing (small/fast for triage lines, larger for full narratives); retrieval
      over ATT&CK text; and **automated faithfulness evaluation** — does every claim in a
      narrative trace to a logged event? The anti-hallucination architecture is currently
      asserted and untested.
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
- **Scenario B (impossible travel) is detected entirely by the hand-written rule** —
  the embeddings contribute nothing, because both login legs are identical vectors after
  IP masking. Never claim "embedding-based detection catches impossible travel."
- **Impossible-travel incidents show the conclusion without the evidence** — only the
  arriving login is flagged and grouped; the earlier login it was compared against is
  benign and never carried in. Display-layer bug, detection unaffected. Fix when the
  entity graph lands (Stage 4) — it makes carrying the compared-against event natural.
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

# Stage 1 (kill point). Wazuh must be up: docker start wazuh  (see Known Issues)
uv run logdet-fetch-data openssh                # Zenodo LogHub fetch, SHA-256 verified
uv run logdet-corpus --ambient-ratio 0.05       # build the kill-point corpus + manifest
uv run logdet-killpoint --seeds 5               # THE measurement, ~40 min, saturates CPU
uv run logdet-killpoint --seeds 1               # smoke pass only -- NOT admissible (§4)
uv run streamlit run src/logdet/dashboard.py
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
| 2026-08-19 | **The §1b kill point returned CONTINUE: best measurable differential 31.1pt on `rephrase`, 5 seeds, Wazuh available throughout.** Recorded exactly as computed, including the `ip_rotate` loss. The roadmap continues; the amplifiers (streaming, bake-off, two-machine, GPU) are unlocked | The assumption the whole roadmap rested on — that v1's robustness gap survives rules the author did not write — held, but *narrowly and by one mechanism*. Wazuh loses 33.3pt under `rephrase` while this system loses 2.2pt: sshd rules match on literal strings (`Failed password`, `Invalid user`), so rewording the message drops them out of the decoder entirely, whereas a sentence embedding of a reworded line stays near the original in vector space. That is a real and explainable property, not luck. It is also the *only* strategy that produced a gap: `mimicry`, `noise` and `volume` are 0.0pt ties, and **`ip_rotate` goes the other way — we lose 11.1pt, Wazuh loses nothing**, because rotating source IPs defeats per-user embedding context while Wazuh's per-IP frequency rules simply fire on whichever IP still crosses the threshold. §1b's registered wording is "≥25pt on at least one strategy", so `verdict()` taking the maximum is the reading as registered rather than a post-hoc choice — the function is a hard-coded literal ladder written before any result existed and pinned by 11 tests. The write-up must therefore claim the mechanism ("signature rules break when you reword; embeddings do not"), never the broad claim ("more robust to camouflage"), and must carry the `ip_rotate` loss in the same table. Three strategies stay excluded pending paced replay, so this verdict is provisional in scope even though it is final in force |
