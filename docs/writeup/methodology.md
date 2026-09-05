# Methodology

*Draft chapter. It describes how the system is built and, more importantly, how it is
measured. Nothing here was computed or re-run while writing: configuration values are
cited to the module that defines them, procedures to the module that implements them,
and every result mentioned in passing to the artifact that records it. Source of record
for results: `docs/FINDINGS.md`; the chapter that reports them is
`docs/writeup/results-chapter.md`.*

---

## 1. What this chapter has to establish

The claim this project defends is narrow — signature rules break when an attack is
reworded and embeddings do not, while against timing and IP rotation the embedding
detector is the weaker system. A narrow claim only means something if the measurement
behind it could have come back the other way, and could not have been quietly steered
once it did.

So this chapter has two jobs and they are not equally interesting. The first is to
describe the system under measurement, which is conventional and is dealt with briskly
in §2. The second is to describe the measurement itself in enough detail that a reader
can say where it would have broken: what was fixed in advance, what is authored and what
is third-party, which instrument answers which question, and what stops the author from
grading their own homework. §§4–12 are that.

Four commitments run through all of it, and each is enforced by something other than
intention:

1. **The deciding criterion was written down before the code existed** (§8).
2. **The rules and the attack tooling come from third parties, run by their own engines**
   (§§5–6).
3. **No change to detection, grouping or scoring lands without re-running the adversarial
   suite** (§11).
4. **The evaluation track may never be imported by the pipeline**, checked statically in
   CI rather than by convention (§12).

---

## 2. The system under measurement

The detection method is standard and is not claimed as the contribution. Isolation Forest
over sentence embeddings is a common design, and a local LLM writing an incident summary
is a common design. What is uncommon is the measurement regime around them, so the system
is described here only to the depth needed to interpret the results.

### 2.1 Ingestion and parsing

Lines arrive from a file tail, from systemd's journal, from a wall-clock replay of a
recorded log, or over HTTP from a remote collector. Every path produces the same parsed
record, so a streamed run and a batch run are comparable by construction — asserted, not
assumed, by a regression test that replays the synthetic corpus in micro-batches and
requires the same flagged events and the same incidents as the single-pass run
(`tests/test_stream_regression.py`).

A syslog line is parsed into eight columns: timestamp, host, process, pid, message, user,
source IP and `template`. `template` is the message with its variable fields masked —
IPs, ports, PIDs and bare numbers replaced by placeholders (`logdet/preprocessing.py`,
`template_message`) — and it is `template` that is embedded, not the raw message. Two
consequences matter later: semantically identical lines from different hosts collapse to
one point in vector space, and **the detector never sees a source IP**, which is why
impossible travel has to be a separate rule (§2.3) and why rewriting the attacker's IP in
a corpus does not change what the detector is looking at.

A second parser reads nginx/Apache access logs and reaches the same eight columns
*through* an Elastic Common Schema document rather than around it
(`logdet/weblog.py`, `logdet/ecs.py`). ECS is adopted as a boundary format only:
detection, grouping and scoring key on the internal columns throughout, so adding a
source cannot move a detection number.

Timestamps carry no year in syslog, so year rollover is inferred from a backwards month
jump (`YEAR_ROLLOVER_MIN_DROP = 6`). Without it the OpenSSH corpus, which spans December
into January, silently places January before December and corrupts every window-based
computation in the pipeline.

### 2.2 Detection

Each parsed line's `template` is embedded with `all-MiniLM-L6-v2`
(`logdet/config.py`, `EMBEDDING_MODEL`). An Isolation Forest is fitted **per user** at
`CONTAMINATION = 0.20`, falling back to a global model for any user with fewer than
`MIN_SAMPLES_PER_USER = 5` lines. Per-user baselines are the design point: anomaly is
judged relative to that account's own history rather than against a global notion of
suspicious, which is what stops "any login from an unusual country is bad" from being the
model.

`CONTAMINATION = 0.20` favours recall deliberately. The Decision Log records the sweep
behind it (0.05 gives precision 0.62 / recall 0.36; 0.20 gives 0.30 / 0.87) and the
project's position: this is analyst decision support, and a missed attack costs more than
an extra alert. That choice is the direct cause of the precision weakness reported in the
results chapter, and §11 explains why five attempts to reverse it were rejected.

Fitting and scoring are separable. `logdet-fit` writes a detector to disk with a
provenance stamp — embedding model, vector width, hyperparameters, library version — and
loading refuses a mismatch, because an Isolation Forest will happily score embeddings
from a different model and return numbers that look fine and mean nothing. The streaming
path always scores against a model fitted on history and never fits on the traffic it is
judging, which would let an attacker's own volume define normal.

### 2.3 Rules that embeddings cannot supply

**Impossible travel** is a physics check, not a learned signal: the same user logging in
from a different subnet within `IMPOSSIBLE_TRAVEL_WINDOW_MINUTES = 60`, where "different"
means the first `TRAVEL_SUBNET_PREFIX_LENGTH = 2` octets differ. It exists because
`template_message` masks the IP before embedding, so both legs of a travel attack embed to
the *same vector* — the embedding layer is blind to it by construction. This is stated as
a limit in the results chapter and must never be written up as embedding-based detection.

**Severity tiers** bucket the anomaly score (`SEVERITY_THRESHOLDS`), with a hard override
to `high` for impossible-travel hits.

### 2.4 Correlation into incidents

Flagged events are grouped into incidents over an entity graph: users, source IPs, hosts
and processes are nodes, events inside `INCIDENT_WINDOW_MINUTES = 30` are edges, and an
incident is a connected component (`logdet/entity_graph.py`). Grouping links on user and
on source IP (`GROUP_BY_SOURCE_IP = True`) — account enumeration varies the username on
every line by design, so a user-only rule would split one attack into N singleton alerts.

Host and process are recorded as nodes but are deliberately **not** grouping links: the
OpenSSH corpus is one host running one process, so a host edge would merge all 655,147
lines into a single incident. An entity every event shares carries no information about
which events belong together.

Parser placeholders (`unknown`, `none`, `-`, …) are excluded from joining
(`NON_IDENTITY_VALUES`), so an absent identity can never become a shared one.

The move from the earlier pairwise scan to the graph was made a **verified no-op** rather
than an improvement: the old algorithm is kept in the test file as an oracle and compared
against the graph on randomised frames and on the pinned corpora. Landing a structural
change and a behavioural change together would have left no way to attribute a moved
incident count to either.

### 2.5 Enrichment, and where the MITRE claim comes from

Every MITRE technique the system *reports* is retrieval output, never model output. An
authored keyword table says which message means which technique ID; everything else about
that ID — name, tactics, kill-chain position, deprecation status, description — comes
from the official Enterprise ATT&CK STIX bundle pinned at **19.2**, verified by SHA-256
and projected into a small committed index so the pipeline stays offline and
deterministic (`logdet/attack.py`). The index builder refuses an ID ATT&CK does not
carry, or has revoked or deprecated.

The split is stated explicitly because ATT&CK publishes no keywords for log lines, so
"ingest the bundle instead of the hand-written table" is not possible: *authored* is which
message means which ID, *ATT&CK* is what that ID is. A test fails if a technique name or
tactic is typed back into the keyword table.

### 2.6 Explanation

A local LLM (phi3 by default, via Ollama) writes the incident narrative. Two things make
it measurable rather than decorative. The technique claim lives in a named field of a
structured JSON reply that is validated against the incident's grounded technique list,
and any ID the lookup did not supply is dropped before rendering
(`LLM_STRUCTURED_OUTPUT = True`). And narration has two tiers — a one-sentence triage line
capped at `LLM_TRIAGE_NUM_PREDICT = 120` generated tokens, and the full structured
narrative — because the cost of narration is generation length, not parameter count.

The faithfulness of the output is itself measured, by an instrument described in §10.4.

### 2.7 Interfaces and deployment

A FastAPI service owns the stream and serves incidents, a live event feed and on-demand
narration; a Streamlit dashboard reads that service; a collector endpoint receives lines
shipped from a remote box. For deployment the collector and analyzer split into two
containers that meet **at a file on a shared volume, never on the network**, so the
collector keeps buffering across an analyzer restart and the analyzer's stream resumes
from its own byte offset (`docker/README.md`).

None of this scores anything. Detection, grouping and severity live in one place, which
is what keeps the streamed-equals-batch lock meaningful.

---

## 3. Constraints fixed before the work, and honoured throughout

These are design positions, not timeline excuses, and they shape what could be measured
(`CLAUDE.md` §2).

- **CPU is the supported floor; the GPU is an accelerator.** The system must run end to
  end on a machine with no GPU. "Runs on a laptop with no GPU" is the reason a team with
  no SOC budget could deploy this, and the moment a GPU becomes required the project
  becomes one more ML security tool with infrastructure demands. Every latency figure is
  therefore reported per machine and never blended.
- **Local-first.** No required cloud API.
- **No fine-tuning of the narrative LLM, and no models above 8B parameters.** Fine-tuning
  does not fix the detection problem and makes results much harder to reproduce.
- **No auto-response, blocking or SOAR.** The system may recommend an action; it must
  never take one. This is a product stance, not a scope cut.
- **Every reported MITRE technique comes from data**, never from the LLM (§2.5).
- **Single-box mode must always work.** The two-machine split is a deployment option; a
  dead network link must downgrade a demonstration, not end it.

One of these was measured false and rewritten rather than quietly kept. The constraint had
read *"the LLM never invents MITRE technique IDs"*; the architecture protected the
structured output, but the narrative prose was protected only by a sentence in the prompt,
and the model ignored it. The constraint now says what is actually enforced, and the
episode is reported as a result (`results/faithfulness/`). An instruction in a prompt is
not an enforcement mechanism.

---

## 4. Corpora

Three corpora, each with a different job.

### 4.1 The synthetic corpus — regression, not evidence

751 lines, 5 users, 5 simulated days, 9 attack instances across three scenarios (brute
force, impossible travel, account enumeration), generated from a fixed seed
(`src/logdet_eval/config.py`, `SYNTHETIC_*`). It has complete ground truth, which is why
every camouflage sweep runs against it, and its numbers are pinned in a regression test.

Its limit is stated up front and is the reason the kill point exists: **the v1 rule
baseline is near-oracle by construction**, because the corpus is built from the same three
attack templates the rules encode. A baseline that scores F1 0.96 on data authored around
it is not evidence about the world.

### 4.2 LogHub OpenSSH — the real corpus

655,147 real sshd lines, 100% parse rate, chosen over the labelled datasets the literature
prefers. HDFS and BGL are labelled, but their anomalies are **system faults, not
adversarial behaviour**: there is no technique ID for a failed block replication, no
attacker for a narrative to describe, and camouflage is semantically undefined because
nobody is choosing to hide. Running on them would benchmark the one layer this project
does not claim as a contribution while switching off both things that make it distinctive
(`CLAUDE.md` §3b).

The OpenSSH corpus has no labels, which is handled by injection rather than by hand
labelling (§4.3).

### 4.3 The kill-point corpus — how a real background is built

A measured property of OpenSSH forced this design: **66–83% of every day is internet brute
force**, and only about 2,400 of 655,147 lines are genuinely benign. Injecting an attack
into the raw corpus would make brute force the statistical majority of "normal", so an
injected brute force would score as an *inlier* — the resulting differential would measure
base-rate contamination rather than camouflage robustness. That is a corpus that
invalidates an experiment rather than one that fails it honestly.

So the background is built explicitly (`logdet_eval/corpus_openssh.py`): real benign lines,
plus real attacker traffic downsampled to a declared `ambient_ratio`, with attacks
injected on top. Every line is real — the benign traffic, the ambient attacker traffic,
the usernames, the host, the vocabulary — and the ambient density becomes a *declared
parameter to report sensitivity across* rather than a hidden default. The primary setting
is `ambient_ratio = 0.05`, and the win was re-measured across a 20× range precisely
because a claim resting on one arbitrary background density is a claim waiting for an
objection (`results/killpoint/killpoint_ambient_sensitivity.md`).

**Attack magnitudes were pre-registered** before any differential was computed
(`src/logdet_eval/config.py`, `KILLPOINT_*`): 15–25 failures for brute force, 10–12 probes
for enumeration. The reasoning is recorded there and matters, because it cuts against this
project's interest: v1's scenarios were sized against v1's own hand-written baseline, which
makes them smaller than anything a production SIEM alerts on — Wazuh's brute-force rules
need 8 events in 120 seconds. Measuring a third-party ruleset against a 4-attempt "brute
force" and reporting that it missed the attack would handicap the comparator, which is the
mirror image of writing rules for attacks you authored and equally fatal.

### 4.4 Authentic captures

For the un-camouflaged case the attacks themselves are third-party: real `hydra` and `ssh`
runs against a real sshd on a separate machine, with ground truth captured **at generation
time** and travelling with the lines (§10.3). These captures are then injected into the
same real background, at the same ambient ratio and seeds and through the same scorer as a
matched synthetic arm, so the only difference between the arms is where the attack lines
came from.

---

## 5. The adversary model

### 5.1 What is authored, and why that is the right layer to author

Three things are stated together in every write-up of an adversarial run, because leaving
any of them out would overclaim:

- **Base attacks are real tool output** for brute force and enumeration.
- **The camouflage layer is authored.** That is the layer this project is *supposed* to
  own — measuring camouflage is the contribution.
- **Impossible travel's distant leg is synthetic by necessity**, because it needs a second
  geographically distinct IP that a single lab machine cannot produce.

### 5.2 The seven transforms

All seven live in one stdlib-only module (`src/logdet_eval/camouflage.py`) so that the
synthetic evaluation path and the Kali attack runner apply *identical* transforms and stay
comparable. Camouflage is applied to the **event list, never to a finished log file**, so
each attack line keeps its scenario and instance label through timestamp shuffling, noise
injection and rewording — which is what keeps scoring automatic under every condition.

| Strategy | What it does |
|---|---|
| `temporal` | re-spaces an instance's events by 8–20 minutes — inside the 30-minute grouping window |
| `slow` | re-spaces by 35–90 minutes — outside it |
| `rephrase` | swaps a message for a semantically equivalent alternative wording |
| `mimicry` | rewrites distinctive attack lines into the shape of the corpus's dominant benign template |
| `noise` | injects benign filler at 1.5 lines per attack line |
| `volume` | keeps 50% of the repeated middle events, preserving first and last |
| `ip_rotate` | gives each line its own source IP, breaking the source-IP grouping axis |

Two design points are recorded in the module itself. The two temporal spreads straddle
`INCIDENT_WINDOW_MINUTES` on purpose — the pair is what demonstrates that the window is
the thing doing the work. And `rephrase` and `mimicry` are opposites, both shipped
deliberately: novel wording makes an attack *more* anomalous to an outlier detector, so
real evasion means adopting the phrasing that already dominates benign traffic. That
prediction is confirmed in the results, where `rephrase` raises this system's own line
detection.

`realistic-combo` is the eighth condition: `slow + mimicry + noise + volume + ip_rotate`,
i.e. everything that does not require inventing novel wording. It is described as the
strongest *realistic* attacker, and §10.2 records what an optimiser thought of that
description.

### 5.3 Magnitudes as data

Since the adaptive adversary was built, a camouflage configuration is a `CamouflagePlan`
— the strategy set *and* the magnitudes, as data. The defaults are exactly the published
constants, so a plan naming the fixed strategies reproduces the fixed recipe byte for
byte; a test pins that with SHA-256 over the camouflaged log and its ground-truth CSV
across seeds and conditions. That is what made it possible to add a searching attacker
without invalidating any previously published camouflage number.

---

## 6. The comparator

**Wazuh, run as the real manager in Docker**, executing its own rules through its own
engine (`logdet_eval/wazuh_runner.py`). The alternative — reimplementing Wazuh's rule
semantics — would keep the rules third-party while making the *matching* ours, which
reintroduces author influence at exactly the layer being measured; its decoder chain and
`if_matched_sid` / `frequency` / `same_source_ip` semantics are intricate enough that a
faithful reimplementation is its own research project.

**Sigma was the original choice and was dropped after measurement, not after
inconvenience.** Across ~3,300 rules in the official repository, not one matches `Failed
password`, `Accepted password`, `Invalid user` or `pam_unix`; its Linux rules target
auditd/Sysmon telemetry this project does not have, and **zero** of them use a
frequency threshold — precisely the rule class `slow` camouflage exists to defeat. A
ruleset that detects nothing before camouflage cannot exhibit a measurable degradation.
The kill-point criterion was not touched by the swap, since §1b had already named Wazuh as
an option; the Sigma coverage gap is itself reported as a finding.

Nothing about the comparator is modified in any run: not its ruleset, not its engine, not
its container clock. Two tempting accelerations were rejected for exactly that reason —
time dilation (compressing the clock and dividing Wazuh's `timeframe` by the same factor)
and `libfaketime` on `analysisd` — because each alters the third party the project is
being compared against, which is what the kill point exists to prevent.

---

## 7. Metrics

**Instance detection** — the share of injected attack instances where *at least one* line
was flagged. It answers "would an analyst see this attack at all", and it is the
registered deciding metric.

**Line detection** — the share of an attack's ground-truth lines that were flagged.
Reported alongside instance detection because instance detection saturates at 100% on
clean data, and the line rate is where a mechanism stays visible after the headline metric
has hit its ceiling.

**Differential** — how much further the comparator's instance detection dropped than this
system's, under identical camouflage on identical corpus files. Positive means this system
held up better.

**Alert volume** — incident count for this system, alert count for Wazuh. These are
different units and are always labelled as such; the ratio is the finding, not the digits
(and see §13 on their reproducibility).

**Line-level precision / recall / F1** against ground truth, reported for continuity with
the v1 baseline.

Three scoring rules are enforced in code rather than by discipline:

1. **One detector-agnostic scorer serves both systems** (`logdet_eval/scoring.py`). Both
   are reduced to a set of flagged 1-based line numbers and scored by the same function,
   with a test asserting it agrees with the older adversarial scorer on identical input —
   two scorers drifting apart would silently turn the differential into an artefact of the
   scoring code.
2. **Lines outside the ground truth are not counted as false positives** in the kill-point
   scorer, because the real corpus contains genuine attacks nobody labelled, and counting
   them would penalise a system for being right.
3. **Rates are pooled from summed confusion counts across seeds, never averaged.** With 9
   instances per corpus a per-seed instance-detection rate moves in 11-point steps, so
   averaging misreports; pooled over five seeds the step is 2.2 points. Single-seed
   instance detection is explicitly inadmissible.

---

## 8. The pre-registered kill point

The whole roadmap rested on one unverified assumption: that v1's robustness gap would
survive contact with rules the author did not write. v1's headline collapse was measured
against *self-written frequency-threshold rules* that `slow` defeats almost by definition,
and a mature third-party ruleset degrades by a different mechanism, so those numbers do
not transfer.

The assumption was therefore tested first, cheaply, before anything was built on it, and
the criterion was fixed in version control **before any Stage 1 code was written**
(`CLAUDE.md` §1b):

| Result | Decision |
|---|---|
| **≥25pt** differential on at least one strategy | **Continue** — build the roadmap |
| **10–25pt** | **Partial** — cheap stages only, skip the amplifiers |
| **<10pt**, or the SIEM degrades *less* than this system | **Stop** — publish the negative result |

Also fixed in advance: the experiment is batch mode on one machine, the deciding quantity
is the drop in instance detection for each system, pooling is over ≥5 seeds, and the
deadline is four weeks. Calibration was recorded too — v1's differential was 87pt against
8pt, so 25pt is a far lower bar.

Three properties make it binding rather than decorative:

- **The verdict function is a hard-coded literal ladder**, written before any result
  existed and pinned by tests at its exact boundaries (25.0 → continue, 24.0 → partial,
  10.0 → partial, 9.0 → stop), with a test asserting that a SIEM degrading *less* than
  this system is a stop and that a detector-only run returns `INCOMPLETE` rather than any
  verdict. A refactor that quietly changed a roadmap decision fails CI.
- **"≥25pt on at least one strategy" means the maximum is the registered reading**, so
  taking the maximum is not a post-hoc choice. It is also why the *shape* of the result —
  one win, four ties, three losses — has to be reported beside the verdict, since the
  criterion was never a claim about the average strategy.
- **The criterion has never been moved, softened or reinterpreted after seeing results.**
  The clearest test of that came with the paced run, which returned two losses and a tie.
  There was a ready-made argument for changing the primary alert level at that point — the
  original justification for level 3 explicitly cited a limitation that a 6.5-hour paced
  replay no longer had — and it was refused, both because changing a deciding threshold
  after seeing results is the thing the kill point exists to prevent regardless of how good
  the reason sounds, and because the higher levels do not favour this system anyway. All
  three levels are reported so a reader can see the shape rather than take the primary on
  trust.

The §1b entry also names the risk in advance: *if the result lands in the bottom row, the
temptation will be to tune until it looks better, and that is a larger risk to this
project's integrity than any technical risk in it.* And a matching anti-goal forbids
scripting a demonstration narrative before the measurement exists, because scripting first
creates pressure to tune until reality agrees.

---

## 9. Two instruments, and why there have to be two

A measured property of the comparator forced the split, and it was measured before it was
worked around: **Wazuh keys its correlation windows on arrival time, not on the timestamp
in the log line.** Verified on both `wazuh-logtest` and the live `analysisd`, 15
`Invalid user` lines from one IP fire rule 5712 identically at 3-second and 1-hour
spacing.

A corpus replayed at machine speed is therefore *simultaneous* to Wazuh. Its drop under any
timing-based camouflage would be 0pt **by construction**, and since `slow` costs this
system real points, the differential would compute to a large negative number that
describes the harness rather than either system — a stop verdict manufactured by the
instrument.

The pre-registered criterion named both "batch mode" and all seven strategies, and this
measurement shows those two clauses cannot both hold. **Fixing the instrument is not the
same as moving the criterion**, and the distinction is why the thresholds, the strategies
and the deciding quantity all stand exactly as registered. So:

- **Batch replay** measures the five timing-independent strategies (`rephrase`, `mimicry`,
  `noise`, `volume`, `ip_rotate`).
- **Wall-clock-paced replay** measures `slow`, `temporal` and `realistic-combo`
  (`logdet_eval/paced_replay.py`, `logdet_eval/paced_killpoint.py`).

Rows from the two instruments are reported in one merged table so that neither half can be
quoted alone (`logdet-killpoint-summary`), but each row is taken **whole** from one
instrument and never mixed, because the paced corpus is thinned so that it can be replayed
in real time.

### 9.1 How paced replay is made affordable without altering the comparator

Replaying the corpus at true speed costs about 144 hours for a five-seed run, which is not
a measurement anyone will make. It was brought to 5.2 hours by exploiting two properties
**of the shipped rules**, both read off the ruleset rather than assumed:

- Wazuh's sshd frequency rules are **rate limits**, so a real gap only has to be honoured
  up to `timeframe / frequency`; any larger real gap is indistinguishable past that.
- They carry **`same_source_ip`**, so spacing is per source IP and unrelated sources can
  replay concurrently.

Dropping global line order is the largest single saving and is sound only when no frequency
rule can fire without a source key. The three such rules need `Timeout before
authentication`, a CRC-32 attack, or a denied user, and the corpus contains **zero** of all
three — checked by an assertion in the harness (`verify_order_relaxation_safe`) rather than
argued.

The instrument was also **probed before it was built**: 15 `Invalid user` lines from one IP
fire rule 5712 at 0.2-second spacing and do not fire it at 20-second spacing, so pacing
genuinely changes Wazuh's verdict and the instrument can express the thing it exists to
measure.

### 9.2 Marking what an instrument cannot claim

Any run where time is compressed, or where a timing-based level is fired against
arrival-time correlation, is recorded as `measured: false` and rendered as an
**illustration**, with the report pointing at the paced artifact for the real figure. The
live harness defaults to no compression, so the default run is a measurement, and it
**refuses to start** when the Wazuh container is not answering rather than degrading to a
one-contestant table.

---

## 10. The other instruments

### 10.1 The live bake-off

A single writer appends each line to both sinks in the same call — the file this
detector's stream tails, and the file Wazuh's logcollector watches — so neither system can
be handed a different corpus. Every line written is recorded in a manifest with its line
number and its scenario/instance label as it goes onto the wire, so **ground truth is
automatic** and both systems reduce to sets of flagged line numbers scored by the same
function as the kill point.

Attribution differs by system for a reason worth stating: Wazuh echoes the matched raw line
in `full_log`, while this system's incidents carry the parsed event, so ours attribute by
`(second, message)`. Both hand out one line number per alert, because a brute force is the
same line twenty times and collapsing duplicates would score a twenty-line burst as one
detected line.

Un-rigging measures are mandatory here: third-party rules only, camouflage strategies
pre-registered in git before the demonstration, the **examiner** picks the attack and
level from a grid rather than watching a scripted sequence, and conditions where this
system loses are included — a demonstration that never loses reads as rigged even when it
is not. The three-act structure concedes first: quiet baseline, then an obvious attack
where both systems detect it and the SIEM hands the analyst one clean alert while this one
hands over a pile, then the camouflaged attack.

The two-box version launches authentic attacks on the Kali machine and ships them over a
direct Cat6 link into the analyzer's collector endpoint, with a mirror tailing the
collector file and appending each line, in order, to Wazuh's watched file — because the
ingest endpoint lives in the pipeline package and may not import the evaluation track
(§12). Ground truth from each firing is shifted by the collector file's length before it,
so one scorer still serves both systems.

### 10.2 The adaptive adversary

Every camouflage figure from the eight fixed conditions measures robustness against *the
transforms their author thought of*. An optimiser removes that limitation: it searches the
strategy subsets and then hill-climbs on the magnitudes, querying the detector's scores
(`logdet_eval/adaptive.py`).

Four properties are enforced in code rather than promised:

- **The search space is the shipped transforms**, reached through the same binding the
  published recipes use, so a searched plan and a published recipe are the same code.
- **A validity floor**: a plan that thins an instance below 3 lines or 40% of its lines is
  refused *before* it can spend a query. Without it an optimiser "evades" by deleting the
  attack, which is surrender rather than evasion.
- **Searched seeds and reported seeds are disjoint**, and the evaluation function *raises*
  on overlap. Reporting the search's own best score would describe how well the optimiser
  fitted one corpus draw — the clean-data-tuning mistake one level up.
- **The same search is pointed at both systems.** An attacker optimising against Wazuh
  flatters this project, so the conservative arm is the one quoted.

Two limits are printed in the artifact itself. The oracle hands the attacker true detection
rates over *labelled* attack lines after every probe, which no real attacker receives, so
the result is an **upper bound on evasion**, not a field estimate. And because the space is
the shipped transforms, a plateau means *these transforms are exhausted*, never *this
detector is robust*.

Against Wazuh, `slow` and `temporal` are refused by the oracle for the §9 reason — an
optimiser handed that space would converge on the harness artefact within a few queries.
The cost is stated with the result: it removes the half of the space where this detector is
weakest, so the reported differential there is an optimistic reading.

### 10.3 The authentic attack runner

The credibility problem this solves is the twin of the third-party-ruleset problem: the
kill point removes self-written *rules*, and this removes self-written *attacks*.

`attack_runner/` is a standalone, **zero-third-party-dependency** package (HTTP is
`urllib`, not `requests`) because the development environment lives on a portable SSD that
can be in only one machine at a time, so the attack box never has the repository checked
out. It drives real tooling with known parameters, records what it *launched* — never a
list of log lines it claims were produced — and attributes captured lines to instances by
**identity plus time**: a line belongs to an instance when its source IP is one that
instance used and its timestamp falls in the window.

Attribution is deliberately **conservative**: ambient traffic from the same IP inside the
window is swept in, because the log genuinely cannot distinguish it and pretending
otherwise would flatter the score. It vendors the camouflage module as a single file, kept
byte-identical to the original by a drift test, so the real-log and synthetic paths cannot
diverge.

### 10.4 The faithfulness harness

Every narrative is checked against **the exact prompt that produced it**; a claim is
grounded when the thing it names appears in that prompt. Five claim kinds are extracted
deterministically — technique, IP, user, time, quantity — plus a hard regression on a
literal `nan` token.

Two method decisions make its output quotable. **No LLM judge**, deliberately: one would
put an unmeasured model inside the measurement, so the harness checks only what can be
extracted deterministically and states in its own text that entity groundedness is a floor
rather than proof that a story is true. And **the checker's own precision was measured
before its output was quoted** — it was wrong twice, once treating a correct restatement of
a timestamp as an invention, once on a stopword approach to usernames that failed on the
first three real narratives. A `--rescore` mode re-checks saved narratives without calling
the model, so fixing an extraction rule cannot regenerate the narratives underneath the fix
and make before and after incomparable.

The control arm is free and is the deployed system: incidents that match no technique carry
an empty-match prompt, so **any** technique ID in those narratives is invented by
definition. Without that split, a low invention rate could not be told apart from a model
that merely copies what it is handed.

---

## 11. Benchmark discipline

> No change to detection, grouping or scoring lands without re-running the evaluation
> suite and recording the delta. Not "it looks better" — numbers.

Every such change reports, at minimum (`CLAUDE.md` §4):

1. Line-level precision / recall / F1 against the v1 baseline;
2. Instance detection on the clean corpus;
3. **Instance detection under camouflage, pooled over ≥5 seeds**;
4. Alert volume.

**Item 3 is the one people skip and it is not optional.** The lesson behind it was learned
expensively in v1: a contamination retune improved clean precision and quietly cost seven
points of `mimicry` robustness, and without the camouflage arm that change looks like an
unambiguous improvement.

> Any tuning validated only on clean data must be re-validated under camouflage. Clean
> instance detection saturates at 100% and hides exactly the safety margin that camouflage
> eats first.

This rule is what turned the precision work from a series of opinions into a series of
measurements. Four of the five rejected precision levers **look better on clean data than
the option that shipped**, and each was rejected on the camouflage arm — which is the rule
doing precisely the job it was written for.

The discipline has a converse that is used just as often: a change that provably *cannot*
move a detection number does not owe the suite, and the proof is structural rather than
argued. Three forms recur:

- **Additive and off by default** — the mined `template_id` column and the ECS layer add a
  capability in a form that cannot move a number, and the *consumer* is the change that
  owes the benchmark.
- **Byte-identity checks** — the camouflage module was moved between packages and proved a
  no-op by SHA-256 over the camouflaged log and its ground-truth CSV across seeds and
  conditions, and the preprocessing regex was widened and proved a no-op by SHA-256 over
  every parsed record of both corpora.
- **Field-level equality** — enrichment changes are verified by asserting every incident is
  identical on every pre-existing field, with the new field as the only difference.

---

## 12. Structural safeguards

Rules that depend on being remembered are not rules. Each of these is checked by something.

- **The evaluation track may never be imported by the pipeline.** The two packages are
  `src/logdet/` and `src/logdet_eval/`, and an AST-based test in CI fails on a violation
  (`tests/test_layering.py`). Baseline rule implementations therefore cannot leak into
  detection. Measuring yourself with code you also depend on is how benchmarks lie.
- **Pinned regression locks.** The synthetic corpus reads 751 lines → 130 flagged events →
  94 incidents in both the batch and the streamed path, asserted end to end. The test's
  docstring carries the rule: if a number changes, that is a detection change and §4
  applies — a green test bought by editing the expected value is worse than no test.
- **Defaults pinned by tests.** Suppression on/off, the suppression quantile, the loneness
  test, and structured LLM output each have a test asserting the shipped value, so changing
  one is a deliberate edit with a failing test attached.
- **Checkpoint resume guards.** A kill-point run is checkpointed per condition, and resume
  *refuses* a checkpoint whose seeds, seed range, ambient ratio, contamination, thinning
  or suppression setting differ — splicing two experiments into one reported result would
  be worse than losing the compute.
- **Interpretation lives beside the artifact, not inside the generator.** Every results
  directory carries a hand-written `notes.md` appended verbatim by the report generator. A
  generator that wrote conclusions would be scripting the narrative, which is an explicit
  anti-goal.

---

## 13. Environment and reproducibility

Runs are driven by `uv` with a locked dependency set; every measurement command is recorded
in `CLAUDE.md` §9 with its approximate cost. Model artifacts, corpora and parsed data are
regenerable and gitignored; the ATT&CK index is committed so that enrichment is
deterministic and offline, and a version bump arrives as a reviewable diff rather than as
results changing under a `latest` URL.

Three environment facts are load-bearing for anyone re-running this.

**Latency figures are per machine and are never blended.** The same code narrates an
incident in 3.9s on the demo box's GPU and 18.2s on its CPU, and earlier machines gave
different numbers again, so every figure is labelled with the machine that produced it and
the measurement method is fixed (the module's own smoke incident, median of three runs
after a warm-up).

**Alert-volume figures reproduce to about ±0.5% across machines; detection rates are
exact.** A committed artifact stopped reproducing on one condition, and the cause was
traced — by rebuilding all 45 camouflaged corpora byte-identically, re-parsing them under
both the old and the new regex, and re-running the artifact's own commit — to **CPU thread
count**. BLAS and torch reorder their reductions with the thread count, embeddings differ
in the last float bits, and near-tied rows cross the contamination cutoff. Every flipped
line was benign, which is why detection rates did not move at all. **Thread pinning was
declined**: it would make which lines get flagged depend on an environment variable, i.e. a
detection-affecting knob smuggled in as configuration, and no other result in the project
was produced under one (`results/adversarial_notes.md`).

**The comparator needs supervision.** The Wazuh container comes back stopped after a
reboot and `wazuh-analysisd` needs about 20–30 seconds before it answers; the kill-point
harness probes availability once at startup and would otherwise proceed detector-only,
yielding an `INCOMPLETE` run after 40 minutes of compute.

---

## 14. Threats to validity of the method itself

The results chapter lists the limits of the results. These are the limits of the
*measurement*, and they are the ones a reader should press on.

- **No independent red-teaming.** Every attack and every camouflage transform was authored
  or driven by the author. The kill point removes self-written rules and the attack runner
  removes self-written base attacks, but nobody outside the project has tried to evade this
  detector. This cannot be fixed from inside the project and is stated as a limitation
  rather than scheduled as a task.
- **The camouflage library is authored around a synthetic attack shape**, which is why
  authentic captures resist all nine conditions. That is an attack-shape finding, not a
  robustness win, and it is reported as one.
- **The adaptive adversary bounds evasion from above**, since its oracle sees labelled
  ground truth (§10.2).
- **The eval set is small and coarse**: 9 attack instances per corpus, so pooled instance
  detection moves in 2.2-point steps. Differences smaller than that are not meaningful.
- **Injection is not the same as capture.** Even authentic attack lines are *placed* into a
  background at a time this project chose, and the same captures placed at different seeds
  are not independent attacks — the effective independent sample is the number of distinct
  captures, not the number of seeds, and it is reported that way.
- **One comparator, one ruleset, one log domain.** Everything here is sshd-shaped auth
  traffic on one corpus family, compared against one SIEM. A different domain or a
  different ruleset could degrade by a different mechanism entirely — which is exactly the
  argument that forced the kill point in the first place, now pointed at this project's own
  conclusions.
