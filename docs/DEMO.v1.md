# Demo Runbook

Everything needed to run the demo without thinking on your feet. Written for a
laptop with no internet and no GPU, because that is the assumption the whole
project is built on.

---

## Pre-flight (do this the night before, not on the day)

```bash
export PATH="$HOME/.local/bin:$PATH"   # uv is not on PATH in fresh shells

ollama serve &                          # separate terminal
curl -s http://localhost:11434/api/tags # must list phi3
uv sync
```

Then generate the demo state and **leave it in place**:

```bash
uv run python src/preprocessing.py --input data/raw/synthetic.log \
    --output data/processed/parsed.csv --year 2026
uv run python src/pipeline.py --input data/processed/parsed.csv \
    --output data/processed/incidents.json          # 13-15 min, narrates 19 of 94
```

Verify before you close the laptop:

```bash
python3 -c "import json; d=json.load(open('data/processed/incidents.json')); \
print(len(d), 'incidents,', sum(1 for i in d if i.get('narrative')), 'narrated')"
```

Expect `94 incidents, 19 narrated`. **If narrated is 0, the demo has no story
in it** — that is the one failure that actually matters.

`data/processed/` is gitignored, so this state does not survive a fresh clone.
Regenerating it takes ~15 min. Do not leave it to demo morning.

---

## The demo (about 6 minutes)

### 0. Frame it in one sentence (15s)

> "This finds attacks in log files without being told what an attack looks
> like, explains what it found as a story mapped to MITRE ATT&CK, and then I
> try to evade my own detector and report how well it holds up."

### 1. The input (30s)

Show `data/raw/synthetic.log`. Scroll it. The point to make out loud:

> "751 lines, 5 users, 5 days. Nine attacks hidden in here across three
> scenarios. Everything else is ordinary noise — cron, systemd, people
> mistyping their passwords."

### 2. The dashboard (2 min) — the main event

```bash
uv run streamlit run src/dashboard.py
```

It opens ranked, not chronological. The first six rows are all real attacks:

| Row | What it is |
|---|---|
| 🔴 #2 alice, 10 events, `T1110` `T1548` `T1136` | Scenario A: brute force → escalation → backdoor account |
| 🟠 #91 / #1 / #27, 6-8 events, `T1110` `T1087` | Scenario C: account enumeration, one IP, many usernames |
| 🔴 #26 admin, 2 events, `T1021.004` | Scenario B: impossible travel |

**Know this before you open #2:** it contains *two* separate brute-force runs
against alice, 27 minutes apart, from two different IPs — the grouper merged
them because they share a user inside the 30-minute window. That's correct
behaviour and a good thing to point out ("it correlated a repeat attempt on the
same account"), but do not describe it as a single attack. Across the corpus,
the 9 ground-truth instances land in 8 incidents for this reason.

**Open #2 and read the narrative aloud.** This is the deliverable — a
chronological attacker story with technique IDs, generated locally by phi3,
grounded in a fixed lookup table rather than free-associated by the model.

Then say the honest part before anyone asks:

> "94 incidents, 9 real attacks. The detector is tuned for recall, so most of
> what you see is false positives. That is deliberate — the ranking and the
> narrative exist to make them cheap to dismiss. I'll show you the precision
> number in a moment rather than hide it."

Tick **Show all** to prove the false positives are ranked last, not hidden.

### 3. Adversarial robustness (1.5 min) — the novel bit

Open `results/adversarial_results.md`. Do **not** re-run it live (~8 min).

> "I camouflaged the same attacks seven ways and re-ran the identical pipeline.
> Instance detection goes from 100% to 80% under the strongest evasion. Every
> bit of that loss is one scenario — impossible travel — and it turns out
> that's caught by a hand-written rule, not the embeddings. So my measured
> weakness is the one rule in the system, not the model."

Have this ready for the follow-up:

> "Rephrasing the attack breaks the rule completely, 15 hits to 0 — but
> detection stays at 100%, because unusual wording is exactly what an outlier
> detector responds to. The two layers fail on opposite inputs."

### 4. Evaluation (1.5 min) — the uncomfortable one, said first

Open `results/evaluation.md`.

> "I also wrote the conventional SIEM this is supposed to improve on, and it
> beats me on clean data: F1 0.96 against my 0.43. I'm reporting that because
> it's true, and because it's explainable — the corpus has three attack
> templates and I wrote the rules knowing all three. The baseline is close to
> an oracle."

Then turn it over — this is the argument:

> "Take that assumption away and it inverts. Under realistic camouflage the
> baseline's recall goes from 0.94 to 0.07. Mine goes from 0.86 to 0.78.
> Rules win when you already know the attack. That's the whole thesis."

---

## If something breaks

| Symptom | Fix |
|---|---|
| `uv: command not found` | `export PATH="$HOME/.local/bin:$PATH"` |
| Dashboard: "No incidents file found" | Wrong working directory — run from the repo root |
| Narratives all say `[LLM narrative generation failed]` | `ollama serve` isn't running. The rest of the demo still works; say so and move on |
| Ollama dead and unfixable | Skip step 2's narrative; show `results/sample_narratives.md` instead — same content, pre-generated |
| Streamlit port in use | `--server.port 8502` |
| Laptop is slow / nothing loads | Play the backup recording |

**Record the backup video during a successful rehearsal.** If the live demo
fails, a recording of it working is the difference between "it works" and
"it worked on my machine, honest."

---

## Questions you will get, with honest answers

**"Your impossible-travel incident (#26) only shows one login — where's the
travel?"**
Good catch, and answer it straight. Only the *second* leg gets flagged: the
rule fires on the arriving login, and the first leg from the user's usual IP is
ordinary traffic that the detector correctly leaves alone. So the incident
contains the anomalous login plus whatever else was grouped with it — in this
case a benign failed password from a home subnet, which is also why it carries
a `T1110` brute-force tag it doesn't really deserve. The rule's own evidence
(the previous login it compared against) isn't currently carried into the
incident. That's a real gap in the presentation layer, not the detection.

**"Isn't this just anomaly detection with extra steps?"**
The detection is standard Isolation Forest. What isn't standard is grouping
anomalies into incidents, mapping them to ATT&CK via a fixed lookup, and
narrating them — and then measuring how all of that degrades under evasion.
Detection is the input, not the contribution.

**"Why is precision so low?"**
Deliberate. `CONTAMINATION=0.20` favours recall because a missed attack is
unrecoverable and a false positive costs an analyst thirty seconds. The
contamination sweep in `results/evaluation.md` §4 shows 0.10 would cut alert
volume 2.4x at the same instance detection — I didn't adopt it because line
recall drops to 0.40, and Phase 5 showed camouflage removes lines first.

**"Can the LLM hallucinate techniques?"**
It can, which is why it never picks them. Techniques come from a keyword
lookup table; the LLM only writes prose about matches it is handed. One real
incident during development: a `NaN` source IP serialised as the string
`"nan"` and phi3 wrote a sentence around it as if it were a value. Fixed by
never letting missing fields reach the prompt.

**"Why synthetic data?"**
Guaranteed ground truth and a reliable demo. It's also the main limitation,
and it's listed under Threats to Validity: I wrote both the attacks and the
baseline rules, which inflates the baseline's precision.

**"What would you do with more time?"**
Run it on the LogHub/HDFS public corpus, where the rule baseline has no oracle
advantage. And have someone else write the camouflage, since right now the
evasions and the detector share an author.
