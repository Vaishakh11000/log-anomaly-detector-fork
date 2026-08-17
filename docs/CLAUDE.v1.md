# CLAUDE.md — AI Development Context

> **Read this file at the start of every session before writing any code.**
> **Update the Progress Tracker and Decision Log at the end of every session.**
> This file is the single source of truth for project state. If this file and the code disagree, trust the code and fix this file.

---

## 1. What This Project Is

**Name:** LLM-Powered Log Anomaly Detector with Attack Narrative & Adversarial Robustness

**One-line:** Detects anomalies in system logs using semantic embeddings (not static rules), stitches related anomalies into a MITRE ATT&CK-mapped attacker narrative via a local LLM, and measures how much detection degrades when attacks are deliberately camouflaged.

**Context:** Final-year CS major project. Solo developer. 2–3 week timeline. Built primarily via AI-assisted development.

**Why it's novel (protect these two things above all else):**
1. **Attack narrative generation** — grouped anomalies become a chronological story mapped to real MITRE technique IDs, not just isolated alerts
2. **Adversarial robustness evaluation** — the system is stress-tested against camouflaged/evasive log sequences, and the detection gap is honestly reported

If scope must be cut, cut anything EXCEPT those two.

---

## 2. Hard Constraints (do not violate)

- **Hardware:** 16GB DDR4 RAM, **no dedicated GPU**. Everything must run CPU-only.
- **LLM:** local via Ollama, model `phi3` by default. Never introduce a required cloud API dependency — demo day may have no internet.
- **Package manager:** `uv` only. Do not use bare `pip` or `python -m venv`.
- **No heavy dependencies:** no PyTorch training loops, no fine-tuning, no models >8B params.
- **Single log source:** auth/syslog-style only. Multi-source correlation is explicitly out of scope.
- **No real-time streaming.** Batch processing on log files only.

---

## 3. Progress Tracker

> **Agent: update this section at the end of every session.**

**Current phase:** Phase 6 — dashboard + demo rehearsal (the last remaining build work)
**Last session date:** 2026-08-16
**Last commit:** eval(phase7): rule baseline, layer ablation, contamination sweep

### Phase checklist
- [x] **Phase 0** — Environment setup (uv, Ollama, repo init)
- [x] **Phase 1** — Skeleton pipeline runs end-to-end on `sample.log`
- [x] **Phase 2** — Synthetic dataset generated (500–1000 lines, 3 attack scenarios, ground truth labeled)
- [x] **Phase 3** — Detection tuned + impossible-travel signal + severity tiers
- [x] **Phase 4** — MITRE mapping expanded + LLM narrative working
      (94 incidents, 19 narrated in 13-15 min, 0 failures; 3 sample narratives in
      `results/sample_narratives.md` = evaluation target #2)
- [x] **Phase 5** — ⭐ Adversarial robustness evaluation complete (PROTECT THIS)
      (7 strategies + realistic combo, pooled over 5 seeds → `results/adversarial_results.md`.
      Headline: instance detection 100% → 80% under `slow`; all loss confined to scenario B,
      which is carried by the impossible-travel rule rather than the embeddings)
- [ ] **Phase 6** — Dashboard + demo rehearsed + backup recording
- [x] **Phase 7** — Rule-based baseline + evaluation numbers → `results/evaluation.md`
      (evaluation target #1 done; **the written report itself is still to be drafted** —
      that's a writing task, all three required comparisons now have numbers behind them)

### Known issues / TODO carried over
_(agent: log anything broken or deferred here so the next session picks it up)_
- ~~`sequence_grouping.py` groups strictly by exact `user` match~~ **RESOLVED in Phase 4** — grouping is
  now two-axis (user OR source IP, union-find). All 9 ground-truth attack instances land in exactly one
  incident each — **no instance is fragmented**. Note the precise claim: that is 9 instances across
  **8** distinct incidents, because scenario A instances 1 and 3 both target `alice` 27 min apart and
  correctly merge into incident #2. Don't say "9 instances → 9 incidents" in the report or the viva.
- ~~LLM narrative does not scale to a full pipeline run~~ **MITIGATED in Phase 4** — the `NARRATE_*`
  budget policy plus the `num_predict` cap bring a full run to a measured **13-15 min** (19 of 94
  incidents narrated, 0 failures), still covering all 9 attack instances. Still slow in absolute
  terms: ~40-60s/incident on CPU is the floor for phi3. If the demo needs to be faster, the lever is
  narrating fewer incidents, not a bigger model.
- **Phase 5 finding that Phase 7 must address:** scenario B (impossible travel) is detected
  *entirely* by the hand-written rule — the embeddings contribute nothing, because the two login
  legs are identical vectors after IP masking. So B's robustness is the rule's robustness, and both
  effective evasions (`slow`, `ip_rotate`) beat the rule rather than the model. Widening
  `IMPOSSIBLE_TRAVEL_WINDOW_MINUTES` or comparing more octets would each shift the trade-off; neither
  is calibrated. Do not claim "embedding-based detection catches impossible travel" in the report.
- ~~The 75 un-narrated incidents are almost all singleton false positives~~ **QUANTIFIED in Phase 7**
  — precision is 0.29 vs the baseline's 0.99, and the system produces ~3.2x the flagged lines and
  ~13x the incidents (103 vs 8). This is the project's weakest number. `results/evaluation.md` §4
  shows `CONTAMINATION=0.10` would cut alert volume 2.4x at the same 100% instance detection.
  **Tested under camouflage and rejected** — see `results/contamination_retune.md`: instance
  detection falls under `mimicry` (100%→93%) and `realistic-combo` (91%→87%). The alert-volume
  problem therefore stands and contamination is *not* the lever. Untried candidates that reduce
  what an analyst sees without reducing what the detector catches: suppress singleton incidents
  with no MITRE match, or recalibrate `SEVERITY_THRESHOLDS`.
- Phase 7 open question: the rule baseline's near-perfect clean-corpus precision is partly an
  artifact of the synthetic corpus being built from the same three attack templates the rules
  encode. The honest fix is the LogHub/HDFS public dataset (section 9 stretch goal), where the
  rules have no oracle advantage. Only attempt if there is genuine time left after Phase 6.
- `uv` lives at `~/.local/bin/uv` and is not on the default `PATH` in non-interactive shells; if
  `uv: command not found`, prefix with `export PATH="$HOME/.local/bin:$PATH"`.
- `preprocessing.py` has no no-arg smoke test — its `__main__` is a required-args CLI, so
  `uv run python src/preprocessing.py` exits 2 instead of self-testing. Every other module follows the
  section 5 convention. Minor; fix when next touching that file.
- ~~The dashboard has only been verified by exercising its data-access paths headlessly~~ **RESOLVED
  in Phase 6** — verified with `streamlit.testing.v1.AppTest`, which actually executes the script
  (an HTTP 200 from the server only proves the JS shell loads). 0 exceptions, 94 incidents render.
  It is now triage-ranked so the first six rows are real attacks; see `DEMO.md`.
- Presentation gap found while checking demo narratives: an impossible-travel incident contains only
  the *arriving* login. The rule compares it against the user's previous login, but that previous
  line is benign, so it is never flagged and never grouped — the incident shows the conclusion
  without the comparison that produced it. Scenario B incident #26 therefore reads as a single login
  plus an unrelated benign failure (which is also where its undeserved `T1110` tag comes from).
  Carrying the compared-against line into the incident as context would fix it. Detection is
  unaffected; this is display only. Documented in `DEMO.md` Q&A in case it comes up in the viva.
- Phase 6 remaining: **rehearse the demo end-to-end and record the backup video.** The narrated
  `incidents.json` must be regenerated first (~15 min, needs `ollama serve`) — `data/processed/` is
  gitignored so it does not survive a clone, and a demo with `narrated: 0` has no story in it.
- Tuned `CONTAMINATION=0.20` trades precision for recall (P=0.30/R=0.87 on the synthetic set) and
  severity tiers don't cleanly separate precision by tier at that setting (medium is actually noisier
  than low here) -- both are informal calls made against a 45-line ground truth set, not calibrated
  numbers. Phase 7's formal evaluation should treat these as a starting point, not a verified result.

---

## 4. Architecture

```
data/raw/*.log
    ↓  src/preprocessing.py      parse syslog lines, mask IP/port/PID → template
data/processed/parsed.csv
    ↓  src/embedding.py          all-MiniLM-L6-v2 → 384-dim vectors
    ↓  src/anomaly_detection.py  per-user Isolation Forest + impossible-travel rule
    ↓  src/sequence_grouping.py  cluster anomalies: same user OR same source IP, 30-min window
    ↓  src/mitre_mapping.py      keyword lookup → ATT&CK technique IDs
    ↓  src/llm_narrative.py      Ollama prompt, GROUNDED in mitre matches
data/processed/incidents.json
    ↓  src/dashboard.py          Streamlit UI

src/adversarial.py               separate eval track: camouflages the generated attack events,
                                 re-runs the same detect chain, measures the gap -> results/
src/baseline_rules.py            eval track: the conventional SIEM this project is measured
                                 against. NEVER import from pipeline.py (Anti-Goal)
src/evaluate.py                  eval track: baseline vs embeddings P/R/F1, layer ablation,
                                 camouflage generalisation, contamination sweep -> results/
src/export_samples.py            eval artifact: one sample narrative per scenario -> results/
src/pipeline.py                  orchestrates the main chain above
```

### File responsibilities
| File | Owns | Do not put here |
|---|---|---|
| `preprocessing.py` | regex parsing, field extraction, templating | any ML logic |
| `embedding.py` | sentence-transformer calls, model caching | anomaly scoring |
| `anomaly_detection.py` | Isolation Forest, per-user baselines, severity tiers, impossible-travel check | grouping logic |
| `sequence_grouping.py` | time-window incident clustering (user + source-IP axes) | LLM calls |
| `mitre_mapping.py` | the lookup table, keyword matcher, incident-level signals | prompts |
| `llm_narrative.py` | Ollama API calls, prompt templates | detection logic |
| `adversarial.py` | camouflage generators, robustness metrics | production pipeline code |
| `baseline_rules.py` | threshold/keyword SIEM rules, used only as the evaluation baseline | anything the pipeline imports |
| `evaluate.py` | P/R/F1, ablation, contamination sweep, report rendering | detection logic (it calls the real chain) |
| `pipeline.py` | orchestration only — thin, no business logic | new algorithms |
| `generate_logs.py` | synthetic log + attack scenario generation | detection code |

---

## 5. Coding Conventions

- Python 3.11+. Type hints on function signatures.
- Every module must be runnable standalone via `if __name__ == "__main__":` with a smoke test. This is how we verify things without a test suite.
- Docstring at top of every module explaining its role in the pipeline.
- No new dependencies without adding to `pyproject.toml` and noting it in the Decision Log below.
- Keep functions small enough to paste into a chat for debugging.
- Config values (model name, window size, contamination) go in `src/config.py`, not scattered as magic numbers.
- Prefer readable over clever. This code gets explained in a viva.

---

## 6. Session Protocol (for the AI agent)

**At session start:**
1. Read this entire file
2. Run `git log --oneline -5` to see recent work
3. Check the Progress Tracker → identify current phase
4. Confirm with the user what this session's goal is before writing code

**During the session:**
- Work on ONE phase at a time. Do not jump ahead.
- After each working feature, run its smoke test before moving on
- If something breaks that isn't part of this session's goal, log it in "Known issues" — don't rabbit-hole

**At session end:**
1. Run the relevant smoke tests
2. Commit (see Git workflow below)
3. **Update the Progress Tracker** (current phase, last commit, known issues)
4. **Append to the Decision Log** if any technical decision was made
5. Tell the user in one line what the next session should tackle

---

## 7. Environment & Commands (uv)

### First-time setup
```bash
# install uv (once, globally)
# Windows PowerShell:
powershell -c "irm https://astral.sh/uv/install.ps1 | iex"
# Linux/Mac:
curl -LsSf https://astral.sh/uv/install.sh | sh

# in the project directory:
uv sync              # creates .venv and installs everything from pyproject.toml
```

### Daily use
```bash
uv run python src/preprocessing.py --input data/raw/synthetic.log --output data/processed/parsed.csv --year 2026
uv run python src/pipeline.py --input data/processed/parsed.csv --no-llm
uv run python src/pipeline.py --input data/processed/parsed.csv --output data/processed/incidents.json
uv run python src/pipeline.py --input data/processed/parsed.csv --narrate-all   # slow: every incident
uv run python src/export_samples.py
uv run python src/adversarial.py                # Phase 5 robustness eval, pools over 5 seeds (~8 min)
uv run python src/adversarial.py --seeds 1      # quick single-seed pass while iterating
uv run python src/evaluate.py                   # Phase 7 evaluation, pools over 5 seeds (~5 min)
uv run python src/evaluate.py --seeds 1         # quick single-seed pass
uv run python src/evaluate.py --render-only     # re-render the report prose from the last run's counts
uv run streamlit run src/dashboard.py
```

`uv run` handles the virtualenv automatically — no manual activation needed.

### Adding a dependency
```bash
uv add scikit-learn        # NOT pip install
```

### Ollama (separate terminal, must be running for narrative steps)
```bash
ollama serve
ollama pull phi3
```

---

## 8. Git / GitHub Workflow

### One-time repo setup
```bash
git init
git add .
git commit -m "chore: initial project skeleton"
gh repo create log-anomaly-detector --private --source=. --push
# or manually: create repo on github.com, then:
# git remote add origin <url>
# git branch -M main
# git push -u origin main
```

### Commit at every phase checkpoint (minimum)
Use conventional commit prefixes so the history reads well in your report:
```bash
git add .
git commit -m "feat(phase2): synthetic log generator with 3 attack scenarios"
git push
```

Prefixes: `feat:` new feature · `fix:` bug fix · `chore:` setup/config · `docs:` documentation · `eval:` evaluation/results · `refactor:` restructuring

### Mandatory commit points
- End of every phase (7 total, minimum)
- Before any large refactor
- After any working demo state — so you can always roll back to something that runs

### What NOT to commit
Covered by `.gitignore`: `.venv/`, `__pycache__/`, `data/processed/*` (generated), model caches, `*.pyc`.
**Do commit:** `data/raw/*.log` (your synthetic datasets are project artifacts and should be versioned), ground truth CSVs, and saved sample narratives.

---

## 9. Dataset Strategy

**Start here (Phase 2):** synthetic logs you generate yourself. Full control, guaranteed ground truth, demos reliably.

**Progress to (optional, Phase 7 stretch):** HDFS public dataset from the LogHub collection. Adds academic credibility and comparability with published work. Only attempt after Phase 5 is complete and committed.

**Decision rule:** if it's Day 14 and Phase 5 isn't done, drop the public dataset entirely. Synthetic + adversarial results are sufficient evidence for this project.

### Synthetic dataset spec (Phase 2 target)
- ~500–1000 total lines, ~5 users, spanning a few simulated days
- Majority benign: routine logins/logouts at plausible hours, cron jobs, systemd messages, occasional isolated failed password (typos are normal — the baseline needs to learn this)
- **Scenario A:** rapid failed passwords → success → `sudo su root` → new user added to sudo group
- **Scenario B:** normal login from usual IP → 15 min later, success from a completely different IP range (impossible travel)
- **Scenario C:** failed logins across many *different* usernames from one IP (enumeration/recon)
- **Ground truth:** `data/raw/ground_truth.csv` mapping line numbers → scenario label. Non-negotiable — precision/recall depends on it.

---

## 10. Decision Log

> **Agent: append here whenever a technical decision is made. Never delete entries.**

| Date | Decision | Rationale |
|---|---|---|
| 2026-08-16 | **Retune to `CONTAMINATION=0.10` tested and rejected** on evidence (`results/contamination_retune.md`) | Ran `adversarial.py --contamination 0.10 --seeds 5`. Instance detection is identical to 0.20 on 7 of 9 camouflage conditions, but degrades on the two that matter most: `mimicry` 100% → 93% and `realistic-combo` 91% → 87%. Mimicry is the only strategy that attacks the *model* rather than a threshold, and at 0.20 it had never hidden a whole instance — at 0.10 it hides 3 of 45. This confirms the predicted mechanism: 0.10 halves line recall (0.86 → 0.40), and camouflage works by subtracting evidence, so thin evidence is what it eats first. The 2.4x alert-volume saving was real but it was the safety margin. **General lesson: any tuning validated only on clean data must be re-validated under camouflage — clean instance detection saturates at 100% and hides exactly this** |
| 2026-08-16 | The rule baseline is compared **with the impossible-travel rule added to it** (`rules_travel`, `FAIR_BASELINE` in `evaluate.py`), not without | The pipeline's own travel rule is the only thing that detects scenario B. Comparing against a baseline that lacks it would have handed this system a free 100%-vs-67% win on instance detection that comes from a rule both systems have. Every real SIEM has a subnet-velocity rule; withholding it would be a strawman |
| 2026-08-16 | Report the Phase 7 headline as it came out: **the rule baseline beats the embedding system on the clean corpus on every metric** (P 0.99 vs 0.29, R 0.94 vs 0.86, F1 0.96 vs 0.43; instance detection ties at 100%) | The result is real and burying it would be dishonest. It is also explainable rather than damning: the corpus is built from three attack templates and the baseline's thresholds/keywords were written knowing them, so the baseline is near-oracle by construction. The defensible claim is not "embeddings win" but "rules win when you already know the attack" — which section 3 of the report then removes, and where the baseline collapses (recall 0.94 → 0.07 under realistic-combo) while the system holds (0.86 → 0.78) |
| 2026-08-16 | `run_anomaly_detection()` now keeps `ml_anomaly` (the embedding verdict before the rule is OR-ed in) and takes `contamination` as a parameter | Evaluation must be able to attribute a detection to the model or the rule, and sweep contamination, without re-implementing how the signals combine — that combination logic is `anomaly_detection.py`'s job per the file-responsibility table. No behaviour change: verified the pipeline still produces 130 anomalies / 94 incidents |
| 2026-08-16 | Kept `CONTAMINATION=0.20` even though the sweep shows 0.10 reaches the same 100% instance detection with 2.4x fewer flagged lines (297 vs 699) | Tempting but not yet safe: line recall falls 0.86 → 0.40 at 0.10, so instances survive on much thinner evidence. Phase 5 showed camouflage works precisely by removing lines, and an instance carried by one line is an instance about to be missed. Adopting 0.10 requires re-running the Phase 5 evaluation at that setting first — the clean-data margin is exactly what adversarial conditions consume |
| 2026-08-16 | Phase 5 camouflage is applied to the **event list** from `generate_logs.build_dataset()`, not to the finished log file, and both corpora then run the identical preprocess→embed→detect chain | Camouflage shifts timestamps and injects lines, so ground-truth *line numbers* stop being stable. Camouflaging events keeps each attack line bound to its scenario/instance label through the transformation. Running the real chain (rather than scoring embeddings directly, as the old `evaluate_robustness()` stub did) means the numbers describe the system that actually ships, including the impossible-travel rule and severity tiers |
| 2026-08-16 | Robustness results are pooled over **5 seeds**, with rates recomputed from summed counts rather than averaged | With 3 instances per scenario a single seed moves instance-detection in 33% steps. Observed directly: `ip_rotate` reads 100% instance detection at seed 42 alone but 84% pooled over 5 — a single-seed number would have reported no effect where a real 16% drop exists |
| 2026-08-16 | Kept both `rephrase` (novel wording) and `mimicry` (benign wording) as separate strategies, and report that rephrasing *increases* detection by 14% | The first implementation only had `rephrase`, which made every condition look *more* detectable — a nonsense result that came from the camouflage, not the detector: rare templates are exactly what an outlier detector flags. Reporting only the strategy that flatters the system would be dishonest; reporting only the one that beats it would be too. The pair is the actual finding — wording attacks help or hurt depending on which direction they move a line relative to the learned distribution |
| 2026-08-16 | Two temporal spreads (`temporal` 8-20 min, `slow` 35-90 min) straddling `INCIDENT_WINDOW_MINUTES=30` and `IMPOSSIBLE_TRAVEL_WINDOW_MINUTES=60` | The original 8-20 min spread produced a 0% change and looked like "the system is robust to timing attacks". It wasn't robust — the gaps simply never left the 30-min grouping window. The narrow spread is now retained explicitly as the control that proves the window, not the timing, is what matters |
| 2026-08-16 | Incident grouping is now two-axis — anomalies join if within the 30-min window AND share **either** the same user **or** the same source IP, linked transitively via union-find (`GROUP_BY_SOURCE_IP`) | Fixes the Phase 3 carried-over issue. Enumeration deliberately varies the username on every line, so user-only grouping scattered it into singletons. Measured on the synthetic set: 111 → 94 incidents, and **all 9 ground-truth attack instances now land in exactly one incident each** (previously Scenario C split into ~6 singletons per instance). Source IPs are distinct enough here (196 unique across 751 lines) that the IP axis doesn't snowball — largest incident is 10 events |
| 2026-08-16 | Parser placeholders (`unknown`, `none`, `-`, …) are never treated as joinable identities (`NON_IDENTITY_VALUES`) | 22 of 130 anomalies are user-less systemd noise. Joining them on `user == "unknown"` merged unrelated lines into a fabricated "incident" — `unknown` is the parser reporting absence, not an identity |
| 2026-08-16 | Removed `"ssh"` from the T1021 keyword list and `"cron"` from T1053; added T1136, T1070 and more specific phrasings | `"ssh"` substring-matched the `ssh2` suffix on *every* sshd line, so every ordinary failed password was tagged Lateral Movement — the grounding table was feeding the LLM a false premise, and narratives duly claimed lateral movement that never happened. `"cron"` matched every benign hourly CRON line as Persistence |
| 2026-08-16 | MITRE mapping gained an incident-level layer (`map_incident_to_mitre`) driven by structural signals — impossible-travel flag → T1021.004, ≥3 distinct usernames from one source IP → T1087 | Some techniques are invisible per-line: no single "Failed password for guest" line is enumeration; it's enumeration only in aggregate. Keeps grounding retrieval-based (still a fixed table, no LLM free-association) while covering patterns keywords structurally cannot express |
| 2026-08-16 | Missing fields are omitted from the prompt and serialised as `""`, never as the string `"nan"` (`_field()` in `llm_narrative.py`; `.where(notna(), "")` before `astype(str)` in `pipeline.py`) | `sudo`/`usermod` lines legitimately have no `source_ip`, and `astype(str)` on `NaN` yields the literal `"nan"`. phi3 treated it as a real value and fabricated detail around it — a saved Scenario A narrative read *"elevating privileges ... by switching to root user with 'nan'"*. A formatting slip became a hallucinated fact in a report artifact, which is exactly the failure mode the grounded-lookup design exists to prevent |
| 2026-08-16 | Ollama calls now pass `num_predict=400` and `temperature=0.2` | 2 of 19 incidents hit the 180s timeout on the first full run — and both were *single-event* incidents, the sparsest prompts, while a 10-event one finished fine. phi3 given little to anchor on keeps generating until the timeout kills it. Capping output tokens fixed both (58s/60s), which is the right lever: raising the timeout would have hidden an unbounded generation instead of bounding it. Low temperature makes demo/report narratives reproducible |
| 2026-08-16 | LLM narratives are generated only for incidents that are high-severity **or** have ≥2 events (`NARRATE_SEVERITIES`/`NARRATE_MIN_EVENTS`), with `--narrate-all` as an escape hatch | phi3 costs ~60s/incident on this CPU; narrating all 94 would take ~1.5h, unusable for a demo or an iteration loop. The policy narrates 19 of 94 — a measured 13m24s and 15m20s across two runs — and still covers **all 9** ground-truth attack instances — the skipped 75 are singleton false positives from the recall-favouring `CONTAMINATION=0.20` |
| 2026-08-16 | Tuned `CONTAMINATION` from 0.05 to 0.20 against the synthetic ground truth (line-level sweep: 0.05→P=0.62/R=0.36/F1=0.45, 0.10→P=0.31/R=0.42/F1=0.36, 0.15→P=0.33/R=0.67/F1=0.44, 0.20→P=0.30/R=0.87/F1=0.45) | This is an analyst-triage tool, not an auto-blocker (per Anti-Goals: no SOAR/auto-response) — severity tiers and the LLM narrative exist specifically to help a human sort through false positives, so recall matters more than precision here. 0.20 was the point where Scenario A's brute-force burst started actually getting caught (6/18 → 15/18 lines) without a further F1 gain past it |
| 2026-08-16 | Impossible-travel is a rule bolted onto the ML score (`is_anomaly \|= impossible_travel`, severity forced to "high"), not a feature fed into Isolation Forest | `template_message()` masks IPs before embedding, so the two legs of a Scenario B login are literally identical vectors — semantically indistinguishable by design. The physics check has to run on the raw (pre-mask) `source_ip`/`timestamp` columns preprocessing.py already extracts, entirely outside the embedding path |
| 2026-08-16 | Synthetic dataset: 5 users, 5 simulated days, ~750 total lines, 3 instances each of Scenario A/B/C (9 attack incidents, 45 labeled lines) | Spec (section 9) didn't pin down instance count; a single instance of each scenario would leave almost nothing to compute precision/recall over in Phase 7. 3x gives a small but real eval set without bloating the "final-year, 2-3 week" scope |
| 2026-08-16 | `sudo`/`usermod` synthetic lines use a simplified `user=<name>` field instead of real sudo's multi-field `TTY=...; USER=root; COMMAND=...` format | Real format's `USER=root` (target user) would be misparsed as the *actor* by the existing `extract_user()` regex, attributing the privilege-escalation step to "root" instead of the compromised user and splitting Scenario A across two users during incident grouping |
| 2026-08-16 | Fixed `extract_user()`'s fallback regex in `preprocessing.py` from `for (\w+) from` to `for ([\w\-]+) from` | Found via ground-truth validation: usernames with hyphens (e.g. `www-data`, used as an enumeration probe target) silently fell back to "unknown". `USER_PATTERN` in the same file already allows hyphens — this just makes the fallback consistent with it |
| 2026-08-16 | Attack scenario source IPs use RFC 5737 documentation ranges (`203.0.113.0/24`, `198.51.100.0/24`, `192.0.2.0/24`) rather than made-up real-looking IPs | Never routable/real, so the synthetic log can't be mistaken for or accidentally reference a real host, while still reading as plausible external attacker infrastructure in the report |
| 2026-08-16 | Fixed `llm_narrative.py` to import `OLLAMA_URL`/`LLM_MODEL`/`LLM_TIMEOUT_SECONDS` from `config.py` instead of hardcoding `llama3` | Module had stale local constants pointing at `llama3`, which isn't pulled on this machine (only `phi3` is) — every narrative call was silently failing with a 404 and falling back to an error string in `incidents.json`. `config.py` already had the correct `phi3` default; the module just wasn't using it |
| 2026-08-16 | Pinned `torch` to the CPU-only wheel index (`download.pytorch.org/whl/cpu`) via `[tool.uv.sources]`, and added `torch` as an explicit direct dependency so the override applies | Default PyPI resolution pulled full CUDA build (~2GB of nvidia-* packages), violating the CPU-only hardware constraint. uv only applies source overrides to packages declared in `[project.dependencies]`, so torch had to be listed explicitly even though it's only used transitively via sentence-transformers |
| — | Dev environment: single local laptop, Ollama running locally | Solo developer, one machine — no remote box to coordinate, and matches the "demo day may have no internet" constraint by default. (Supersedes an earlier shared-VM setup, now dropped) |
| — | Use `uv` over pip/venv | Faster, single lockfile, less env drift across sessions |
| — | `phi3` over `llama3:8b` as default | CPU-only 16GB machine; phi3 is fast enough for per-incident narratives; llama3 available as final-demo upgrade |
| — | Synthetic data first, HDFS as stretch goal | Controlled ground truth, faster to iterate, guaranteed demo reliability |
| — | MITRE mapping via keyword lookup table, not LLM free-association | Prevents hallucinated technique IDs; defensible design choice in the report |
| — | Hybrid: embeddings + lightweight physics rules (impossible travel) | Embeddings can't catch "successful login that is geographically impossible" — that's a physics check, not a semantic one |
| — | Per-user baselines, not global | Avoids naive "any foreign IP = malicious" false positives |

---

## 11. Anti-Goals — Things The Agent Should Push Back On

If the user (or the agent's own instinct) suggests any of these, flag the scope risk before proceeding:

- ❌ Fine-tuning an LLM — no GPU, no time
- ❌ Real-time log streaming / Kafka / production ingestion
- ❌ Multi-log-source correlation (firewall + app + auth)
- ❌ Auto-response / blocking actions (SOAR) — narrative and recommendation only
- ❌ Building a full MITRE ATT&CK ontology — the small lookup table is deliberate
- ❌ Adding many hand-written detection rules — that recreates the SIEM this project differentiates from. Rules are limited to physics-based impossibility checks only.
- ❌ Chasing a 0% adversarial robustness gap — an honest measured gap with analysis scores better than a suspiciously perfect number
- ❌ Polishing the dashboard before Phase 5 is done

---

## 12. Evaluation Targets (what the report needs)

Three comparisons, all required:

| # | Comparison | Metric | Phase |
|---|---|---|---|
| 1 | Rule-based baseline vs. embedding detector | precision / recall / F1 | 7 ✅ `results/evaluation.md` |
| 2 | Detection-only vs. detection + narrative | qualitative — 3 saved sample narratives | 4 ✅ `results/sample_narratives.md` |
| 3 | Raw attacks vs. camouflaged attacks | detection rate %, per scenario | 5 ✅ `results/adversarial_results.md` |

For #3, a 25–40% gap is a realistic and *good* result. Report it honestly with analysis of which camouflage strategy worked best and why.

---

## 13. Quick Health Check

Run this when picking up the project after a break:
```bash
git log --oneline -5
uv run python src/preprocessing.py --input data/raw/sample.log --output data/processed/parsed.csv --year 2026
uv run python src/pipeline.py --input data/processed/parsed.csv --no-llm
curl http://localhost:11434/api/tags     # is Ollama alive?
```
If all four succeed, the project is in a working state and you can build forward.
