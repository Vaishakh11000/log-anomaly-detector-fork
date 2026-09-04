# Narration tiers and model routing — how to read these numbers

_Interpretation only. Every table below is generated (`latency.json`, each
arm's `faithfulness.md`); this file is written by hand, following the bake-off
precedent — a generator that writes conclusions is scripting the narrative._

## What was asked, and what the measurement did to the question

The plan was **"small model for triage lines, larger model for full
narratives"**. The first half is measured and holds. The second half does not,
and it fails for a reason worth writing down: **on this GPU the cost is
generation length, not parameter count.**

## 1. The cost is generation length, not parameter count

Demo box (RTX 4060 8GB), CLAUDE.md section 2c's method unchanged:
`llm_narrative.__main__`'s own smoke incident, median of 3 timed runs after a
warm-up, so these compare with every latency figure already in that file.

| model | tier | GPU median | CPU median | rendered text |
|---|---|---|---|---|
| phi3 (3.8B) | triage | **0.95s** | 5.06s | 307 / 275 chars |
| phi3 (3.8B) | full (structured JSON) | 3.29s | 18.00s | 881 / 830 chars |
| llama3 (8B) | triage | **0.93s** | **3.73s** | 191 / 200 chars |
| llama3 (8B) | full (structured JSON) | **3.62s** | **16.81s** | 614 / 647 chars |

The CPU column is the section 2 floor, measured on the same box through a
second Ollama server started with `CUDA_VISIBLE_DEVICES=""` on port 11435. The
phi3 full figure, 18.00s, reproduces the 18.2s already recorded in section 2c
on a different prompt, which is the check that this bench is measuring the same
thing.

**The tier split is worth roughly 3.5x** on either model. The two prompts are
nearly the same size (1,363 against 1,630 characters), so that gap is the
generation cap and nothing else.

**Doubling the parameter count costs about 10% on the GPU and nothing on the
CPU.** llama3 runs the full tier in 3.62s against phi3's 3.29s on the 4060, and
**16.81s against phi3's 18.00s on the CPU** — where a model with twice the
parameters was expected to take roughly twice as long. Per character llama3 is
about 20% slower (38 against 46 characters a second on CPU); it writes about
22% less; the two cancel. So sending the cheap tier to a smaller model buys
almost nothing, and the honest form of "model routing" here is a **token
budget**, not a model swap.

That is why `LLM_TRIAGE_MODEL` and `LLM_NARRATIVE_MODEL` both default to
`LLM_MODEL`. The knobs exist and pointing a tier at another model is a config
edit; nothing measured here justifies making that the default.

## 2. What the cheap tier buys

The budget policy (`NARRATE_*`) leaves **75 of the synthetic corpus's 94
incidents with no prose at all**, because a full narrative costs ~3.9s each on
this GPU and ~18.2s on its CPU. At 0.9s a line, all 94 get a sentence for about
the price of 22 full narratives.

## 3. Faithfulness of the triage tier (phi3, 94 incidents)

`triage_phi3/`. Median 0.89s per line, 231 characters.

| | |
|---|---|
| Fully faithful lines | **91/94** |
| Invented technique IDs | **0** |
| Invented IPs / usernames | 0 of 56 / 0 of 32 |
| Ungrounded claims | 4, all `time` |

The three unfaithful lines are the habit already documented in
`results/faithfulness/notes.md`: phi3 restating a timestamp in a form the
checker cannot match back.

**The enforcement did not have to fire, and claiming otherwise would overstate
it.** 33 of 94 lines named a technique ID, and every one was an ID the incident
had been handed (32 `T1110`, 1 `T1078`). In the control arm — 41 incidents that
matched nothing, where any ID is invented by definition — **0 lines named one at
all.** The strip removed correct IDs, not invented ones. Its worth is the same
as structured output's: a guard that does not depend on the model staying
compliant, not evidence that this model was about to lie.

## 4. The second model, which is what the enforcement claim needed

CLAUDE.md says structured output's worth is that "it does not depend on that
compliance holding for another model". Until now only phi3 had ever been run,
so that was an argument rather than a measurement. Same corpus, same prompts,
same checker:

| arm | model | fully faithful | invented IDs | validation drops | median |
|---|---|---|---|---|---|
| prose (current prompt) | phi3 | 78/94 | **12 of 101** | n/a | 3.4s |
| prose (current prompt) | llama3 | **92/94** | **0 of 67** | n/a | 3.9s |
| structured JSON | phi3 | 88/94 | 0 of 65 | 1 | 2.0s |
| structured JSON | llama3 | **91/94** | 0 of 63 | **0** | 2.8s |

Three readings.

**llama3 is the more faithful narrator, structured or not.** Unguarded prose is
where the difference shows: phi3 invents 12 technique IDs, llama3 invents none.

**The guard is still untested against a non-compliant model.** It fired once in
94 narratives for phi3 and zero times for llama3. Two models, both compliant
under structured output — so the claim that survives is "the enforcement costs
nothing and does not depend on the model", not "the enforcement was needed
here".

**Nothing was made the default on this evidence.** llama3 is better on the
metric that matters and slower everywhere, and the CPU floor (section 2) is the
constraint that decides it — see below.

## 5. The default model: phi3 stays, and the reason is not speed

The CPU floor was measured expecting it to settle this, and it did not — llama3
is *faster* on both tiers at the floor. What is left is memory and
reproducibility, so those are the grounds the default rests on, stated plainly
rather than dressed up as a performance argument:

- **VRAM and disk.** phi3 q4 is 2.2GB on disk and 3.8GB resident; llama3 q4 is
  4.7GB and 5.0GB. Both fit the 4060's 8GB, but section 2c records llama3:8b as
  *unverified* on the 6GB dev box once the KV cache is counted, and the CPU
  floor has to work on machines smaller than either.
- **Every stored artifact is phi3.** `results/faithfulness/` and its arms were
  measured on phi3, and section 2c's latency table is phi3 throughout. Changing
  the default silently would make those numbers describe something the code no
  longer does.
- **The gain is small where it counts.** Under structured output — the shipped
  configuration — phi3 already reads **0 invented technique IDs on both
  corpora**. llama3's advantage is 88/94 to 91/94 on the synthetic corpus and
  187/193 to 188/193 on OpenSSH, and most of the residue is the timestamp
  restatement the checker cannot match.

llama3 *is* the better narrator, most visibly with the guard off, and on a box
with the VRAM it costs nothing in speed. Anyone who wants it changes one line
(`LLM_MODEL`, or just the full tier via `LLM_NARRATIVE_MODEL`) — and then owes
section 2c a re-measure, because the figures there are phi3's.

## 6. Known cost of the 80-token cap

**24 of 94 triage lines (26%) are cut mid-sentence**, because the cap ends
generation rather than the model ending it. A cut line still reads, but it
stops mid-clause and an analyst scanning the list will see it. Raising the cap
raises the cost proportionally, which is the whole point of the tier — so this
is recorded as a measured cost of the setting rather than quietly fixed.

## 7. What this does not measure

The checker is the faithfulness harness's, so it checks **entities, not
stories** — the same limit stated in `results/faithfulness/notes.md`. A triage
line can ground every IP, user and count and still assert something the log
does not support: one of the 94 lines explains an event away as coinciding
"with a scheduled maintenance window", which appears nowhere in its prompt and
is not a claim any of the five extractable kinds can catch.
