# The triage token cap — how to read this sweep

_Interpretation only. Every table below is generated (each arm's
`faithfulness.md` / `faithfulness.json`); this file is written by hand,
following the bake-off precedent — a generator that writes conclusions is
scripting the narrative._

## The question

`results/routing/notes.md` closed with a known cost: **24 of 94 triage lines
(26%) were cut mid-sentence**, because the 80-token cap ends generation rather
than the model ending it. Raising the cap is the obvious fix and it is also the
expense the cheap tier exists to avoid, so it had to be measured rather than
argued.

Five arms, 94 synthetic incidents each, phi3 on the 4060 demo box. Three vary
the token cap; two leave the cap at 80 and instead ask the model for a shorter
sentence, which is the alternative that costs nothing.

## The result

| arm | cut mid-sentence | 94 lines took | median | median chars | fully faithful |
|---|---|---|---|---|---|
| cap 80 (previous default) | 19.1% (18/94) | 83.6s | 0.89s | 226 | 92/94 |
| **cap 120 (adopted)** | **1.1% (1/94)** | **88.1s** | 0.90s | 234 | 91/94 |
| cap 160 | 3.2% (3/94) | 91.9s | 0.90s | 231 | 89/94 |
| cap 80, "under 25 words" | 4.3% (4/94) | 75.1s | 0.73s | 178 | 89/94 |
| cap 80, "under 35 words" | 4.3% (4/94) | 81.2s | 0.82s | 204 | 87/94 |

**The cap is a tail control, not a per-line cost, and that is why raising it is
cheap.** Almost every line finishes well inside 80 tokens; only the long ones
ever reach the limit. So going to 120 buys the tail for **5% of the wall clock**
and leaves the median per-line time untouched at 0.90s. The tier's whole
argument — 0.9s a line against a full narrative's 3.3s — is unaffected.

**160 buys nothing further.** It reads *more* truncation than 120, not less,
which is the size of the noise rather than a real reversal.

## Two things that keep this honest

**The 26% figure was not stable and the new one is not either.** Cap 80 measured
24/94 cut in the previous session and **18/94 here** on identical settings, same
model, same prompt, same temperature. So ~6 lines is run-to-run variance and the
only difference large enough to act on is the **18 → 1** step. The headline is
"the cap was cutting about a fifth of the lines and now cuts about one", not the
decimal.

**Longer generation costs a little accuracy, and the cost is visible.** The two
non-`time` ungrounded claims that appear at the higher caps are entity slips the
short arm did not have room to make: a mistyped source IP (`10.00.1.102` for
`10.0.1.102`) at cap 120 and another (`10.00.1.229`) at cap 160, plus one
invented quantity each. That is why the "fully faithful" column moves *down* as
the cap moves up, 92 → 91 → 89, and it is a real if small trade: fewer cut
sentences, marginally more room to mistype an entity.

## Why the word limit was not adopted

Asking for "under 25 words" truncates about as little (4.3%) and is genuinely
faster (75.1s), so it was a serious candidate. It loses on two counts. It
**shortens the line** 226 → 178 characters, which is 21% less of the one
sentence an analyst gets. And both word-capped arms scored **below** both
token-capped ones on faithfulness (89/94 and 87/94), all of it the timestamp
restatement the checker cannot match — inside the noise individually, but in the
same direction twice.

It also **changes the prompt**, which raising the cap does not. `TRIAGE_MAX_WORDS`
stays in `config.py` at `None` with the numbers beside it, and the plumbing
(`--triage-max-words`) stays so the arm can be re-run.

## What did not change

**No technique ID reached a reader in any arm.** Every distinct ID any arm wrote
was `T1110`, and every one was grounded for the incident that produced it — 30,
33 and 37 lines named one at caps 80/120/160, all stripped. The control arm (41
incidents matching nothing, where any ID is invented by definition) **named none
at all** in every arm. Raising the cap gives the model more room to write a
technique claim and it did not use it to invent one.

## Reproducing

```bash
uv run logdet-faithfulness --triage --output results/routing/cap_sweep/cap080
uv run logdet-faithfulness --triage --triage-num-predict 120 \
     --output results/routing/cap_sweep/cap120
uv run logdet-faithfulness --triage --triage-num-predict 160 \
     --output results/routing/cap_sweep/cap160
uv run logdet-faithfulness --triage --triage-max-words 25 \
     --output results/routing/cap_sweep/cap080_w25
uv run logdet-faithfulness --triage --triage-max-words 35 \
     --output results/routing/cap_sweep/cap080_w35
```

`cap120` is the shipped setting, so that arm is also the current triage
faithfulness artifact. Note the sweep flags override the config for one run;
they do not change the default.
