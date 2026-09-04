# Retrieval over ATT&CK text — what was built and what was declined

_Interpretation only. The table below is generated
(`results/retrieval/attack_text_cost.py`); this file is written by hand,
following the bake-off precedent — a generator that writes conclusions is
scripting the narrative._

## The item, and the two things it could mean

Stage 5 carried **"retrieval over ATT&CK text"** as an open item, declined once
as unmeasurable without an LLM judge. That phrase turns out to cover two
different changes with opposite risk profiles, and separating them is most of
the work:

* **(A) put ATT&CK's description into the prompt**, so the model explains the
  matched technique in ATT&CK's terms rather than from its own memory;
* **(B) render that description beside the narrative**, quoted from the pinned
  index, with no model involved at all.

**(B) shipped. (A) is declined, and this time with a number attached.**

## Why (A) is declined

**The cost is measured and it is large.** ATT&CK's descriptions for the eleven
techniques this system can emit total 10,670 characters — T1110 alone is 1,580.
Against the structured prompt this system actually sends:

| | |
|---|---|
| Median prompt today | 1,157 chars |
| Median growth if the matched techniques' full ATT&CK text were added | **+1,580 chars (+137%)** |
| Worst case (an incident matching several techniques) | +4,090 chars |

More than doubling the prompt is not free at either tier. Section 2c's latency
figures are prompt-size-sensitive by construction, and the triage tier's entire
argument is that its prompt is the *same* size as the full tier's and only the
generation is short — a change that inflates every prompt attacks the cheap tier
hardest.

**The benefit is still the thing that cannot be measured.** The faithfulness
harness checks *entities* — technique IDs, IPs, users, times, quantities — and
a technique explanation is none of those. Whether a paraphrase of ATT&CK's
description is faithful to it is a claim about prose, and judging it needs a
human or an LLM judge; an LLM judge puts an unmeasured model inside the
measurement. That is the same blocker as before and nothing here removed it.

**And the text is fixed, so there is nothing for a model to add.** ATT&CK's
description of T1110 is the same string every time T1110 matches. A model handed
it can only reproduce it or paraphrase it, and paraphrasing is precisely where
invention got in — the failure this stage spent two sessions closing. Spending
137% of the prompt to introduce a new opportunity to reword a fixed string is
the wrong trade in both directions at once.

## What shipped instead

`logdet-attack` now projects **ATT&CK's first sentence** for each indexed
technique into the committed index, citations and link markup stripped
(`attack.summarise`). It reaches the analyst three ways: in each incident's
`mitre_techniques` entries, over the API, and under the technique list on the
dashboard, quoted verbatim beside the technique's own ATT&CK URL.

| | |
|---|---|
| Index growth | 1,327 chars (11 techniques, ~120 each); the file is 12.4KB |
| Prompt growth | **none** — the prompt block names ID, name and tactic and is untouched |
| Model involvement | none |

One sentence rather than the whole description because this sits beside an
incident, not in a reference manual; the `url` is there for depth, and the
system is expected to work with no network at demo time, which is why the text
is committed rather than fetched.

**This is the grounding design applied to one more field**, not a new idea: the
technique ID comes from the authored keyword table, everything *about* that ID
comes from the pinned bundle, and now that includes what it means.

## What this does not claim

It does not make the enrichment *correct*. The coverage matrix already records
that this project counts technique **matches**, not true positives, and that
measuring enrichment precision needs technique-level ground truth no corpus here
has. A correct sentence attached to a wrong technique ID is still a wrong
answer — better presented, not more right.

## Reproducing

```bash
uv run python results/retrieval/attack_text_cost.py   # needs the 54MB bundle
uv run logdet-attack --refresh                        # rebuild the index
uv run logdet-attack                                  # show what is indexed
```
