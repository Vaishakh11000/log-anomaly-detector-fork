# Stage 4's two remaining structural items, and why neither was built

Stage 4 shipped the entity graph, moved grouping onto it, and used it to close
the impossible-travel evidence gap. Two items were left open in the tracker:
**temporal decay on graph edges** and **multi-source correlation**. Both were
examined before building, and neither survives. This note records why, so the
next session does not re-derive it.

Both fail §1's test — a feature should either improve detection/explanation or
make the adversarial measurement more credible.

---

## 1. Temporal decay on edges is a reparametrisation of the window, not a feature

The graph's edges are *consecutive events on one entity, when the gap between
them is inside the window*. Grouping consumes those edges through
`components()`, which needs a hard partition: an edge either exists or it does
not.

So a decayed edge weight has to be thresholded before grouping can use it. For
any monotone decreasing decay `w(gap)` and any threshold `t`:

```
edge exists  iff  w(gap) >= t  iff  gap <= w⁻¹(t)
```

which is a plain window of size `w⁻¹(t)`. The partition is identical to the one
`INCIDENT_WINDOW_MINUTES` already produces. Decay changes the *name* of the
knob and nothing else, while costing the full §4 suite to land, because
incident count is one of the four numbers §4 asks for.

Decay only becomes a real feature if something consumes a **continuous** weight
rather than a thresholded one. There is one candidate consumer in the codebase
— suppression's loneness guard — and it is already closed:

> Both graph loneness variants (`quiet` and `share@r`) were measured on the
> full §4 suite on 2026-09-04 and rejected. `quiet` is *strictly dominated*: it
> removes the same attack lines as the shipped test while suppressing fewer
> benign ones.

The reason `quiet` failed is the reason decay cannot rescue it. The attack lines
suppression costs — 8 on `slow`, 6 on `realistic-combo` — are **genuinely
isolated**: on the timing-spread conditions there is no benign traffic around
the alert either, recent or old. A guard that weights neighbours by recency has
the same nothing to weigh. See `results/suppression/loneness/notes.md`.

**Verdict: not built.** If it is ever revisited, the honest framing is *entity
heat* — an accumulated decayed activity score per entity, feeding triage
ranking — which is a different feature from edge decay and would need its own
justification, since triage ranking is already improved by the sequence
surprisal tiebreaker and no number in `results/` measures what heat would fix.

---

## 2. Multi-source correlation has almost nothing to correlate

The plumbing is easy; the question is whether the graph would find anything.
`data/external/Linux.log` (LogHub) is the only real corpus available here with
genuine multi-service auth traffic on one host (`combo`): 9,666 auth-service
events, parsed by this project's own `LineParser` (99.37% overall parse rate
since 2026-08-30).

| service | events |
|---|---|
| sshd | 5,009 |
| ftpd | 3,453 |
| su | 944 |
| telnetd | 179 |
| klogind | 50 |
| login | 31 |

A cross-service link is exactly the condition `EntityGraph.edges` tests: two
events from **different** services sharing a user or a source IP, inside the
30-minute incident window.

Measured (`cross_source_overlap.py`):

| join key | cross-service links in the window | on what |
|---|---|---|
| `source_ip` | **2** | one IP, `81.181.213.88`, ftpd ↔ klogind |
| `user` | 70 | **all 70 on `root`** |

Over the whole corpus, ignoring the window entirely, the picture is the same:
**1 source IP of 331** appears in more than one auth service, and **2 users of
14** (`root` and `test`). `ftpd` and `telnetd` carry no username the parser can
lift at all, so two of the three busiest services cannot be joined on user in
the first place.

**The user column is worse than it looks, not better.** Every one of the 70
links is `root` — the superuser account every service names, not a shared
identity. Joining services on `root` is the failure the entity graph module
already refuses for host and process: *an entity that every event shares
carries no information about which events belong together*. `root` is a
legitimate join key **within** one service (a root brute force is a real
attack, and `NON_IDENTITY_VALUES` correctly does not exclude it), which is why
this is a finding about cross-source joining specifically rather than a bug to
fix in `normalise_identity`.

So the graph fed a second source would find **one** genuine cross-service link
in 9,666 events. Any measurable cross-source correlation would have to come
from an attack we authored and planted across two logs — and a correlation the
author planted, found by the author's grouper, measured against the author's
ground truth, is the trap §1b and §8 exist to keep out of this project's
claims.

**Verdict: not built.** The structure to support it already exists — the graph
takes entity kinds, and `ENTITY_COLUMNS` already carries `host` and `process`
as nodes. What is missing is a corpus, not code. The natural place for it is
**Stage 6**, where §2d's Kali runner generates real attacks with ground truth
captured at generation time and can legitimately produce cross-source traffic
(an ssh brute force followed by a real `sudo`), and **Stage 7**, where ECS
normalisation gives more than one source a common schema.

---

## Reproducing

```bash
uv run python results/correlation/cross_source_overlap.py
```

No embeddings, no models, ~10s. Nothing in this note touched detection,
grouping or scoring, so §4 did not apply.
