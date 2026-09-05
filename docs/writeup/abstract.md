# Abstract

*Draft. Every figure below is cited to an artifact in `results/` or `docs/results.v1/`.
Source of record: `docs/FINDINGS.md`.*

---

## Abstract

Open-source SIEMs and most of the published log-anomaly literature report how well a
detector performs, but not how much worse it gets when the attacker actively tries to
hide. This project builds a local-first log anomaly detector — sentence embeddings with a
per-user Isolation Forest, grouped into incidents, enriched from a pinned MITRE ATT&CK
index and narrated by a small local LLM — and subjects it to that missing measurement on
every change, against a third-party ruleset executed by its own engine.

A kill point was registered in version control before any evaluation code existed: a
≥25pt differential in instance detection under camouflage, against the real Wazuh
manager on the LogHub OpenSSH corpus, or the project stops. The result is narrower than
the criterion suggests. Across eight camouflage strategies pooled over five seeds the
tally is **one win, four ties and three losses**
(`results/killpoint/killpoint_eight_strategies_ambient0.05.md`). The single win is
`rephrase` at **+31.1pt**, and it is a mechanism rather than luck: Wazuh's sshd rules
match literal strings, so a reworded line leaves the decoder entirely, while its sentence
embedding stays near the original. That win is stable across a 20× range of background
density (+31.2 / +31.1 / +31.1,
`results/killpoint/killpoint_ambient_sensitivity.md`) and survives an attacker allowed to
search rather than pick (+35.6pt, `results/adaptive_wazuh/notes.md`).

The losses are reported with equal weight. Against IP rotation the embedding detector is
the weaker system (**−11.1pt**), against slowed timing it is weaker (**−8.9pt**), and
against `realistic-combo` — the strategy closest to how an attacker would actually
behave — it is weaker still (**−13.3pt**,
`results/killpoint/killpoint_paced_ambient0.05.md`). When the same search is pointed at
both systems rather than only at the SIEM, the conservative differential is **−2.2pt**:
negative (`results/adaptive_wazuh/notes.md`). Precision is not an open problem but a
closed negative result — **five levers were measured against it and five rejected**, four
because the mandatory camouflage arm exposed a cost that clean data hid
(`results/suppression/`, `docs/results.v1/contamination_retune.md`).

Four results are not differentials and cannot be taken back by any comparison. On real
traffic this detector is the quieter system, raising roughly 3.2× fewer alerts than
Wazuh at its own default level. Wazuh's headline 100% is level-3 saturation: raise the
threshold and it detects 11.1% — one instance in nine — on the *clean* corpus. Invented
MITRE technique IDs went from 47/142 and 119/197 to **0 and 0** under structured,
validated output, confirmed on two corpora and two models. And authentic `hydra`/`ssh`
attacks captured from real tooling hold 100% instance detection on all nine camouflage
conditions (50/50 pooled), qualified as an attack-shape finding rather than a robustness
win.

The contribution is therefore a method as much as a system: a pre-registered kill point
honoured when it returned an uncomfortable shape, a comparator run as its own engine, a
third-party attack toolchain, and a benchmark rule that made four of the five precision
rejections visible. The defensible claim is narrow and stated first — signature rules
break when an attack is reworded and embeddings do not; against timing and IP rotation
the embedding detector is the weaker of the two; and under an optimising attacker the
advantage disappears.

**Keywords:** log anomaly detection, adversarial evaluation, SIEM comparison, MITRE
ATT&CK, LLM grounding, reproducible measurement.

---

## Shorter variant (≈150 words, for a submission form)

This project measures what open-source SIEMs and most log-anomaly papers do not report:
how much detection degrades when the attacker tries to hide. A local-first embedding
detector is compared against the real Wazuh manager on real OpenSSH logs, under eight
camouflage strategies pooled over five seeds, against a kill point registered in version
control before any results existed.

The tally is **one win, four ties, three losses**. The win, `rephrase` at **+31.1pt**, is
explainable: signature rules match literal strings and a reworded line falls out of the
decoder, while its embedding does not move far. Against IP rotation (−11.1pt), slowed
timing (−8.9pt) and `realistic-combo` (−13.3pt) the embedding detector is the weaker
system, and under an optimising attacker the conservative differential is **−2.2pt**.
Precision resisted five measured fixes, four rejected on adversarial evidence. The
narrow claim, and the rejections, are the contribution.
