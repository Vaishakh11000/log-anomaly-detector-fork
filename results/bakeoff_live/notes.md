# Live two-box bake-off — reading

**Date:** 2026-09-05. **Command:**
`logdet-live-bakeoff --repeat 3 --attacks brute_force enumeration --level none --brute-space 90`

The last open Stage 6 item: authentic attacks launched on the Kali box, shipped
over the Cat6 link (`--peer`, not `--corpus-out`) into the analyzer's
`POST /collector/ingest`, with the detector and Wazuh scored side by side on the
same shipped stream.

## What is actually proven here

The **wire and the plumbing**, end to end, live:

- Kali ran real `hydra` (scenario A) and real `ssh` enumeration (scenario C)
  against its own sshd, captured ground truth at launch, and shipped 318
  captured lines over the direct link into the collector endpoint.
- The analyzer's detector tailed the collector file and scored it.
- Wazuh saw the **identical** 318 lines: a `WazuhMirror` tails the collector
  file and appends each line, in order, to the file its logcollector watches —
  **318 collector lines, 318 mirrored**, so neither system was handed a
  different stream.
- One scorer (`scoring.measure_lines`, the kill point's own) served both
  systems, aligned by Kali's ground-truth line numbers shifted per fire.

Attacks launched on one physical machine, alerts on another. That is the
§2c/§2d demonstration.

## The numbers

| system | instance (6/6) | line rate | flagged |
|---|---|---|---|
| this detector | **100%** | **80%** (93/117) | 105 |
| Wazuh (level ≥3) | **100%** | 72% (84/117) | 96 |

Per scenario, both systems detect **every** instance (3/3 A, 3/3 C). The only
separation is the line rate, and it is small:

| scenario | ours (lines) | Wazuh (lines) |
|---|---|---|
| A brute force | 80% (72/90) | 77% (69/90) |
| C enumeration | 78% (21/27) | **56%** (15/27) |

## How to read it — and how NOT to

**This is a demonstration, not a new gap.** The ties on instance detection are
expected and already known: the injected §4 runs (`results/kali/injected_notes.md`)
established that authentic attacks hold ~100% on both systems — an
**attack-shape finding**, not a robustness win. An authentic instance is a few
heterogeneous lines against a real per-user baseline; one surviving line calls
it detected, and at level `none` (no camouflage) nothing removes them. So a live
scored bake-off of authentic attacks *shows ties*, and its worth is that the
whole two-box pipeline works in front of an examiner, not a headline number.

**The line-rate edge is consistent with the kill-point mechanism but must not be
quoted as a differential.** The detector holds more of each attack's lines than
Wazuh, most on enumeration (78% vs 56%) — Wazuh's sshd decoder matches literal
strings and the detector embeds them. But this is level `none`; the real
`rephrase` differential lives in the recorded kill point, not here.

## Caveats (all load-bearing)

- **Not §4-admissible.** Six live firings are not ≥5 *recorded* seeds; §4
  instance detection wants the recorded corpus. Camouflage was measured in the
  injected runs, not live here.
- **Attacks-only.** No benign background, so the flagged/alert counts (105 vs
  96) are **not** a false-positive or alert-volume rate. Act 1 (benign) is the
  single-box `bakeoff.run_benign_baseline`.
- **brute_force needs `--brute-space` (90s here).** `hydra` fires from
  `127.0.0.1` and cannot bind a source, and sshd's `srclimit_penalise` is keyed
  per source /32, so back-to-back instances get throttled to one line each
  (a first, unspaced run read A=33% for exactly this reason). Spacing lets the
  penalty decay; enumeration instead binds a distinct loopback source per
  instance (`127.0.0.1{11,12,13}`), so it needs no spacing.
- **Loopback attack, link ships the lines.** The attack runs against Kali's own
  sshd (every authentic capture does); the Cat6 link carries the *captured
  lines*, not the attack. So the attribution source stays `127.0.0.1` and the
  target stays `root` (68 lines of real history in the background — though here
  there is no background, attacks-only).
- **Scenario B (impossible travel) omitted** — its distant leg is synthetic by
  necessity (§2d).
