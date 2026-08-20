# Camouflage Robustness: All Eight Strategies

Every camouflage strategy against **Wazuh** (real manager, its own rules and
engine), on the real LogHub OpenSSH corpus, pooled over 5 seeds.

**Differential = how much more Wazuh degraded than we did.** Positive means we
held up better; negative means Wazuh did.

| Strategy | Ours (Δpt) | Wazuh (Δpt) | Differential | Instrument |
|---|---|---|---|---|
| rephrase | +2.2 | +33.3 | **+31.1** | batch |
| mimicry | +0.0 | +0.0 | +0.0 | batch |
| noise | +0.0 | +0.0 | +0.0 | batch |
| volume | +0.0 | +0.0 | +0.0 | batch |
| temporal | +0.0 | +0.0 | +0.0 | paced |
| slow | +8.9 | +0.0 | -8.9 | paced |
| ip_rotate | +11.1 | +0.0 | -11.1 | batch |
| realistic-combo | +13.3 | +0.0 | -13.3 | paced |

## What this adds up to

**1 win, 4 ties, 3 losses.**

- won: `rephrase`
- tied: `mimicry`, `noise`, `temporal`, `volume`
- lost: `ip_rotate`, `realistic-combo`, `slow`

Best differential **+31.1pt** → **CONTINUE** against the registered ≥25pt bar, cleared by `rephrase`.

## The claim this supports, and the one it does not

The result is **one mechanism, not a general property.** `rephrase` works
because Wazuh's sshd rules match literal strings — `Failed password`,
`Invalid user` — so rewording the message drops the line out of the decoder
entirely, while a sentence embedding of a reworded line stays near the
original in vector space. That is explainable and expected, not luck.

Everything else is a tie or a loss. In particular:

- **`realistic-combo` is a loss**, and it is the strategy closest to how a
  real attacker would actually behave.
- **`ip_rotate` is a loss**: spreading an attack across many source IPs
  defeats our per-user embedding context, while Wazuh's per-IP frequency
  rules simply fire on whichever IP still crosses the threshold.
- **`slow` is a loss** once Wazuh is replayed at true speed.

Supportable: *"signature rules break when you reword an attack; embeddings
do not."* Not supportable: *"more robust to camouflage."*

## Why two instruments

Wazuh's correlation windows key on **arrival time, not the timestamp in the
log line**. Replayed at machine speed every event is simultaneous to it, so
its drop under `slow`, `temporal` and `realistic-combo` would be 0pt *by
construction*. Those three come from a wall-clock-paced replay instead; the
other five come from batch, where pacing is irrelevant to the mechanism.

The two corpora are not identical — the paced one is thinned to
`max_events_per_ip=12` so it can be replayed in
real time — so each row is taken whole from one instrument rather than mixed.

## Alert volume

Neither system is precise here, and on this corpus we are not the noisier one:
on the clean corpus Wazuh raises roughly **3.2x** the alerts we do at its own
default level. Per-run counts are in the two source reports.

Sources: `killpoint_ambient0.05.md` (batch), `killpoint_paced_ambient0.05.md` (paced).
