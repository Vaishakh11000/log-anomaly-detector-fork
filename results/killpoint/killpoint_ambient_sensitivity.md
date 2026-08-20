# Does the result survive a different background density?

`ambient_ratio` is how much *real* attacker traffic from the open internet
sits in the background the injected attacks are hidden in. It was picked at
0.05 with no strong reason, and the entire surviving claim rests on a single
number — so if that number only holds at 0.05, it is an artefact.

Same batch experiment, 5 seeds, every strategy, across a 20x range:

| Strategy | ambient 0.01 | ambient 0.05 | ambient 0.2 | Spread |
|---|---|---|---|---|
| rephrase | +31.2 | +31.1 | +31.1 | 0.1 |
| temporal * | +0.0 | +0.0 | +0.0 | 0.0 |
| mimicry | +0.0 | +0.0 | +0.0 | 0.0 |
| noise | +0.0 | +0.0 | +0.0 | 0.0 |
| volume | +0.0 | +0.0 | +0.0 | 0.0 |
| ip_rotate | -13.3 | -11.1 | -8.9 | 4.4 |
| slow * | -15.6 | -11.1 | -22.2 | 11.1 |
| realistic-combo * | -15.6 | -11.1 | -20.0 | 8.9 |

`*` = timing-dependent. **Their differentials here are artefacts and must not
be read as sensitivity**: batch replay makes Wazuh's drop 0pt by construction,
so all that varies down those rows is *our* drop. The real numbers for those
three come from the paced instrument.

## What it shows

**`rephrase` does not move.** Across a 20x change in how much real attacker
traffic surrounds the injected attacks, it reads +31.2 / +31.1 / +31.1 — a
spread of 0.1pt. That is what a mechanism looks like, as opposed to a lucky
configuration: rewording drops a line out of Wazuh's decoder regardless of what
else is in the log, because the decoder matches literal strings.

**The ties stay ties** at every density.

**`ip_rotate` is the one real result that moves**, from -13.3 at the quietest
background to -8.9 at the noisiest — a 4.4pt spread. It stays a loss
throughout; the noisier the background, the less it costs us. Worth stating
in the write-up rather than quoting the single friendliest figure.

The verdict is CONTINUE at all three densities.
