# Live two-box bake-off

Authentic attacks launched on the Kali box, shipped over the Cat6 link into `POST /collector/ingest`, scored side by side. Attacks-only (no benign background), so this is not an alert-volume measurement.

- peer: `http://10.10.10.2:8000`  seeds: live firings, not recorded seeds
- collector lines: 318  mirrored to Wazuh: 318
- our incidents: 2  Wazuh alerts (level >= 3): 96

| system | instance / line detection |
|---|---|
| this detector | 100% (6/6) / 80% |
| Wazuh | 100% (6/6) / 72% |

## Per scenario

| scenario | ours (inst / lines) | Wazuh (inst / lines) |
|---|---|---|
| A | 100% (3/3) / 80% | 100% (3/3) / 77% |
| C | 100% (3/3) / 78% | 100% (3/3) / 56% |

Interpretation lives in `results/bakeoff_live/notes.md`, not here (bake-off precedent: a generator that writes conclusions is scripting the narrative).
