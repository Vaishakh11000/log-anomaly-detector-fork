# Demo runbook — 31 August 2026

Written for the review room. Two acts, the safe one first. Every step says what you
should see, and what to do when you do not see it.

**One bake-off session at a time.** This bit us while preparing the deck, so it is
worth knowing: if a grid page is left open with its stream running and you then start a
second bake-off — another browser tab, or the command line — both write background
traffic into the same log file, and the scoring silently reports **0% for our detector**
while Wazuh looks fine. Nothing is broken; the two harnesses are simply fighting over one
file. Before firing anything, press **Close the stream** on any grid page you are not
using, and close old browser tabs.

**The rule for the room: never debug live.** If a step does not produce what this file
says it should, move to the fallback, keep talking, and carry on. There is a screenshot
of every act in `screenshots/`, so a failure costs you the live version, not the point
you were making.

---

## Before you leave the house

- [ ] The laptop is plugged in. Detection saturates the CPU and a mobile GPU throttles on
      battery.
- [ ] `git log --oneline -1` shows the commit you expect.
- [ ] The presentation folder is on the machine you will actually present from, including
      `deck.pdf`, `KNOWLEDGE-PACK.pdf`, `QA-PREP.pdf` and `references/`.
- [ ] **Say the latency number for the machine you are on.** The 5.2 s figure was measured
      on the RTX 3050 development laptop. If you present on the RTX 4060 machine,
      re-measure it once before quoting it, or quote the CPU number instead. Quoting a
      figure from a different machine is the one thing here that would be dishonest.

---

## Act 0 — Start everything, 10 minutes before

Four terminals, in this order. Wait for each before starting the next.

**1. The SIEM.**

```bash
docker start wazuh
docker ps --filter name=wazuh          # expect: Up ...
```

`wazuh-analysisd` needs 20-30 seconds after that before it will answer. After a reboot
the container comes back as `Exited (255)` — that is normal, `docker start` fixes it.

*If Docker will not start:* you lose Act 2 only. Act 1 needs no container.

**2. The language model.**

```bash
ollama serve                            # leave running
ollama ps                               # PROCESSOR column must say GPU
```

If `PROCESSOR` says CPU, the machine has the wrong Ollama package installed
(`ollama` rather than `ollama-cuda`). Do not try to fix that in the room — narration
still works, it takes about 24 seconds instead of 5, so say so and move on.

**3. The detector service.**

```bash
export PATH="$HOME/.local/bin:$PATH"
cd ~/log-anomaly-detector-fork
uv run logdet-api                       # 127.0.0.1:8000
curl -s localhost:8000/health           # expect {"status":"ok",...}
```

*If the detector model is missing:* `uv run logdet-fit --input data/processed/parsed.csv`
rebuilds it in about a minute. Do this **before** the room, never in it.

**4. The dashboards.**

```bash
uv run streamlit run src/logdet/dashboard.py --server.port 8501
uv run streamlit run src/logdet_eval/bakeoff_dashboard.py --server.port 8502
```

Open both tabs now and leave them open. Zoom the browser to about 110% — the incident
rows are small at native size on a projector.

**5. One throwaway firing to warm everything.** Fire any cell on the grid once and close
the stream again, so the first thing the panel sees is not the model loading.

---

## Act 1 — The detector, live (safe; needs no container, no network)

**What you are showing:** a detector following a log that is still being written,
producing incidents while they watch, with a plain-English explanation on demand.

Terminal:

```bash
uv run logdet-replay --input data/raw/synthetic.log \
     --output data/live/demo.log --speed 600 --max-gap 1 --truncate
```

In the dashboard sidebar, set the source to `data/live/demo.log`, untick *Replay once*,
and press **Start**.

**What they should see:** *Lines seen* and *Lines parsed* climbing together; incidents
appearing in the list, newest and most serious first; MITRE codes as green tags.

**What to say while it runs:**
"That is the log being written now, and the detector reading it. Every one of those
incidents is a group of related events, not one line, and the tag is the MITRE technique —
which comes from a lookup table, not from the language model."

Then click one incident open. It shows the raw events, the source addresses, the
techniques. Click **Narrate now** and wait.

**What to say while narration runs:** "This is a small model running on this laptop. No
cloud, no API key. It is describing events it was handed — it is not deciding whether
this is an attack."

**Fallbacks:**
- Dashboard shows *Cannot reach the service*: the API terminal died. Restart it. If that
  fails, show `screenshots/dashboard-incidents.png`.
- Narration hangs: `ollama serve` is not running. Say so, show
  `screenshots/incident-narrative.png`, and move on — the narrative is not the claim.

---

## Act 2 — The bake-off (the good one; needs Wazuh)

**What you are showing:** the same attack fired at our detector and at a real production
SIEM, on the same stream, with a member of staff choosing what gets fired.

Open the grid tab (port 8502) and press **Open the stream**. It takes about 30 seconds,
because it resets Wazuh's correlation state, which restarts `wazuh-analysisd`.

**Quiet baseline first.** Let it sit for a moment on "Quiet stream. Pick a cell."

Say: "Nothing is happening yet. Background traffic only. Both systems are reading it.
On a 30-line quiet run we raised 5 alerts and Wazuh raised 19 — every one of them a false
positive, because there is no attack in there at all. That is the alert-fatigue problem,
and we are on the wrong side of it too."

**Then invite them to choose.** "Pick an attack and a camouflage level." Hand the choice
over — it is what makes this a demonstration rather than a video.

**What to steer towards if they have no preference:** `enumeration` at `none`, then
`enumeration` at `rephrase`. It takes about a minute per instance, and the reworded run is
where Wazuh's line rate collapses from 100% to 34% while ours holds.

**Time each cell honestly:**

| Attack | Real time per instance |
|---|---|
| `enumeration` | about 1 minute |
| `brute_force` | about 2.5 minutes |
| `impossible_travel` | **15 minutes** — the two logins are 15 minutes apart by design |

Do not fire `impossible_travel` live unless you have 45 minutes. Its result is on
slide 14 and in `results/bakeoff/bakeoff.md`: Wazuh 3 of 3 clean, **0 of 3** reworded.

**The two rows marked with a star (`slow`, `realistic-combo`) are honest about their own
limits.** Say it before anyone asks: "Those two cannot be measured on this instrument.
Wazuh times its rules by when a line arrives, so if we compress time its score is decided
by our replay speed, not its rules. The real figures for those come from a six-hour
paced run — and both of them are losses for us."

**Fallbacks:**
- "Wazuh container is not answering": you did not wait long enough after `docker start`,
  or it is not running. Untick *Score Wazuh too* and run the detector alone, saying that
  the comparison numbers are on the slide — or show `screenshots/bakeoff-scored.png`.
- A firing hangs: press **Close the stream**, reopen, fire a smaller cell.
- The page freezes: it is Streamlit repainting, not the firing. The firing runs on its own
  thread and will finish.
- **Our detector reports 0% while Wazuh reports 100%:** almost certainly a second bake-off
  session writing to the same log. Close every other grid tab, press *Close the stream*,
  reopen, and fire again. It is not a detection failure — verified while preparing this
  deck: the same condition on a clean log scores 100%.

---

## Act 3 — Only if they ask "so how do you know the comparison is fair?"

Show slide 13, then say the mechanism: one writer appends every line to both systems in
the same call, so neither can be handed different traffic; and the injector records every
line's number and label as it writes it, so the right answer is known automatically and
the same scoring code grades both systems.

If they want to see it, the manifest and both systems' scores for every condition are in
`results/bakeoff/bakeoff.md`, and the whole 18-cell table can be regenerated from the
saved JSON with one command:

```bash
uv run logdet-bakeoff --merge results/bakeoff/bf_measured2 results/bakeoff/bf_measured \
     results/bakeoff/enum_measured results/bakeoff/it_measured results/bakeoff/illustration \
     --notes results/bakeoff/notes.md --output results/bakeoff
```

---

## After the demo

```bash
curl -s -X POST localhost:8000/stream/stop
```

Press **Close the stream** on the grid page if you opened it. Leaving a stream running
keeps the service tailing a file nobody is writing, which looks like a live stream on the
dashboard and will confuse the next person to open it.

---

## The three sentences to end on

1. "Rewording an attack costs a production SIEM 33 points of detection and costs us 2."
2. "We lose on three of the eight camouflage strategies, and those are on the slide."
3. "The threshold that decides whether this project continues was written down before we
   had any results."
