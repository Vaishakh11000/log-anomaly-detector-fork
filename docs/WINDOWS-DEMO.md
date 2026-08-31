# Running the demo on a Windows laptop

For showing the project on somebody else's machine. Use the **public release**
(`Vaishakh11000/log-anomaly-detector`), not this fork — it ships the pre-computed
results, so the dashboard has something to show the moment it opens, and it carries no
development notes.

Two routes below. Take the first one unless you specifically need to re-run detection.

---

## Route 1 — the demo (about 5 minutes, ~60 MB)

The dashboard reads a results file that ships with the repo. It does **not** import
torch, does not download any model, and does not need Ollama — the 19 narratives are
already in that file. Checked on 2026-08-31: the page renders 94 incidents, 19 notable,
19 narrated, with nothing installed but Streamlit and pandas.

### 1. Install uv

Open **PowerShell** (normal user is fine, no admin needed) and run:

```powershell
powershell -c "irm https://astral.sh/uv/install.ps1 | iex"
```

**Then close PowerShell and open it again** — the installer adds `uv` to PATH and the
old window will not see it. Check:

```powershell
uv --version
```

If it says `uv is not recognized`, you skipped the reopen; if it still fails, use the
full path `& "$env:USERPROFILE\.local\bin\uv.exe" --version`.

### 2. Get the code

With git, if the laptop has it:

```powershell
git clone https://github.com/Vaishakh11000/log-anomaly-detector.git
cd log-anomaly-detector
```

Without git — download the ZIP instead:

1. Open <https://github.com/Vaishakh11000/log-anomaly-detector>
2. Green **Code** button → **Download ZIP**
3. Right-click the ZIP → **Extract All**
4. In PowerShell: `cd` into the extracted folder (it will be
   `log-anomaly-detector-main`).

### 3. Run it

```powershell
uv run --no-project --with streamlit --with pandas streamlit run src/dashboard.py
```

The browser opens at `http://localhost:8501`. If Windows Firewall asks, **Cancel** is
fine — the page is local and does not need network access.

`--no-project` is what keeps this small: without it, uv installs the whole project
including PyTorch (~2 GB) that the dashboard never touches.

### 4. What to show them

The list opens ranked by triage priority, not by time. The real attacks are at the top:

| Row | What it is |
|---|---|
| 🔴 **#2 — alice**, 10 events, `T1110` `T1548` `T1136` | brute force → privilege escalation → backdoor account. **Open this one** and read the narrative — it is the headline feature |
| 🟠 #91 / #1 / #27, 6-8 events, `T1110` `T1087` | account enumeration: one IP trying many usernames |
| 🔴 #26 — admin, 2 events, `T1021.004` | impossible travel — same account, two places, 15 minutes apart |

Points worth making out loud:

- **Nobody told it what an attack looks like.** No labels, no attack signatures. It
  learned each user's normal and flagged what did not fit.
- **The MITRE technique codes come from a lookup table, not the language model.** The
  model only writes prose about codes it was handed — otherwise it invents plausible
  ones that do not exist.
- **94 incidents for 9 real attacks** is the honest weakness. Tick *Show all 94* in the
  sidebar and say so; the false positives are ranked last, not hidden.
- It ran on this laptop with no GPU, no cloud account and no internet.

### Stopping it

`Ctrl+C` in PowerShell, then close the browser tab.

---

## Route 2 — re-running detection on the laptop (30+ minutes, ~2 GB)

Only needed if you want to show the pipeline actually computing, rather than the
results it computed earlier.

```powershell
uv sync                                  # installs everything, CPU-only PyTorch
uv run python src/pipeline.py --input data/processed/parsed.csv `
    --output data/processed/incidents.json --no-llm
uv run --no-project --with streamlit --with pandas streamlit run src/dashboard.py
```

`--no-llm` skips the narratives and takes a couple of minutes instead of 13-15. The
first run also downloads the sentence-transformer model (~90 MB), so it needs internet
once.

**Do not run this ten minutes before a demo.** If it fails you have nothing; Route 1
always works.

### Live narratives (optional, adds ~2.5 GB)

1. Install Ollama for Windows: <https://ollama.com/download>
2. `ollama pull phi3`
3. Drop the `--no-llm` flag above.

Expect roughly a minute per incident on a CPU, so 19 narrated incidents is about 15
minutes. There is no reason to do this live — the shipped file already has them.

---

## If something goes wrong

| Symptom | Cause and fix |
|---|---|
| `uv is not recognized` | PowerShell was not reopened after installing uv. Close it and open a new window. |
| `running scripts is disabled on this system` | Execution policy. Run `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` in that window, then the install line again. |
| `No incidents file found` | You are not in the repo root. `cd` into the folder that contains `src` and `data`, then re-run. |
| Page loads but the list is empty | The `data/processed/incidents.json` file did not come with the download. Re-download the ZIP; that file is committed on purpose. |
| `Port 8501 is already in use` | Add `--server.port 8502` to the end of the command. |
| First run hangs for a minute | Windows Defender scanning the freshly unpacked Python packages. It only happens once. |
| Very slow on battery | Plug it in. Detection is CPU-bound and Windows throttles hard on battery. |

---

## What not to take to a friend's laptop

- **This fork.** It carries development notes and unfinished work.
- **The Wazuh comparison and the live bake-off.** They need Docker, a container image
  and a warm-up period — that is the demo for your own machine, not a laptop you have
  never booted.
