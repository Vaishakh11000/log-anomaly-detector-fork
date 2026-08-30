"""
make_diagrams.py
Draws the three presentation diagrams as SVG, at exactly the size of the slide
area they sit in.

Why not Mermaid. The slide area is about 1.9:1. A pipeline of eight sequential
steps is either eight boxes wide or eight boxes tall, and Mermaid's automatic
layout gave 6.9:1 and 0.6:1 for the same graph -- measured with
`render_diagrams.py`, not guessed. Scaled into a slide, that put the labels at
roughly 7px, which is unreadable from the back of a room. Mermaid also drops a
subgraph's `direction` as soon as an edge crosses the subgraph boundary, so the
two-row layout this needs cannot be expressed. Laying the boxes out by hand
costs one file and gives a diagram that is legible at projector size.

    uv run python docs/presentation-2026-08-31/make_diagrams.py
"""

from pathlib import Path

HERE = Path(__file__).resolve().parent
OUT = HERE / "diagrams"

W, H = 1180, 560          # the usable slide area, in slide pixels

PALETTE = {
    "src":   ("#e8f2e8", "#3f7d3f", "#1e3a1e"),
    "proc":  ("#e6eef8", "#2c5f9e", "#12304f"),
    "model": ("#f0e8f6", "#7a4a9e", "#3d2352"),
    "store": ("#fbf3d9", "#9b7a1a", "#4d3c05"),
    "out":   ("#dfe8f5", "#1e3f66", "#12283f"),
    "eval":  ("#fbe9e7", "#b1442e", "#6d2317"),
}

HEAD = f'''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}" width="{W}" height="{H}"
     font-family="Segoe UI, Helvetica Neue, Arial, sans-serif">
<defs>
  <marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7"
          orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="#41556b"/></marker>
  <marker id="arrowlight" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7"
          orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="#b1442e"/></marker>
</defs>
'''


class Box:
    """A rounded rectangle with a bold title and small body lines."""

    def __init__(self, x, y, w, h, title, lines=(), kind="proc", small=False):
        self.x, self.y, self.w, self.h = x, y, w, h
        self.title, self.lines, self.kind, self.small = title, list(lines), kind, small

    # anchor points, so arrows never have to be positioned by hand
    @property
    def left(self): return (self.x, self.y + self.h / 2)
    @property
    def right(self): return (self.x + self.w, self.y + self.h / 2)
    @property
    def top(self): return (self.x + self.w / 2, self.y)
    @property
    def bottom(self): return (self.x + self.w / 2, self.y + self.h)

    def svg(self) -> str:
        fill, stroke, text = PALETTE[self.kind]
        title_size = 15 if self.small else 17
        body_size = 12.5 if self.small else 13.5
        parts = [
            f'<rect x="{self.x}" y="{self.y}" width="{self.w}" height="{self.h}" rx="9" '
            f'fill="{fill}" stroke="{stroke}" stroke-width="2"/>'
        ]
        cx = self.x + self.w / 2
        block = 1 + len(self.lines)
        top = self.y + self.h / 2 - (block - 1) * (body_size + 4) / 2 + 1
        parts.append(
            f'<text x="{cx}" y="{top}" text-anchor="middle" font-size="{title_size}" '
            f'font-weight="600" fill="{text}">{self.title}</text>')
        for index, line in enumerate(self.lines, start=1):
            parts.append(
                f'<text x="{cx}" y="{top + index * (body_size + 4)}" text-anchor="middle" '
                f'font-size="{body_size}" fill="{text}">{line}</text>')
        return "\n".join(parts)


def band(x, y, w, h, label, colour="#b1442e", fill="#fdf5f3") -> str:
    """A titled region drawn behind a group of boxes."""
    return (f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="12" fill="{fill}" '
            f'stroke="{colour}" stroke-width="1.5" stroke-dasharray="7 5"/>'
            f'<text x="{x + 14}" y="{y + 19}" font-size="13.5" font-weight="600" '
            f'fill="{colour}">{label}</text>')


def line(p1, p2, dashed=False, light=False, label=None, label_dy=-7) -> str:
    marker = "arrowlight" if light else "arrow"
    colour = "#b1442e" if light else "#41556b"
    dash = ' stroke-dasharray="6 5"' if dashed else ""
    out = (f'<path d="M{p1[0]},{p1[1]} L{p2[0]},{p2[1]}" fill="none" stroke="{colour}" '
           f'stroke-width="2"{dash} marker-end="url(#{marker})"/>')
    if label:
        mx, my = (p1[0] + p2[0]) / 2, (p1[1] + p2[1]) / 2 + label_dy
        out += (f'<text x="{mx}" y="{my}" text-anchor="middle" font-size="12" '
                f'fill="{colour}">{label}</text>')
    return out


def elbow(points, dashed=False, light=False, label=None, label_at=None) -> str:
    """A routed line through explicit corners, for the row-wrap connector."""
    marker = "arrowlight" if light else "arrow"
    colour = "#b1442e" if light else "#41556b"
    dash = ' stroke-dasharray="6 5"' if dashed else ""
    d = "M" + " L".join(f"{x},{y}" for x, y in points)
    out = (f'<path d="{d}" fill="none" stroke="{colour}" stroke-width="2"{dash} '
           f'marker-end="url(#{marker})"/>')
    if label and label_at:
        out += (f'<text x="{label_at[0]}" y="{label_at[1]}" text-anchor="middle" '
                f'font-size="12" fill="{colour}">{label}</text>')
    return out


def write(name: str, body: str) -> None:
    (OUT / f"{name}.svg").write_text(HEAD + body + "\n</svg>\n")
    print(f"  wrote diagrams/{name}.svg")


# --- Diagram A: the methodology, eight steps in two rows -------------------

def methodology() -> None:
    # A 60px channel on the left is deliberate: the adversarial arrow feeds back
    # into step 1 and needs somewhere to run that is not on top of a box.
    bw, bh, gap = 252, 96, 32
    x0 = 60
    row1_y, row2_y = 44, 208
    xs = [x0 + i * (bw + gap) for i in range(4)]

    r1 = [
        Box(xs[0], row1_y, bw, bh, "1 · Read the logs",
            ["real OpenSSH, 655k lines", "+ 751-line test corpus"], "src"),
        Box(xs[1], row1_y, bw, bh, "2 · Parse and mask",
            ["split the line into fields;", "hide IP, port and PID"], "proc"),
        Box(xs[2], row1_y, bw, bh, "3 · Embed the meaning",
            ["MiniLM turns each line", "into 384 numbers"], "model"),
        Box(xs[3], row1_y, bw, bh, "4 · Score each user",
            ["Isolation Forest per user;", "no labelled data needed"], "model"),
    ]
    r2 = [
        Box(xs[0], row2_y, bw, bh, "5 · Group into incidents",
            ["same user, 30 minutes,", "+ impossible-travel check"], "proc"),
        Box(xs[1], row2_y, bw, bh, "6 · Attach MITRE technique",
            ["from a lookup table —", "never from the LLM"], "proc"),
        Box(xs[2], row2_y, bw, bh, "7 · Explain in English",
            ["local phi3 via Ollama,", "fully offline"], "model"),
        Box(xs[3], row2_y, bw, bh, "8 · Show the analyst",
            ["dashboard + HTTP API,", "ranked by severity"], "out"),
    ]

    parts = []
    for row in (r1, r2):
        for a, b in zip(row, row[1:]):
            parts.append(line((a.right[0] + 3, a.right[1]), (b.left[0] - 5, b.left[1])))
    # wrap from the end of row 1 to the start of row 2
    mid = row1_y + bh + 34
    parts.append(elbow([(r1[3].bottom[0], r1[3].bottom[1] + 3),
                        (r1[3].bottom[0], mid), (r2[0].top[0], mid),
                        (r2[0].top[0], r2[0].top[1] - 5)]))

    ev_y = 372
    parts.append(band(x0 - 12, ev_y, W - 2 * x0 + 36, 158,
                      "Adversarial evaluation — the gate every change has to pass"))
    e1 = Box(x0 + 12, ev_y + 34, 320, 100, "Camouflage the attack",
             ["reword · mimic normal traffic ·", "rotate source IPs · slow it down ·",
              "or all of them together"], "eval")
    e2 = Box(x0 + 388, ev_y + 34, 320, 100, "Fire it at both systems",
             ["ours and Wazuh, same lines,", "same moment, same scorer"], "eval")
    e3 = Box(x0 + 764, ev_y + 34, 320, 100, "Report the drop",
             ["how much detection each one", "loses — including where we lose"], "eval")
    parts += [e1.svg(), e2.svg(), e3.svg()]
    parts.append(line((e1.right[0] + 3, e1.right[1]), (e2.left[0] - 5, e2.left[1]), light=True))
    parts.append(line((e2.right[0] + 3, e2.right[1]), (e3.left[0] - 5, e3.left[1]), light=True))
    # camouflaged attacks re-enter at step 1, up the left-hand channel
    parts.append(elbow([(e1.left[0] - 3, e1.left[1]), (26, e1.left[1]),
                        (26, r1[0].left[1]), (r1[0].left[0] - 5, r1[0].left[1])],
                       dashed=True, light=True, label="disguised attacks go back in",
                       label_at=(x0 + 176, ev_y - 12)))
    # and our verdicts drop out of step 8 into the report
    parts.append(elbow([(r2[3].bottom[0], r2[3].bottom[1] + 3),
                        (r2[3].bottom[0], ev_y - 16),
                        (e3.top[0], ev_y - 16), (e3.top[0], e3.top[1] - 5)],
                       dashed=True, light=True, label="what each system detected",
                       label_at=(e3.top[0] - 40, ev_y - 24)))

    write("methodology", "\n".join([b.svg() for b in r1 + r2] + parts))


# --- Diagram B: the system architecture ------------------------------------

def architecture() -> None:
    """Three columns above a full-width comparison band.

    The band is drawn first, because it has a fill and would otherwise paint
    over the boxes that sit inside it.
    """
    back, boxes, parts = [], [], []

    # left column: where log lines come from, plus the saved model
    sources = [
        Box(14, 46, 232, 64, "File tail", ["/var/log/auth.log"], "src", small=True),
        Box(14, 122, 232, 64, "journald", ["this machine's own journal"], "src", small=True),
        Box(14, 198, 232, 64, "Paced replay", ["a recording, at real speed"], "src", small=True),
    ]
    store = Box(14, 282, 232, 78, "Saved detector model",
                ["fitted once on history;", "fingerprint checked on load"], "store", small=True)
    parts.append('<text x="14" y="32" font-size="14" font-weight="600" fill="#3f7d3f">'
                 'Live sources</text>')

    # middle column: the detection engine
    mx, mw = 288, 336
    core = [
        Box(mx, 46, mw, 64, "Parser", ["one common event shape · OpenSSH 100% · Linux 99.4%"],
            "proc", small=True),
        Box(mx, 122, mw, 64, "Streaming processor",
            ["a batch every 50 lines or 5 seconds"], "proc", small=True),
        Box(mx, 198, mw, 64, "Embedding + Isolation Forest",
            ["scores the stream, never refits"], "model", small=True),
        Box(mx, 274, mw, 64, "Incidents + MITRE technique",
            ["grouping · impossible travel · lookup table"], "proc", small=True),
    ]
    parts.append(f'<text x="{mx}" y="32" font-size="14" font-weight="600" fill="#2c5f9e">'
                 f'Detection engine — always running</text>')

    # right column: what a person actually uses
    rx, rw = 666, 300
    face = [
        Box(rx, 46, rw, 64, "FastAPI service",
            ["/incidents · live /events · /stream/status"], "out", small=True),
        Box(rx, 122, rw, 64, "Streamlit dashboard",
            ["ranked incidents · MITRE tags · health"], "out", small=True),
        Box(rx, 198, rw, 64, "Local LLM narrative",
            ["phi3 on demand · 5.2 s GPU / 24.2 s CPU"], "model", small=True),
    ]
    parts.append(f'<text x="{rx}" y="32" font-size="14" font-weight="600" fill="#1e3f66">'
                 f'What the analyst uses</text>')

    # bottom band: the comparison, deliberately outside the pipeline
    band_y = 382
    back.append(band(14, band_y, 1152, 168,
                     "Comparison track — a separate package; the pipeline never imports it"))
    comp = [
        Box(40, band_y + 46, 320, 96, "Wazuh 4.9 in Docker",
            ["the real manager, with its own", "rules and its own engine"], "eval"),
        Box(430, band_y + 46, 320, 96, "One shared scorer",
            ["the same code scores both", "systems, from the same lines"], "eval"),
        Box(820, band_y + 46, 320, 96, "Robustness report",
            ["the drop under camouflage,", "side by side, losses included"], "eval"),
    ]

    boxes = sources + [store] + core + face + comp

    for source in sources:
        parts.append(line((source.right[0] + 3, source.right[1]),
                          (core[0].left[0] - 5, core[0].left[1] + 24)))
    for a, b in zip(core, core[1:]):
        parts.append(line((a.bottom[0], a.bottom[1] + 3), (b.top[0], b.top[1] - 5)))
    parts.append(line((store.right[0] + 3, store.right[1] - 14),
                      (core[2].left[0] - 5, core[2].left[1] + 14),
                      dashed=True, label="loaded once", label_dy=-9))
    parts.append(elbow([(core[0].right[0] + 3, core[0].right[1]),
                        (rx - 22, core[0].right[1]), (rx - 22, face[0].left[1]),
                        (face[0].left[0] - 5, face[0].left[1])]))
    parts.append(line((face[0].bottom[0], face[0].bottom[1] + 3),
                      (face[1].top[0], face[1].top[1] - 5)))
    parts.append(line((face[2].top[0], face[2].top[1] - 3),
                      (face[1].bottom[0], face[1].bottom[1] + 5), dashed=True,
                      label="narrative, on demand", label_dy=13))
    parts.append(elbow([(core[3].right[0] + 3, core[3].right[1]),
                        (rx - 22, core[3].right[1]), (rx - 22, face[2].left[1]),
                        (face[2].left[0] - 5, face[2].left[1])], dashed=True))
    # the same lines go to Wazuh; our verdicts go to the scorer
    parts.append(elbow([(core[0].left[0] - 3, core[0].left[1] - 12),
                        (268, core[0].left[1] - 12), (268, band_y + 34),
                        (comp[0].top[0], band_y + 34), (comp[0].top[0], comp[0].top[1] - 5)],
                       dashed=True, light=True, label="the identical lines",
                       label_at=(360, band_y + 30)))
    parts.append(line((core[3].bottom[0], core[3].bottom[1] + 3),
                      (comp[1].top[0], comp[1].top[1] - 5), dashed=True, light=True,
                      label="our verdicts", label_dy=-6))
    parts.append(line((comp[0].right[0] + 3, comp[0].right[1]),
                      (comp[1].left[0] - 5, comp[1].left[1]), light=True))
    parts.append(line((comp[1].right[0] + 3, comp[1].right[1]),
                      (comp[2].left[0] - 5, comp[2].left[1]), light=True))

    write("architecture", "\n".join(back + [b.svg() for b in boxes] + parts))


# --- Diagram C: the live bake-off ------------------------------------------

def bakeoff() -> None:
    pick = Box(14, 54, 252, 110, "The examiner picks",
               ["3 attacks × 6 camouflage levels", "— nothing scripted in advance"], "eval")
    inject = Box(14, 214, 252, 110, "The injector builds it",
                 ["makes the attack, then", "camouflages it as chosen"], "eval")
    writer = Box(310, 134, 272, 110, "One writer",
                 ["appends every line to BOTH", "systems in the same call"], "proc")
    truth = Box(310, 316, 272, 110, "Manifest = ground truth",
                ["every line numbered and", "labelled as it is written"], "store")
    ours = Box(626, 54, 252, 110, "Our detector",
               ["embeddings +", "Isolation Forest"], "proc")
    wazuh = Box(626, 214, 252, 110, "Wazuh manager",
                ["its own sshd rules,", "its own engine"], "eval")
    scorer = Box(626, 374, 252, 96, "One shared scorer",
                 ["same code, both systems"], "out")
    board = Box(922, 134, 244, 250, "Live scoreboard",
                ["instances found", "share of the attack's lines",
                 "alerts raised by each", "the difference between them", "",
                 "computed while they watch"], "out")

    parts = [
        line((pick.bottom[0], pick.bottom[1] + 3), (inject.top[0], inject.top[1] - 5)),
        line((inject.right[0] + 3, inject.right[1] - 20),
             (writer.left[0] - 5, writer.left[1] + 20)),
        line((writer.right[0] + 3, writer.right[1] - 24),
             (ours.left[0] - 5, ours.left[1] + 24)),
        line((writer.right[0] + 3, writer.right[1] + 24),
             (wazuh.left[0] - 5, wazuh.left[1] - 24)),
        line((writer.bottom[0], writer.bottom[1] + 3), (truth.top[0], truth.top[1] - 5)),
        elbow([(ours.right[0] + 3, ours.right[1]), (900, ours.right[1]),
               (900, scorer.right[1]), (scorer.right[0] + 5, scorer.right[1])]),
        elbow([(wazuh.right[0] + 3, wazuh.right[1]), (900, wazuh.right[1]),
               (900, scorer.right[1] - 14), (scorer.right[0] + 5, scorer.right[1] - 14)]),
        line((truth.right[0] + 3, truth.right[1] + 30),
             (scorer.left[0] - 5, scorer.left[1] + 10),
             label="the right answer, known automatically", label_dy=34),
        elbow([(scorer.right[0] + 3, scorer.right[1] + 26),
               (board.bottom[0], scorer.right[1] + 26),
               (board.bottom[0], board.bottom[1] + 5)]),
        '<text x="626" y="34" font-size="14" font-weight="600" fill="#41556b">'
        'Both systems read the very same stream, line for line</text>',
    ]
    write("bakeoff", "\n".join(
        [b.svg() for b in (pick, inject, writer, truth, ours, wazuh, scorer, board)] + parts))


if __name__ == "__main__":
    methodology()
    architecture()
    bakeoff()
