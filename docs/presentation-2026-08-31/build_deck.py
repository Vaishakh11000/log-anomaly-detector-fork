"""
build_deck.py
Renders the presentation folder's Markdown into printable HTML and then PDF.

Why this exists: the slide content lives in PRESENTATION.md so it can be
hand-checked as text, but what goes into the review room is a PDF. Keeping one
builder means the two can never drift -- the PDF is always the Markdown, and
editing the PDF directly is not a thing anyone can accidentally do.

Diagrams are Mermaid source files rendered in the page by a *local* copy of
mermaid.min.js, so the export needs no network and no CDN.

Usage (from the repo root):
    uv run python docs/presentation-2026-08-31/build_deck.py deck
    uv run python docs/presentation-2026-08-31/build_deck.py docs
    uv run python docs/presentation-2026-08-31/build_deck.py all
"""

import asyncio
import re
import sys
from pathlib import Path

import markdown

HERE = Path(__file__).resolve().parent
DIAGRAMS = HERE / "diagrams"

# Slide size. 1280x720 is 16:9 at a size that keeps table text readable when the
# PDF is projected; anything smaller and the results table stops being legible
# from the back of a room.
SLIDE_W, SLIDE_H = 1280, 720

DECK_CSS = f"""
@page {{ size: {SLIDE_W}px {SLIDE_H}px; margin: 0; }}
* {{ box-sizing: border-box; }}
body {{ margin: 0; background: #fff; color: #16212e;
       font-family: "Segoe UI", "Helvetica Neue", Arial, sans-serif; }}
.slide {{ width: {SLIDE_W}px; height: {SLIDE_H}px; padding: 38px 56px 54px;
         page-break-after: always; break-after: page; position: relative;
         overflow: hidden; display: flex; flex-direction: column; }}
.slide:last-of-type {{ page-break-after: auto; break-after: auto; }}
h1.slide-title {{ font-size: 34px; margin: 0 0 6px; color: #12304f;
                 letter-spacing: -0.2px; }}
.rule {{ height: 3px; width: 96px; background: #2c5f9e; margin: 0 0 18px; }}
.body {{ flex: 1; min-height: 0; font-size: 20px; line-height: 1.45; }}
.body.tight {{ font-size: 17px; line-height: 1.35; }}
.body.tighter {{ font-size: 15px; line-height: 1.3; }}
ul {{ margin: 6px 0 10px; padding-left: 24px; }}
li {{ margin: 0 0 9px; }}
li > strong {{ color: #12304f; }}
p {{ margin: 8px 0; }}
table {{ border-collapse: collapse; width: 100%; margin: 8px 0 10px; }}
th, td {{ border: 1px solid #c3d0de; padding: 6px 9px; text-align: left;
         vertical-align: top; }}
th {{ background: #e6eef8; color: #12304f; font-weight: 600; }}
tr:nth-child(even) td {{ background: #f7fafd; }}
code {{ background: #eef2f7; padding: 1px 5px; border-radius: 3px;
       font-family: "Cascadia Mono", Consolas, monospace; font-size: 0.92em; }}
blockquote {{ margin: 12px 0; padding: 14px 20px; background: #fbf3d9;
             border-left: 5px solid #9b7a1a; font-size: 1.02em; }}
blockquote p {{ margin: 4px 0; }}
em {{ color: #4a5a6b; }}
.footer {{ position: absolute; left: 56px; right: 56px; bottom: 18px;
          display: flex; justify-content: space-between; font-size: 13px;
          color: #7c8a99; border-top: 1px solid #dde5ee; padding-top: 8px; }}
.diagram {{ display: flex; justify-content: center; align-items: flex-start;
           min-height: 0; }}
.diagram svg {{ width: 100%; height: auto; max-height: 100%; }}
/* A diagram slide carries its bullets above the picture, so the slide still
   reads as the template's bulleted format rather than as a bare figure. */
.lead {{ font-size: 16px; line-height: 1.35; flex: 0 0 auto; }}
.lead ul {{ margin: 0 0 8px; }}
.lead li {{ margin: 0 0 4px; }}
/* The college's own title-slide format, kept as it was in the 7 August deck. */
.title-slide {{ justify-content: flex-start; align-items: center; text-align: center;
               padding-top: 46px; }}
.title-slide .trust {{ font-size: 17px; font-style: italic; color: #3a4a5c; }}
.title-slide .college {{ font-size: 27px; font-weight: 700; color: #12304f;
                        margin: 4px 0 2px; }}
.title-slide .naac {{ font-size: 15px; color: #3a4a5c; }}
.title-slide .dept {{ font-size: 18px; font-weight: 700; letter-spacing: 0.6px;
                     color: #12304f; margin: 18px 0 0; }}
.title-slide hr.band {{ width: 100%; border: 0; border-top: 3px solid #2c5f9e;
                       margin: 12px 0 20px; }}
.title-slide h1 {{ font-size: 38px; margin: 8px 0 4px; color: #12304f; }}
.title-slide .sub {{ font-size: 19px; color: #4a5a6b; margin-bottom: 26px; }}
.title-slide .who {{ font-size: 18px; line-height: 1.7; color: #16212e; }}
.title-slide .guide {{ font-size: 18px; margin-top: 14px; color: #16212e; }}
.end-slide {{ justify-content: center; align-items: center; text-align: center; }}
.end-slide h1 {{ font-size: 52px; color: #12304f; }}
.shot {{ display: grid; grid-template-columns: 1fr 1fr; gap: 12px; height: 100%; }}
.shot figure {{ margin: 0; display: flex; flex-direction: column; min-height: 0; }}
.shot img {{ width: 100%; flex: 1 1 auto; min-height: 0; object-fit: contain;
            object-position: top; border: 1px solid #c3d0de; border-radius: 4px;
            background: #fff; }}
.shot figcaption {{ font-size: 11.5px; color: #4a5a6b; padding-top: 3px;
                   line-height: 1.25; flex: 0 0 auto; }}
"""

DOC_CSS = """
@page { size: A4; margin: 20mm 18mm; }
body { font-family: "Segoe UI", "Helvetica Neue", Arial, sans-serif;
       color: #16212e; font-size: 12.5px; line-height: 1.55; margin: 0; }
h1 { font-size: 25px; color: #12304f; border-bottom: 3px solid #2c5f9e;
     padding-bottom: 6px; margin: 26px 0 12px; page-break-after: avoid; }
h1:first-child { margin-top: 0; }
h2 { font-size: 18px; color: #1c4a78; margin: 20px 0 8px; page-break-after: avoid; }
h3 { font-size: 15px; color: #2c5f9e; margin: 14px 0 6px; page-break-after: avoid; }
table { border-collapse: collapse; width: 100%; margin: 10px 0; font-size: 11.5px; }
th, td { border: 1px solid #c3d0de; padding: 5px 8px; text-align: left;
         vertical-align: top; }
th { background: #e6eef8; color: #12304f; }
code { background: #eef2f7; padding: 1px 4px; border-radius: 3px;
       font-family: Consolas, monospace; font-size: 0.92em; }
blockquote { margin: 10px 0; padding: 10px 16px; background: #fbf3d9;
             border-left: 4px solid #9b7a1a; }
li { margin: 0 0 5px; }
hr { border: 0; border-top: 1px solid #dde5ee; margin: 22px 0; }
"""

MD_EXT = ["tables", "sane_lists", "attr_list"]


def md_to_html(text: str) -> str:
    return markdown.markdown(text, extensions=MD_EXT)


def diagram_block(name: str, lead_md: str = "") -> str:
    """Inline the hand-laid-out SVG for a diagram slide.

    Inlined rather than linked so the HTML is one self-contained file, and drawn
    at the slide's own size so nothing is scaled down (see make_diagrams.py for
    why these are not Mermaid).
    """
    svg = (DIAGRAMS / f"{name}.svg").read_text()
    svg = svg.split("?>", 1)[-1].strip()
    # The slide keeps its bullets above the picture, so a diagram slide still
    # reads in the template's bulleted format rather than as a bare figure.
    lead = f'<div class="lead">{md_to_html(lead_md)}</div>' if lead_md.strip() else ""
    return f'{lead}<div class="body diagram">{svg}</div>'


def screenshot_grid(shots: list[tuple[str, str]], lead_md: str = "") -> str:
    """Four captures in a 2x2 grid, skipping any that were not taken."""
    cells = []
    for filename, caption in shots:
        if not (HERE / "screenshots" / filename).exists():
            continue
        cells.append(
            f'<figure><img src="screenshots/{filename}" alt="{caption}">'
            f"<figcaption>{caption}</figcaption></figure>"
        )
    lead = f'<div class="lead">{md_to_html(lead_md)}</div>' if lead_md.strip() else ""
    if not cells:
        return lead + '<div class="body"><p><em>Screenshots pending capture.</em></p></div>'
    return lead + '<div class="body"><div class="shot">' + "".join(cells) + "</div></div>"


SHOTS = [
    ("dashboard-incidents.png", "Live dashboard: incidents as the stream emits them, with stream health"),
    ("incident-narrative.png", "One incident: events, severity, MITRE technique, LLM narrative"),
    ("bakeoff-grid.png", "The bake-off grid: the examiner picks attack and camouflage level"),
    ("bakeoff-scored.png", "Both systems scored live on the same firing"),
]


def split_slides(markdown_text: str) -> list[tuple[str, str]]:
    """Cut PRESENTATION.md into (title, body markdown) at each '# Slide N —' heading."""
    parts = re.split(r"^# Slide \d+ — ", markdown_text, flags=re.M)[1:]
    slides = []
    for part in parts:
        head, _, rest = part.partition("\n")
        # The numbers appendix follows the last slide; it is not a slide.
        rest = rest.split("\n## Numbers used in this deck")[0]
        # Strip only the trailing "---" separator, as whole lines. Stripping
        # the character would eat the leading dash of the first bullet and
        # silently turn a list into a paragraph.
        body = re.sub(r"(?:\n\s*-{3,}\s*)+$", "", rest.strip())
        slides.append((head.strip(), body.strip()))
    return slides


def density(body_md: str) -> str:
    """Shrink the type when a slide carries a lot of table."""
    rows = body_md.count("\n|")
    if rows > 12 or len(body_md) > 1800:
        return "tighter"
    if rows > 5 or len(body_md) > 1100:
        return "tight"
    return ""


def build_deck() -> Path:
    source = (HERE / "PRESENTATION.md").read_text()
    slides = split_slides(source)
    total = len(slides)
    html = [
        "<!doctype html><html><head><meta charset='utf-8'>",
        "<title>LLM-Based Log Anomaly Detector — 31 August 2026</title>",
        f"<style>{DECK_CSS}</style></head><body>",
    ]

    for index, (title, body_md) in enumerate(slides, start=1):
        # The template's own footer: department on the right with the slide
        # number, exactly as the 7 August deck carried it.
        footer = (
            '<div class="footer"><span></span>'
            f"<span>Department of Computer Engineering | SJCEM &nbsp;&nbsp; {index}</span>"
            "</div>"
        )
        if index == 1:
            html.append(
                '<section class="slide title-slide">'
                '<div class="trust">Aldel Education Trust&rsquo;s</div>'
                '<div class="college">St. John College of Engineering and '
                'Management, Palghar</div>'
                '<div class="naac">NAAC Accredited with Grade A+</div>'
                '<div class="dept">DEPARTMENT OF COMPUTER ENGINEERING</div>'
                '<hr class="band">'
                "<h1>LLM-Based Log Anomaly Detector</h1>"
                '<div class="sub">with Attack Narrative and Adversarial Robustness</div>'
                '<div class="who">Harsh Bangera (Roll No. 3)<br>'
                "Manas Chaudhari (Roll No. 17)<br>"
                "Krish Mendon (Roll No. 62)<br>"
                "Anandan Nair (Roll No. 68)</div>"
                '<div class="guide">Prof. Darshan Mhapsekar<br>31 August 2026</div>'
                f"{footer}</section>"
            )
            continue
        if title.lower().startswith("thank you"):
            html.append(
                '<section class="slide end-slide"><h1>Thank you</h1>'
                "<p style='font-size:24px;color:#4a5a6b'>Questions</p>"
                f"{footer}</section>"
            )
            continue

        if "Proposed Methodology" in title:
            body = diagram_block("methodology", body_md)
        elif "System Architecture" in title:
            body = diagram_block("architecture", body_md)
        elif "how the comparison is kept fair" in title:
            body = diagram_block("bakeoff", body_md)
        elif "Working system" in title:
            body = screenshot_grid(SHOTS, body_md)
        else:
            body = f'<div class="body {density(body_md)}">{md_to_html(body_md)}</div>'

        html.append(
            f'<section class="slide"><h1 class="slide-title">{title}</h1>'
            f'<div class="rule"></div>{body}{footer}</section>'
        )

    html.append("</body></html>")
    out = HERE / "deck.html"
    out.write_text("\n".join(html))
    return out


def build_doc(md_name: str, html_name: str, title: str) -> Path:
    body = md_to_html((HERE / md_name).read_text())
    out = HERE / html_name
    out.write_text(
        "<!doctype html><html><head><meta charset='utf-8'>"
        f"<title>{title}</title><style>{DOC_CSS}</style></head><body>{body}</body></html>"
    )
    return out


async def to_pdf(pages: list[tuple[Path, Path, bool]]) -> None:
    """Print each HTML file to PDF with the bundled Chromium.

    `slide_size` pages print at exactly one slide per page; documents print A4
    with margins from their own @page rule.
    """
    from playwright.async_api import async_playwright

    async with async_playwright() as p:
        browser = await p.chromium.launch()
        page = await browser.new_page(viewport={"width": SLIDE_W, "height": SLIDE_H})
        for html_path, pdf_path, is_slides in pages:
            await page.goto(html_path.as_uri())
            await page.emulate_media(media="print")
            if is_slides:
                await page.pdf(path=str(pdf_path), print_background=True,
                               width=f"{SLIDE_W}px", height=f"{SLIDE_H}px",
                               margin={"top": "0", "bottom": "0",
                                       "left": "0", "right": "0"})
            else:
                await page.pdf(path=str(pdf_path), print_background=True,
                               format="A4")
            print(f"  wrote {pdf_path.relative_to(HERE)}")
        await browser.close()


def main() -> None:
    what = sys.argv[1] if len(sys.argv) > 1 else "all"
    jobs = []
    if what in ("deck", "all"):
        jobs.append((build_deck(), HERE / "deck.pdf", True))
    if what in ("docs", "all"):
        for md_name, html_name, pdf_name, title in [
            ("KNOWLEDGE-PACK.md", "knowledge-pack.html", "KNOWLEDGE-PACK.pdf",
             "Knowledge Pack"),
            ("QA-PREP.md", "qa-prep.html", "QA-PREP.pdf", "Q&A Preparation"),
            ("references/REFERENCES.md", "references.html",
             "references/REFERENCES.pdf", "References"),
        ]:
            if (HERE / md_name).exists():
                jobs.append((build_doc(md_name, html_name, title),
                             HERE / pdf_name, False))
    asyncio.run(to_pdf(jobs))


if __name__ == "__main__":
    main()
