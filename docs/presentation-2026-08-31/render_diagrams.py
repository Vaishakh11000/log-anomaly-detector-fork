"""
render_diagrams.py
Renders each diagrams/*.mmd on its own, reports the aspect ratio it comes out at,
and saves a PNG.

Why separately from the deck build: a Mermaid graph whose natural shape is much
wider than a slide scales down until the labels are unreadable, and that is only
visible after a full export. Rendering one diagram at a time makes the shape
measurable in seconds, so the layout can be fixed before it reaches a slide.

    curl -sL https://cdn.jsdelivr.net/npm/mermaid@10.9.1/dist/mermaid.min.js \
         -o docs/presentation-2026-08-31/diagrams/mermaid.min.js
    uv run python docs/presentation-2026-08-31/render_diagrams.py

The library itself is not kept in git -- it is 3.2MB of vendored JavaScript for
a renderer the deck does not use. The .mmd files stay because they are the
evidence behind that decision: run this and it reports the aspect ratios that
ruled Mermaid out (6.9:1 and 0.6:1 against a slide area of 1.9:1).
"""

import asyncio
from pathlib import Path

HERE = Path(__file__).resolve().parent
DIAGRAMS = HERE / "diagrams"

PAGE = """<!doctype html><html><head><meta charset="utf-8"><style>
body{{margin:0;background:#fff;font-family:"Segoe UI",Arial,sans-serif}}
</style></head><body><pre class="mermaid">{src}</pre>
<script>{lib}</script>
<script>mermaid.initialize({{startOnLoad:true,theme:'base',
flowchart:{{useMaxWidth:false,htmlLabels:true,curve:'basis',nodeSpacing:38,rankSpacing:46}},
themeVariables:{{fontFamily:'Segoe UI, Helvetica Neue, Arial',fontSize:'16px'}}}});</script>
</body></html>"""


async def main() -> None:
    from playwright.async_api import async_playwright

    lib = (DIAGRAMS / "mermaid.min.js").read_text()
    async with async_playwright() as p:
        browser = await p.chromium.launch()
        page = await browser.new_page(viewport={"width": 2200, "height": 1400})
        for mmd in sorted(DIAGRAMS.glob("*.mmd")):
            html = DIAGRAMS / f".{mmd.stem}.preview.html"
            html.write_text(PAGE.format(src=mmd.read_text().strip(), lib=lib))
            await page.goto(html.as_uri())
            await page.wait_for_selector("pre.mermaid svg", timeout=30000)
            box = await page.evaluate(
                "() => { const s = document.querySelector('pre.mermaid svg');"
                "const r = s.getBoundingClientRect();"
                "return {w: Math.round(r.width), h: Math.round(r.height)}; }")
            ratio = box["w"] / max(box["h"], 1)
            fit = "ok" if 1.3 <= ratio <= 2.6 else "TOO WIDE" if ratio > 2.6 else "TOO TALL"
            print(f"{mmd.stem:14s} {box['w']:5d} x {box['h']:5d}  "
                  f"aspect {ratio:4.2f}  {fit}   (slide area is about 1.9)")
            element = await page.query_selector("pre.mermaid svg")
            await element.screenshot(path=str(DIAGRAMS / f"{mmd.stem}.png"))
            html.unlink()
        await browser.close()


if __name__ == "__main__":
    asyncio.run(main())
