"""
capture_screenshots.py
Takes the deck's screenshots from the system while it is actually running.

Nothing here is mocked: the dashboard is the real Streamlit page reading the
real FastAPI service, and the bake-off grid is the real page that drives the
injector and the Wazuh container. A deck that shows a drawing of a dashboard
invites the question of whether the dashboard exists.

Prerequisites, in this order:
    uv run logdet-api                                        # service
    curl -X POST localhost:8000/stream/start ... synthetic.log --once
    uv run streamlit run src/logdet/dashboard.py --server.port 8501
    uv run streamlit run src/logdet_eval/bakeoff_dashboard.py --server.port 8502

    uv run python docs/presentation-2026-08-31/capture_screenshots.py dashboard
    uv run python docs/presentation-2026-08-31/capture_screenshots.py grid
"""

import asyncio
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
SHOTS = HERE / "screenshots"
VIEWPORT = {"width": 1500, "height": 950}


async def settle(page, seconds: float = 3.0) -> None:
    """Streamlit paints in several passes; give the rerun time to land."""
    await page.wait_for_timeout(int(seconds * 1000))


async def dashboard_shots() -> None:
    from playwright.async_api import async_playwright

    async with async_playwright() as playwright:
        browser = await playwright.chromium.launch()
        page = await browser.new_page(viewport=VIEWPORT, device_scale_factor=2)
        await page.goto("http://127.0.0.1:8501", wait_until="networkidle")
        await settle(page, 6)
        await page.screenshot(path=str(SHOTS / "dashboard-incidents.png"))
        print("  dashboard-incidents.png")

        # Open the first incident, then ask for its narrative.
        # The sidebar has expanders too; pick the incident rows by their text.
        summaries = page.locator("summary").filter(has_text="event(s)")
        if await summaries.count():
            await summaries.first.click()
            await settle(page, 3)
        narrate = page.get_by_role("button", name="Narrate now")
        if await narrate.count():
            await narrate.first.click()
            print("  waiting for the local LLM ...")
            for _ in range(24):
                await settle(page, 5)
                if await page.locator("text=LLM narrative").count():
                    body = await page.inner_text("body")
                    if "Not narrated yet" not in body:
                        break
        await settle(page, 2)
        # Frame the opened incident rather than the top of the page.
        if await summaries.count():
            await summaries.first.scroll_into_view_if_needed()
            await settle(page, 1)
        await page.screenshot(path=str(SHOTS / "incident-narrative.png"))
        print("  incident-narrative.png")
        await browser.close()


async def grid_shots() -> None:
    """Open the grid, photograph the quiet stream, then fire two real cells.

    The pair fired is `enumeration` at `none` and then at `rephrase`. It is the
    cheapest honest pair on the grid -- the attack spans 42 seconds of real time
    against impossible travel's 15 minutes per instance -- and it still shows
    the mechanism: rewording costs Wazuh most of the attack's lines while ours
    holds (results/bakeoff/bakeoff.md).
    """
    from playwright.async_api import async_playwright

    async def wait_until_quiet(page, minutes: float = 12) -> None:
        for _ in range(int(minutes * 6)):
            await settle(page, 10)
            body = await page.inner_text("body")
            if "Quiet stream" in body or "Last firing failed" in body:
                return
        print("  ! still firing after the wait; screenshotting anyway")

    async with async_playwright() as playwright:
        browser = await playwright.chromium.launch()
        page = await browser.new_page(viewport=VIEWPORT, device_scale_factor=2)
        await page.goto("http://127.0.0.1:8502", wait_until="networkidle")
        await settle(page, 5)

        open_button = page.get_by_role("button", name="Open the stream")
        if await open_button.count():
            await open_button.first.click()
            # Opening resets Wazuh's correlation state, which restarts analysisd
            # and takes ~30s before the page comes back with the grid.
            print("  opening the stream (Wazuh restart takes ~30s) ...")
            for _ in range(24):
                await settle(page, 8)
                if "Quiet stream" in await page.inner_text("body"):
                    break

        await page.screenshot(path=str(SHOTS / "bakeoff-grid.png"))
        print("  bakeoff-grid.png")

        # Fire buttons are laid out attack-major: 3 attacks x 6 levels.
        levels = ["none", "mimicry", "rephrase", "ip_rotate", "slow", "realistic-combo"]
        attacks = ["brute_force", "impossible_travel", "enumeration"]

        for level in ("none", "rephrase"):
            index = attacks.index("enumeration") * len(levels) + levels.index(level)
            buttons = page.get_by_role("button", name="Fire")
            if await buttons.count() <= index:
                print("  ! grid not rendered as expected")
                break
            print(f"  firing enumeration / {level} ...", flush=True)
            await buttons.nth(index).click()
            await settle(page, 5)
            await wait_until_quiet(page)

        await settle(page, 3)
        await page.screenshot(path=str(SHOTS / "bakeoff-scored.png"), full_page=True)
        print("  bakeoff-scored.png")
        await browser.close()


if __name__ == "__main__":
    SHOTS.mkdir(exist_ok=True)
    which = sys.argv[1] if len(sys.argv) > 1 else "dashboard"
    asyncio.run(dashboard_shots() if which == "dashboard" else grid_shots())
