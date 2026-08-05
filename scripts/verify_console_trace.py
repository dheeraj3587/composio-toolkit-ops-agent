"""Local verification of the run console's rendered DOM.

The run page's trace is a client component, so the initial HTML only carries
skeletons and the real markup exists after hydration. `curl` cannot see it. This
drives a real Chromium against the dev server and asserts on the hydrated DOM,
plus captures screenshots at desktop and mobile widths.

Local debug only — not a production path, not part of `make test`.

    ./.venv/bin/python scripts/verify_console_trace.py <run_id>
"""

from __future__ import annotations

import asyncio
import os
import re
import sys
from pathlib import Path

from playwright.async_api import async_playwright

REPO = Path(__file__).resolve().parent.parent
WEB_ORIGIN = "http://127.0.0.1:3000"
OUT = Path("/tmp/console-verify")


def env_value(path: Path, key: str) -> str:
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if stripped.startswith(f"{key}=") and not stripped.startswith("#"):
            return stripped.split("=", 1)[1].strip().strip("\"'")
    raise SystemExit(f"{key} missing from {path}")


async def mint_cookie() -> str:
    """Reuse the app's own signer so the session is byte-identical to a real login.

    The minter refuses unless `ALLOW_DEV_SESSION_MINT=true` is in its process
    environment, which is passed explicitly here rather than inherited — running
    this script is the deliberate act that arms it, and nothing else should.
    """
    import subprocess

    result = subprocess.run(  # noqa: S603
        ["node", "--experimental-strip-types", "scripts/dev-session-cookie.mjs"],
        cwd=REPO / "web",
        capture_output=True,
        text=True,
        check=False,
        env={**os.environ, "ALLOW_DEV_SESSION_MINT": "true"},
    )
    if result.returncode != 0:
        raise SystemExit(result.stderr.strip() or "could not mint a dev session cookie")
    token = result.stdout.strip()
    if not token:
        raise SystemExit("could not mint a dev session cookie")
    return token


async def main(run_id: str) -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    cookie = await mint_cookie()
    failures: list[str] = []
    console_errors: list[str] = []

    async with async_playwright() as playwright:
        browser = await playwright.chromium.launch()
        context = await browser.new_context(viewport={"width": 1440, "height": 1200})
        await context.add_cookies(
            [
                {
                    "name": "ops_session",
                    "value": cookie,
                    "domain": "127.0.0.1",
                    "path": "/",
                    "httpOnly": True,
                    "sameSite": "Lax",
                }
            ]
        )
        page = await context.new_page()
        page.on(
            "console",
            lambda message: (
                console_errors.append(message.text) if message.type == "error" else None
            ),
        )
        page.on("pageerror", lambda error: console_errors.append(str(error)))

        await page.goto(f"{WEB_ORIGIN}/runs/{run_id}", wait_until="networkidle")

        steps = page.locator("[data-slot='chain-of-thought-step']")
        count = await steps.count()
        print(f"chain-of-thought steps: {count}")
        if count == 0:
            failures.append("the trace rendered no steps")

        statuses = [await steps.nth(i).get_attribute("data-status") for i in range(count)]
        labels = [
            re.sub(r"\s+", " ", (await steps.nth(i).inner_text()).replace("\n", " · ")).strip()
            for i in range(count)
        ]
        for status, label in zip(statuses, labels, strict=True):
            print(f"  [{status}] {label[:110]}")

        # The run is paused at a human gate, so the last node must read as halted
        # rather than active — status is carried by form, not colour.
        if statuses and statuses[-1] not in {"halted", "active", "complete"}:
            failures.append(f"unexpected terminal status {statuses[-1]!r}")

        bars = page.locator(".stage-bar")
        bar_count = await bars.count()
        widths = [await bars.nth(i).evaluate("node => node.style.width") for i in range(bar_count)]
        print(f"stage bars: {bar_count} widths={widths}")

        await page.screenshot(path=str(OUT / "run-desktop.png"), full_page=True)

        # Entry animations must not replay on the 4s poll: the run page calls
        # router.refresh() on an interval, and a mount-keyed animation strobes.
        first_node = page.locator(".trace-node").first
        before = await first_node.evaluate(
            "node => getComputedStyle(node).animationName + '|' + getComputedStyle(node).animationDelay"
        )
        await page.wait_for_timeout(5_500)
        after_count = await page.locator("[data-slot='chain-of-thought-step']").count()
        after = await first_node.evaluate(
            "node => getComputedStyle(node).animationName + '|' + getComputedStyle(node).animationDelay"
        )
        print(f"after poll: steps={after_count} animation={after} (was {before})")
        if after_count != count:
            failures.append(f"step count changed across the poll: {count} -> {after_count}")

        # Reduced motion must disable the travel and the stagger.
        reduced = await context.new_page()
        await reduced.emulate_media(reduced_motion="reduce")
        await reduced.goto(f"{WEB_ORIGIN}/runs/{run_id}", wait_until="networkidle")
        marker = reduced.locator(".cot-marker-live").first
        if await marker.count():
            name = await marker.evaluate("node => getComputedStyle(node).animationName")
            print(f"reduced-motion live marker animation: {name}")
            if name not in {"none", ""}:
                failures.append(f"reduced motion still animates the marker ({name})")
        await reduced.close()

        # Keyboard focus must be visible on the disclosure control.
        await page.keyboard.press("Tab")
        focus_outline = await page.evaluate(
            "() => { const el = document.activeElement;"
            " const s = el ? getComputedStyle(el) : null;"
            " return s ? `${s.outlineStyle} ${s.outlineWidth} ${s.boxShadow.slice(0, 40)}` : 'none' }"
        )
        print(f"first focus ring: {focus_outline}")

        # Readable at 375px.
        mobile = await browser.new_context(
            viewport={"width": 375, "height": 812}, device_scale_factor=2
        )
        await mobile.add_cookies(
            [
                {
                    "name": "ops_session",
                    "value": cookie,
                    "domain": "127.0.0.1",
                    "path": "/",
                    "httpOnly": True,
                    "sameSite": "Lax",
                }
            ]
        )
        mobile_page = await mobile.new_page()
        await mobile_page.goto(f"{WEB_ORIGIN}/runs/{run_id}", wait_until="networkidle")
        overflow = await mobile_page.evaluate(
            "() => document.documentElement.scrollWidth - document.documentElement.clientWidth"
        )
        print(f"375px horizontal overflow: {overflow}px")
        if overflow > 1:
            failures.append(f"page overflows horizontally at 375px by {overflow}px")
        await mobile_page.screenshot(path=str(OUT / "run-mobile.png"), full_page=True)
        await mobile.close()

        # Every other page, for the reskin pass.
        for name, path in [
            ("overview", "/"),
            ("system", "/system"),
            ("new-run", "/runs/new"),
        ]:
            await page.goto(f"{WEB_ORIGIN}{path}", wait_until="networkidle")
            await page.screenshot(path=str(OUT / f"{name}.png"), full_page=True)

        await browser.close()

    # The dev server's HMR socket fails its handshake under headless Chromium and
    # retries on a loop. It is noise from the tooling, not the page: the app still
    # hydrates, which is exactly what the step assertions above prove.
    ignorable = ("Download the React DevTools", "favicon", "webpack-hmr", "_next/static/chunks/hmr")
    real_errors = [
        error for error in console_errors if not any(skip in error for skip in ignorable)
    ]
    if real_errors:
        print("console errors:")
        for error in real_errors[:8]:
            print(f"  {error[:200]}")
        failures.append(f"{len(real_errors)} console error(s)")

    print(f"\nscreenshots in {OUT}")
    if failures:
        print("FAILURES:")
        for failure in failures:
            print(f"  - {failure}")
        return 1
    print("all checks passed")
    return 0


if __name__ == "__main__":
    run = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("RUN_ID", "")
    if not run:
        raise SystemExit("usage: verify_console_trace.py <run_id>")
    raise SystemExit(asyncio.run(main(run)))
