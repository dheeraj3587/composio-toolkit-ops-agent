#!/usr/bin/env python3
"""Fail if any Chromium/headless-shell process is still running.

Run INSIDE the browser-worker container after the tests. A leaked browser is a
real defect: it holds memory and a session the janitor believed it closed. Uses
only /proc so it needs no extra tools in the image.
"""

from __future__ import annotations

import sys
from pathlib import Path

_NEEDLES = ("chrome", "chromium", "headless_shell")


def _orphans() -> list[str]:
    found: list[str] = []
    proc = Path("/proc")
    if not proc.is_dir():
        return found
    for entry in proc.iterdir():
        if not entry.name.isdigit():
            continue
        try:
            cmdline = (
                (entry / "cmdline").read_bytes().replace(b"\x00", b" ").decode("utf-8", "replace")
            )
        except OSError:
            continue
        lowered = cmdline.casefold()
        if any(needle in lowered for needle in _NEEDLES):
            # Report the executable name only, never full args (which could carry
            # a profile path).
            found.append(cmdline.split(" ", 1)[0] or entry.name)
    return found


def main() -> int:
    orphans = _orphans()
    if orphans:
        print(f"orphaned browser processes remain: {len(orphans)}", file=sys.stderr)
        for name in orphans:
            print(f"  {name}", file=sys.stderr)
        return 1
    print("no orphaned Chromium processes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
