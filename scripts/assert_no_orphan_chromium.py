#!/usr/bin/env python3
"""Fail if any Chromium/headless-shell process is still running.

Run after real-browser tests, either on the CI host or inside the browser-worker
container. A leaked browser is a real defect: it holds memory and a session the
janitor believed it closed. Uses only /proc so it needs no extra tools.
"""

from __future__ import annotations

import sys
from pathlib import Path

_NEEDLES = ("chrome", "chromium", "headless_shell", "headless-shell")


def _orphans() -> list[str]:
    found: list[str] = []
    proc = Path("/proc")
    if not proc.is_dir():
        return found
    for entry in proc.iterdir():
        if not entry.name.isdigit():
            continue
        try:
            # Match the kernel process name, never the full command line. The old
            # implementation matched this script's own filename (and its parent
            # shell command), so the assertion failed even when no browser existed.
            # It also risked retaining browser profile arguments in memory.
            process_name = (entry / "comm").read_text(encoding="utf-8").strip()
        except OSError:
            continue
        lowered = process_name.casefold()
        if any(needle in lowered for needle in _NEEDLES):
            found.append(process_name or entry.name)
    return sorted(found)


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
