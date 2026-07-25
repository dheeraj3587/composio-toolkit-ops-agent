#!/usr/bin/env python3
"""Poll the browser service's readiness endpoint until it is up, or time out.

Used by the browser-image CI job after `docker compose up -d browser-worker`. It
calls the CACHED readiness endpoint (which does not launch a browser per request),
so polling it frequently is cheap.

Exit 0 when the service reports a healthy readiness state; non-zero on timeout.
Never prints secrets — only the sanitized state string.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.error
import urllib.request

_HEALTHY = {"ready", "configured_not_verified", "capacity_exhausted"}


def _probe(url: str) -> str | None:
    try:
        with urllib.request.urlopen(url, timeout=10) as response:  # noqa: S310 - fixed local URL
            payload = json.load(response)
    except (urllib.error.URLError, TimeoutError, ValueError):
        return None
    state = payload.get("state")
    return state if isinstance(state, str) else None


def main() -> int:
    parser = argparse.ArgumentParser(description="Wait for the browser service to be ready.")
    parser.add_argument("--url", default="http://127.0.0.1:8081/internal/ready")
    parser.add_argument("--timeout", type=float, default=90.0)
    args = parser.parse_args()

    deadline = time.monotonic() + args.timeout
    last = "no_response"
    while time.monotonic() < deadline:
        state = _probe(args.url)
        if state is not None:
            last = state
            print(f"browser-service state: {state}", flush=True)
            if state in _HEALTHY:
                return 0
            if state == "not_configured":
                print("browser-service refused: token not configured", file=sys.stderr)
                return 1
        time.sleep(2.0)
    print(
        f"browser-service did not become ready in {args.timeout}s (last: {last})", file=sys.stderr
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
