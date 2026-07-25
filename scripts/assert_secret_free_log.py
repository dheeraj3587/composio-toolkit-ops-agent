#!/usr/bin/env python3
"""Fail if the browser-service log contains anything that looks like a secret.

A defence-in-depth CI check: the service is designed never to log tokens,
cookies, storage state or credential values, and this asserts it against the
actual captured log. It matches the CI service token and common credential
shapes without ever echoing a matched value.
"""

from __future__ import annotations

import os
import re
import sys

# Patterns that must never appear in a service log line.
_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("fernet_key", re.compile(r"\bg[A-Za-z0-9_-]{42}=\b")),
    ("vault_reference", re.compile(r"vault://[a-z0-9-]+/[a-z0-9_-]+/[A-Za-z0-9_-]+")),
    ("cookie_header", re.compile(r"(?i)set-cookie:")),
    ("bearer_token", re.compile(r"(?i)bearer\s+[A-Za-z0-9._-]{16,}")),
    ("storage_state", re.compile(r'"cookies"\s*:\s*\[')),
)


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: assert_secret_free_log.py <logfile>", file=sys.stderr)
        return 2
    try:
        text = open(sys.argv[1], encoding="utf-8", errors="replace").read()
    except OSError as exc:
        print(f"could not read log: {type(exc).__name__}", file=sys.stderr)
        return 2

    offenders: list[str] = []
    # The CI-only service token is passed via the environment; match it literally.
    ci_token = os.environ.get("BROWSER_SERVICE_TOKEN", "")
    if ci_token and ci_token in text:
        offenders.append("service_token")
    for name, pattern in _PATTERNS:
        if pattern.search(text):
            offenders.append(name)

    if offenders:
        # Report the CATEGORY only, never the matched text.
        print(
            f"service log contains secret-shaped content: {', '.join(offenders)}", file=sys.stderr
        )
        return 1
    print("service log is free of secret-shaped content")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
