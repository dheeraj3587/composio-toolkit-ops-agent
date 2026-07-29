#!/usr/bin/env python3
"""Fail if a service log contains anything that looks like a secret.

A defence-in-depth CI check: the service is designed never to log tokens,
cookies, storage state or credential values, and this asserts it against the
actual captured log. It matches every configured secret-like environment value
and common credential shapes without ever echoing a matched value.
"""

from __future__ import annotations

import os
import re
import sys

# Patterns that must never appear in a service log line. A Fernet key is 32
# bytes encoded as 43 URL-safe base64 characters plus ``=``. The lookarounds
# deliberately do not use ``\b``: there is no word boundary after ``=``.
_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "fernet_key",
        re.compile(r"(?<![A-Za-z0-9_-])[A-Za-z0-9_-]{43}=(?![A-Za-z0-9_=-])"),
    ),
    ("fernet_token", re.compile(r"(?<![A-Za-z0-9_-])gAAAAA[A-Za-z0-9_-]{32,}={0,2}")),
    ("vault_reference", re.compile(r"vault://[a-z0-9-]+/[a-z0-9_-]+/[A-Za-z0-9_-]+")),
    ("cookie_header", re.compile(r"(?i)set-cookie:")),
    ("bearer_token", re.compile(r"(?i)bearer\s+[A-Za-z0-9._-]{16,}")),
    ("storage_state", re.compile(r'"cookies"\s*:\s*\[')),
    (
        "provider_key",
        re.compile(
            r"(?<![A-Za-z0-9_-])(?:"
            r"AIza[0-9A-Za-z_-]{20,}|"
            r"(?:sk-or-v1-|gsk_|pplx-|ydc-sk-|bu_|ak_|csk-)[A-Za-z0-9_-]{16,}"
            r")(?![A-Za-z0-9_-])"
        ),
    ),
)

_SECRET_ENV_NAME = re.compile(
    r"(?:^|_)(?:API_KEY|TOKEN|KEY|SECRET|PASSWORD|PRIVATE_KEY)$", re.IGNORECASE
)


def _configured_secret_values() -> tuple[str, ...]:
    """Return configured secret values without retaining their variable names."""

    values: set[str] = set()
    for name, value in os.environ.items():
        if _SECRET_ENV_NAME.search(name) and len(value) >= 8:
            values.add(value)
    return tuple(values)


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: assert_secret_free_log.py <logfile>", file=sys.stderr)
        return 2
    try:
        text = open(sys.argv[1], encoding="utf-8", errors="replace").read()
    except OSError as exc:
        print(f"could not read log: {type(exc).__name__}", file=sys.stderr)
        return 2

    offenders: set[str] = set()
    if any(secret in text for secret in _configured_secret_values()):
        offenders.add("configured_environment_secret")
    for name, pattern in _PATTERNS:
        if pattern.search(text):
            offenders.add(name)

    if offenders:
        # Report the CATEGORY only, never the matched text.
        print(
            f"service log contains secret-shaped content: {', '.join(sorted(offenders))}",
            file=sys.stderr,
        )
        return 1
    print("service log is free of secret-shaped content")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
