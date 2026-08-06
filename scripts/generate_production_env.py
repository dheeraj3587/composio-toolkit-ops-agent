#!/usr/bin/env python3
"""Fill .env.production.example from the local .env plus fresh machine secrets.

Three rules decide every value, and the reason each one exists is the reason the
generated file is safe to deploy:

* Provider credentials and the operator login are COPIED from ``.env``. They
  identify real external accounts, so regenerating them would produce a file
  that authenticates as nobody.
* Machine-only tokens and storage keys are GENERATED fresh. A development secret
  promoted into production silently widens the blast radius of a leaked laptop,
  and nothing outside this deployment needs to recognize these values.
* Host-specific values are left as explicit placeholders. Guessing a domain
  would produce a file that looks complete and fails at TLS issuance.

Secrets never reach stdout: the summary prints variable names and a category,
never a value.
"""

from __future__ import annotations

import os
import re
import secrets
import sys
from pathlib import Path

from cryptography.fernet import Fernet

ROOT = Path(__file__).resolve().parent.parent
TEMPLATE = ROOT / ".env.production.example"
LOCAL = ROOT / ".env"
TARGET = ROOT / ".env.production"

ASSIGNMENT = re.compile(r"^([A-Z_][A-Z0-9_]*)=(.*)$")

# Copied from .env: these name real external accounts.
COPY_FROM_LOCAL = frozenset(
    {
        "PERPLEXITY_API_KEY",
        "GOOGLE_GENAI_API_KEY",
        "GEMINI_MODEL",
        "OPENROUTER_API_KEY",
        "OPENROUTER_MODEL",
        "CEREBRAS_API_KEY",
        "CEREBRAS_MODEL",
        "GROQ_API_KEY",
        "GROQ_MODEL",
        # Mercury leads every inference chain in this system, and it was the one
        # provider this set left out — so a key added to .env was dropped on the
        # next regeneration and reported as "left at template defaults" rather
        # than as missing. The deployment then ran its primary provider blank and
        # silently started at the second one.
        "MERCURY_API_KEY",
        "MERCURY_MODEL",
        "MERCURY_REASONING_EFFORT",
        "COMPOSIO_API_KEY",
        "COMPOSIO_USER_ID",
        "COMPOSIO_GMAIL_API_KEY",
        "COMPOSIO_GMAIL_USER_ID",
        "COMPOSIO_GMAIL_SIGNUP_CONNECTED_ACCOUNT_ID",
        "COMPOSIO_GMAIL_CONNECTED_ACCOUNT_ID",
        "GMAIL_SIGNUP_ADDRESS",
        "YDC_API_KEY",
        "OPS_AUTH_USERNAME",
        "OPS_AUTH_PASSWORD",
        "OUTREACH_RECIPIENT_OVERRIDE",
    }
)

# Generated fresh: nothing outside this deployment needs to recognize them.
# 48 URL-safe bytes comfortably clears every 32-character minimum in
# ops/core/config.py and contains no placeholder marker.
GENERATE_TOKEN = frozenset(
    {
        "OPS_INTERNAL_API_TOKEN",
        "OPS_AUTH_SESSION_SECRET",
        "BROWSER_SERVICE_TOKEN",
        "BROWSER_SESSION_CAPABILITY_KEY",
        "BROWSER_SECRET_BROKER_TOKEN",
    }
)

# Placeholders that only the host owner can resolve.
NEEDS_OWNER = {
    "DOMAIN": "REPLACE-ME.example",
    "ACME_EMAIL": "",
    "OPS_CORS_ORIGINS": "https://REPLACE-ME.example",
    "MANAGED_AUTH_CALLBACK_BASE_URL": "https://REPLACE-ME.example",
}


def read_env(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        match = ASSIGNMENT.match(stripped)
        if match is None:
            continue
        # Strip a trailing "# pragma: allowlist secret"-style comment the way a
        # shell would not, because these values are read by python-dotenv.
        values[match.group(1)] = match.group(2).split(" #", 1)[0].strip()
    return values


def main() -> int:
    local = read_env(LOCAL)
    generated: list[str] = []
    copied: list[str] = []
    owner: list[str] = []
    kept: list[str] = []
    missing: list[str] = []

    out: list[str] = []
    for line in TEMPLATE.read_text(encoding="utf-8").splitlines():
        match = ASSIGNMENT.match(line)
        if match is None:
            out.append(line)
            continue
        name = match.group(1)

        if name in NEEDS_OWNER:
            out.append(f"{name}={NEEDS_OWNER[name]}")
            owner.append(name)
        elif name in GENERATE_TOKEN:
            out.append(f"{name}={secrets.token_urlsafe(48)}")
            generated.append(name)
        elif name == "SECRET_VAULT_KEY":
            out.append(f"{name}={Fernet.generate_key().decode('ascii')}")
            generated.append(name)
        elif name == "LANGGRAPH_AES_KEY":
            # Exactly 32 UTF-8 bytes, per docs/OPERATIONS.md:107.
            out.append(f"{name}={secrets.token_urlsafe(64)[:32]}")
            generated.append(name)
        elif name in COPY_FROM_LOCAL and local.get(name):
            out.append(f"{name}={local[name]}")
            copied.append(name)
        else:
            out.append(line)
            if name in COPY_FROM_LOCAL:
                missing.append(name)
            else:
                kept.append(name)

    # Create at 0600 before any byte is written, rather than writing and then
    # chmod-ing: scripts/deploy-droplet.sh refuses an .env.production that ever
    # grants group or other access, and a two-step write leaves a window where a
    # umask-derived mode is briefly readable.
    handle = os.open(TARGET, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(handle, "w", encoding="utf-8") as stream:
        stream.write("\n".join(out) + "\n")
    TARGET.chmod(0o600)

    def show(label: str, names: list[str]) -> None:
        print(f"\n{label} ({len(names)})")
        for name in names:
            print(f"  {name}")

    print(f"wrote {TARGET.relative_to(ROOT)} mode 0600")
    show("generated fresh", generated)
    show("copied from .env", copied)
    show("MUST be set by the host owner", owner)
    show("blank in .env, left at the template default", missing)
    print(f"\nleft at template defaults ({len(kept)})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
