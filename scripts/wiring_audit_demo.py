"""Print the sanitized startup wiring audit with placeholder keys.

No provider network call is made: the SDK clients are constructed lazily and
this script only proves that configured settings inject the real runtime
classes. Secret values are never printed.
"""

from __future__ import annotations

import secrets
import tempfile
from pathlib import Path

from cryptography.fernet import Fernet

from ops.config import Settings
from ops.run_service import RunService


def main() -> None:
    tmp = Path(tempfile.mkdtemp())
    env = {
        "PERPLEXITY_API_KEY": "pplx-PLACEHOLDER",  # pragma: allowlist secret
        "GOOGLE_GENAI_API_KEY": "gm-PLACEHOLDER",  # pragma: allowlist secret
        "COMPOSIO_API_KEY": "comp-PLACEHOLDER",  # pragma: allowlist secret
        "BROWSER_USE_API_KEY": "bu-PLACEHOLDER",  # pragma: allowlist secret
        "SECRET_VAULT_KEY": Fernet.generate_key().decode(),  # pragma: allowlist secret
        "LANGGRAPH_AES_KEY": secrets.token_hex(16),  # pragma: allowlist secret
        "COMPOSIO_GMAIL_CONNECTED_ACCOUNT_ID": "acct-PLACEHOLDER",
        "OUTREACH_RECIPIENT_OVERRIDE": "owner@example.com",
        "ALLOW_LIVE_BROWSER": "true",
        "OPS_DB_PATH": str(tmp / "ops.db"),
        "CHECKPOINT_DB_PATH": str(tmp / "checkpoints.db"),
        "SECRET_VAULT_DB_PATH": str(tmp / "vault.db"),
        "PROVIDER_EFFECTS_DB_PATH": str(tmp / "effects.db"),
    }
    settings = Settings.from_env(env=env)
    svc = RunService.from_paths(db_path=tmp / "ops.db", settings=settings)
    svc.startup()
    header = "{:<21} | {:<32} | {:<10} | {}".format(
        "dependency", "class", "configured", "runtime_wired"
    )
    print("SANITIZED STARTUP WIRING AUDIT (placeholder keys, no network calls)")
    print(header)
    print("-" * len(header))
    for row in svc.wiring_audit():
        print(
            "{:<21} | {:<32} | {!s:<10} | {!s}".format(
                row["dependency"],
                str(row["class"]),
                row["configured"],
                row["runtime_wired"],
            )
        )
    svc.shutdown()


if __name__ == "__main__":
    main()
