"""Create one live signup run against the local control plane and watch it.

A soft-launch smoke test, not a test-suite addition: it drives the same public
API the operator UI drives, so what it proves is what the UI would do.

Usage: ./.venv/bin/python scripts/fire_signup_run.py <app_name> [work_email_slug]
"""

from __future__ import annotations

import json
import secrets
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

BASE = "http://127.0.0.1:8000"
TERMINAL = {"completed", "blocked", "failed", "waiting_for_hitl", "configuration_required"}


def internal_token() -> str:
    """Read the internal API token without printing any secret value."""

    for line in Path(".env").read_text(encoding="utf-8").splitlines():
        if line.startswith("OPS_INTERNAL_API_TOKEN="):
            return line.split("=", 1)[1].strip().strip('"')
    raise SystemExit("OPS_INTERNAL_API_TOKEN is not set in .env")


def call(method: str, path: str, token: str, body: dict | None = None) -> tuple[int, dict]:
    data = json.dumps(body).encode() if body is not None else None
    headers = {"X-Ops-Internal-Token": token}
    if data is not None:
        headers["Content-Type"] = "application/json"
        headers["Idempotency-Key"] = "idem_" + secrets.token_hex(16)
    request = urllib.request.Request(BASE + path, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request) as response:
            return response.status, json.load(response)
    except urllib.error.HTTPError as error:
        return error.code, {"error": error.read().decode()[:2000]}


def main() -> int:
    app_name = sys.argv[1] if len(sys.argv) > 1 else "Apify"
    slug = sys.argv[2] if len(sys.argv) > 2 else app_name.lower()
    token = internal_token()
    status, detail = call(
        "POST",
        "/api/runs",
        token,
        {
            "app_name": app_name,
            "account_mode": "create_account",
            "browser_provider": "playwright",
            "credential_creation_policy": "create_if_missing",
            "execution_mode": "execute_when_configured",
            "dry_run": False,
            "requested_scope_policy": "maximum",
            "provider_setup": {},
            "company": {
                "legal_name": "Composio Toolkit Ops",
                "website": "https://composio.dev",
                "work_email_ref": f"vault://company/work_email/{slug}",
                "use_case": f"Evaluate {app_name} for automated app onboarding research.",
                "callback_urls": [],
            },
        },
    )
    if status != 201:
        print(f"create failed: HTTP {status}\n{detail.get('error') or detail}")
        return 1
    run_id = detail.get("run_id") or (detail.get("run") or {}).get("run_id")
    if not run_id:
        print(json.dumps(detail, indent=2)[:2000])
        return 1
    print(f"{run_id}  {detail.get('status')}")

    seen = 0
    for _ in range(180):
        _, record = call("GET", f"/api/runs/{run_id}", token)
        _, timeline = call("GET", f"/api/runs/{run_id}/timeline", token)
        events = timeline.get("events") or timeline.get("items") or []
        for event in events[seen:]:
            print(
                "   ",
                event.get("created_at", "")[:19],
                event.get("kind") or event.get("event"),
                event.get("reason_code") or event.get("summary") or "",
            )
        seen = len(events)
        state = record.get("status")
        if state in TERMINAL:
            hitl = record.get("hitl_request") or {}
            print(f"\n{state}  {hitl.get('type') or ''}  {hitl.get('reason_code') or ''}")
            print(hitl.get("instruction") or "")
            return 0
        time.sleep(5)
    print("still running after 15 minutes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
