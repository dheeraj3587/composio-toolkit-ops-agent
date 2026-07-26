"""Sanitized production smoke for the Pipedrive login classification.

Runs INSIDE the browser-worker container against the real vendor with no
credentials, and prints only the three classification fields plus the session
lifecycle. It never prints page content, and it always deletes the session it
created so the single interactive slot is not left held.
"""

from __future__ import annotations

import json
import os
import urllib.request

BASE = "http://127.0.0.1:8081"
HEADERS = {
    "X-Browser-Service-Token": os.environ["BROWSER_SERVICE_TOKEN"],
    "X-Browser-Session-Owner": "production-smoke",
    "Content-Type": "application/json",
}


def call(path: str, payload: object | None = None, method: str = "POST") -> dict[str, object]:
    body = json.dumps(payload).encode() if payload is not None else None
    request = urllib.request.Request(BASE + path, data=body, headers=HEADERS, method=method)
    with urllib.request.urlopen(request, timeout=240) as response:  # noqa: S310 - loopback
        return json.load(response)


def main() -> None:
    from ops.p1_adapter import P1OperationalAdapter, to_operational_research

    found = P1OperationalAdapter().lookup("Pipedrive")
    research = to_operational_research(found.record).model_copy(
        update={
            "login_url": "https://app.pipedrive.com/auth/login",
            "credential_management_url": "https://app.pipedrive.com/settings/api",
        }
    )
    created = call(
        "/internal/browser/sessions",
        {"app_slug": "pipedrive", "secret_scope": "production-classifier-smoke"},
    )
    session_id = str(created["session_id"])
    print("session_created", flush=True)
    try:
        observation = call(
            f"/internal/browser/sessions/{session_id}/navigate",
            {
                "research": research.model_dump(mode="json"),
                "credential_refs": {},
                "credential_creation_policy": "reuse_only",
            },
        )
        print(
            json.dumps(
                {
                    "status": observation.get("status"),
                    "human_action_type": observation.get("human_action_type"),
                    "reason_code": observation.get("reason_code"),
                },
                sort_keys=True,
            ),
            flush=True,
        )
    finally:
        call(f"/internal/browser/sessions/{session_id}", None, "DELETE")
        print("session_deleted", flush=True)


if __name__ == "__main__":
    main()
