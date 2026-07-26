"""Probe the PRODUCTION ASGI entry point and print its run-detail projection.

Run as a subprocess, never imported by the test session. Importing ``api.main``
applies the production monkeypatches (assignment runtime, live bootstrap and
projection) to shared classes for the lifetime of the process, so doing it inside
the suite would silently change which code path every later test exercises. A
separate process is the only way to assert real production behavior without
contaminating the rest of the run.

Prints one JSON line: the run-detail payload, or ``{"error": ...}``.
"""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

_PAYLOAD = {
    "app_name": "Pipedrive",
    "company": {
        "legal_name": "Example Company",
        "website": "https://example.test",
        "work_email_ref": "vault://company/work_email/test-operator",
        "use_case": "Evaluate documented integration access.",
        "callback_urls": [],
    },
    "requested_scope_policy": "maximum",
    "browser_provider": "playwright",
    "dry_run": True,
}


def main() -> int:
    from starlette.testclient import TestClient

    # api.main is the production entry point: importing it installs the
    # assignment runtime, live bootstrap and projection layers.
    import api.main as production_main
    from api.service import LocalRunService
    from ops.config import Settings
    from ops.run_service import RunService as CoreRunService

    root = Path(tempfile.mkdtemp())
    settings = Settings.from_env(dotenv_path=None)
    db_path = root / "ops.db"
    core = CoreRunService.from_paths(db_path=db_path, settings=settings)
    service = LocalRunService(db_path, core_service=core, settings=settings)
    application = production_main.create_app(service=service)

    headers = {"X-Ops-Internal-Token": "probe-token"}
    with TestClient(application, raise_server_exceptions=False) as client:
        created = client.post("/api/runs", json=_PAYLOAD, headers=headers)
        if created.status_code != 201:
            print(json.dumps({"error": "create_failed", "status": created.status_code}))
            return 1
        run_id = created.json()["run"]["run_id"]
        detail = client.get(f"/api/runs/{run_id}", headers=headers)
        if detail.status_code != 200:
            print(json.dumps({"error": "detail_failed", "status": detail.status_code}))
            return 1
        print(json.dumps(detail.json()))
    return 0


if __name__ == "__main__":
    sys.exit(main())
