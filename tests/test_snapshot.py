from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
P1_ROOT = REPOSITORY_ROOT / "data" / "p1"
SNAPSHOT_PATH = P1_ROOT / "SNAPSHOT.json"
RESULTS_PATH = P1_ROOT / "results.json"
COVERAGE_PATH = P1_ROOT / "composio_coverage.json"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _snapshot() -> dict[str, object]:
    return json.loads(SNAPSHOT_PATH.read_text(encoding="utf-8"))


def test_snapshot_manifest_has_complete_provenance() -> None:
    snapshot = _snapshot()

    assert snapshot.keys() == {
        "source_repository",
        "source_commit",
        "results_sha256",
        "coverage_sha256",
        "copied_at",
    }
    assert snapshot["source_repository"] == "dheeraj3587/composio-ai-product-ops"
    assert re.fullmatch(r"[0-9a-f]{40}", str(snapshot["source_commit"]))

    copied_at = str(snapshot["copied_at"])
    assert copied_at.endswith("Z")
    assert datetime.fromisoformat(copied_at.replace("Z", "+00:00")).utcoffset() is not None


def test_snapshot_hashes_lock_canonical_p1_bytes() -> None:
    snapshot = _snapshot()

    assert _sha256(RESULTS_PATH) == snapshot["results_sha256"]
    assert _sha256(COVERAGE_PATH) == snapshot["coverage_sha256"]


def test_snapshot_contains_expected_public_contract_rows() -> None:
    records = json.loads(RESULTS_PATH.read_text(encoding="utf-8"))
    assert isinstance(records, list)
    by_slug = {record["slug"]: record for record in records}

    assert by_slug["hubspot"]["access_model"]["kind"] == "Self-Serve"
    assert by_slug["salesforce"]["access_model"]["kind"] == "Gated"

    required_fields = {
        "app",
        "slug",
        "auth_methods",
        "access_model",
        "api_type",
        "buildability",
        "main_blocker",
        "recommended_next_action",
        "evidence_urls",
        "primary_docs_url",
        "confidence",
        "verification_status",
    }
    assert all(required_fields <= record.keys() for record in records)


def test_repository_excludes_forbidden_p1_material() -> None:
    forbidden_names = {
        "interview2.md",
        "INTERVIEW_PREP.md",
        "handcheck",
        "report",
    }
    present = {
        path.name for path in REPOSITORY_ROOT.iterdir() if path.name not in {".git", ".venv"}
    }
    assert forbidden_names.isdisjoint(present)
