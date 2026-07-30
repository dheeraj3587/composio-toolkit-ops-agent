"""Regression tests for the three critical production fixes.

C2 — the email/gated credential path must terminate at ``completed`` (with the
     emitted vault references merged into the bundle) instead of dead-ending at
     ``credentials_ready`` with no forward action.
C3 — the Browser Use provider session id must be a declared, persisted state key
     so a paused HITL run survives an api restart.
"""

from __future__ import annotations

from pathlib import Path

from ops.core.models import CompanyProfile
from ops.core.state import OperationsState, validate_status_transition
from ops.core.storage import OperationsStorage
from ops.research.p1_adapter import P1OperationalAdapter, to_operational_research
from ops.runs.service import RunService


def _service(tmp_path: Path) -> RunService:
    return RunService(storage=OperationsStorage(tmp_path / "ops.db"))


def _company() -> CompanyProfile:
    return CompanyProfile(
        legal_name="Example Labs, Inc.",
        website="https://example.com",
        work_email_ref="vault://company/work_email/profile_1",
        use_case="Authorized integration via the provider developer API.",
    )


# ---- C3: provider session id is persisted state -----------------------------
def test_provider_session_id_is_a_declared_state_key() -> None:
    # If this key is not declared, LangGraph silently drops it from the encrypted
    # checkpoint and a paused HITL run cannot be resumed after an api restart.
    assert "browser_provider_session_id" in OperationsState.__annotations__


# ---- C2: email credential path terminates at completed ----------------------
def test_email_path_two_hop_transition_is_legal() -> None:
    # poll_email advances a reply carrying credentials through both legal hops.
    assert validate_status_transition("waiting_for_reply", "credentials_ready", "poll_email")
    assert validate_status_transition("credentials_ready", "completed", "poll_email")


def test_email_credentials_merge_into_existing_bundle(tmp_path: Path) -> None:
    svc = _service(tmp_path)
    record = {
        "integrator_bundle": {
            "app_slug": "salesforce",
            "credential_refs": {"api_key": "vault://salesforce/api_key/existing"},
        }
    }
    change = svc._email_credentials_bundle_change(
        record, _company(), {"email_secret_1": "vault://email-import/api_key/new"}
    )
    refs = change["integrator_bundle"]["credential_refs"]  # type: ignore[index]
    assert refs["api_key"] == "vault://salesforce/api_key/existing"
    assert refs["email_secret_1"] == "vault://email-import/api_key/new"


def test_email_credentials_build_bundle_when_absent(tmp_path: Path) -> None:
    svc = _service(tmp_path)
    research = to_operational_research(P1OperationalAdapter().lookup("Salesforce").record)
    record = {"operational_research": research.model_dump(mode="json")}
    change = svc._email_credentials_bundle_change(
        record, _company(), {"email_secret_1": "vault://email-import/api_key/abc"}
    )
    bundle = change["integrator_bundle"]  # type: ignore[index]
    assert bundle["app_slug"] == "salesforce"
    assert bundle["credential_refs"] == {"email_secret_1": "vault://email-import/api_key/abc"}


def test_email_credentials_no_bundle_without_company_or_research(tmp_path: Path) -> None:
    svc = _service(tmp_path)
    # No existing bundle and no company/research to build one from -> no-op change,
    # but the run still terminates at completed (handled by poll_email itself).
    assert svc._email_credentials_bundle_change({}, None, {"email_secret_1": "vault://x/y/z"}) == {}
