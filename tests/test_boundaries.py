from __future__ import annotations

import ast
import asyncio
from dataclasses import asdict
from pathlib import Path

import pytest

from ops.browser_worker import BrowserObservation, BrowserWorker
from ops.credential_capture import CredentialCapture
from ops.gmail_worker import GMAIL_TOOL_ALLOWLIST, GmailWorker
from ops.graph import PhaseUnavailableError, build_graph
from ops.outreach import correlation_subject
from ops.p1_adapter import get_operational_research
from ops.routing import classify_access

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
PROVIDER_BOUNDARY_FILES = (
    "graph.py",
    "routing.py",
    "p1_adapter.py",
    "operational_research.py",
    "browser_worker.py",
    "developer_app_worker.py",
    "credential_capture.py",
    "credential_validator.py",
    "gmail_worker.py",
    "outreach.py",
    "reply_classifier.py",
)
BANNED_IMPORT_ROOTS = {
    "browser_use_sdk",
    "composio",
    "google",
    "langgraph",
    "perplexity",
    "playwright",
}


def _import_roots(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    roots: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            roots.update(alias.name.split(".", 1)[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            roots.add(node.module.split(".", 1)[0])
    return roots


def test_provider_boundaries_make_no_external_sdk_imports() -> None:
    for filename in PROVIDER_BOUNDARY_FILES:
        path = REPOSITORY_ROOT / "ops" / filename
        assert path.is_file(), filename
        assert _import_roots(path).isdisjoint(BANNED_IMPORT_ROOTS), filename


def test_graph_is_explicitly_unavailable() -> None:
    with pytest.raises(PhaseUnavailableError, match="Phase 3") as exc_info:
        build_graph()

    assert exc_info.value.phase == 3
    assert exc_info.value.capability == "LangGraph workflow"


def test_p1_and_final_routing_use_verified_phase_2_evidence() -> None:
    research = asyncio.run(get_operational_research("HubSpot"))

    assert research.app_name == "HubSpot"
    assert research.access_route == "self_serve"
    assert classify_access(research) == "self_serve"


def test_browser_and_capture_boundaries_are_explicitly_unavailable() -> None:
    with pytest.raises(PhaseUnavailableError, match="Phase 5"):
        asyncio.run(BrowserWorker().start(None))

    with pytest.raises(PhaseUnavailableError, match="Phase 6"):
        asyncio.run(
            CredentialCapture().capture_and_store(
                "wss://browser.example.invalid",
                "example-app",
                {"client_id": "#client-id"},
            )
        )


def test_browser_observation_has_no_generic_secret_value_container() -> None:
    observation = BrowserObservation(
        status="credential_page_ready",
        current_url="https://developer.example.invalid/credentials",
        page_title="Credentials",
        credential_field_labels=("Client ID", "Client secret"),
    )

    assert set(asdict(observation)).isdisjoint(
        {"credentials", "credential_values", "payload", "raw", "values"}
    )
    with pytest.raises(TypeError):
        BrowserObservation(  # type: ignore[call-arg]
            status="credential_page_ready",
            current_url="https://developer.example.invalid/credentials",
            page_title="Credentials",
            credential_values="not-accepted",
        )


def test_gmail_boundary_is_unavailable_and_allowlist_is_least_privilege() -> None:
    assert GMAIL_TOOL_ALLOWLIST == (
        "GMAIL_SEND_EMAIL",
        "GMAIL_CREATE_EMAIL_DRAFT",
        "GMAIL_SEND_DRAFT",
        "GMAIL_FETCH_EMAILS",
        "GMAIL_FETCH_MESSAGE_BY_THREAD_ID",
        "GMAIL_LIST_THREADS",
        "GMAIL_REPLY_TO_THREAD",
        "GMAIL_GET_PROFILE",
    )
    with pytest.raises(PhaseUnavailableError, match="Phase 4"):
        asyncio.run(GmailWorker().ensure_connected())


def test_outreach_subject_carries_stable_short_run_correlation() -> None:
    assert correlation_subject(app_name="Example App", run_id="12345678-abcd-ef00") == (
        "[API Access Request][run:12345678] Example App × Composio"
    )
