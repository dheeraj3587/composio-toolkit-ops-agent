"""Offline-safe durable graph execution and mode-aware create-path proofs.

These tests exercise the encrypted LangGraph checkpointer with a self-generated
test AES key and a temporary checkpoint database. No provider adapters are
injected and no live network calls occur.
"""

from __future__ import annotations

import secrets
from pathlib import Path

from ops.config import Settings
from ops.graph import DurableOperationsWorkflow, WorkflowDependencies, build_graph
from ops.models import CompanyProfile, OperationsRequest
from ops.run_service import RunService


def _request(app_name: str = "HubSpot", *, dry_run: bool = True) -> OperationsRequest:
    return OperationsRequest(
        app_name=app_name,
        company=CompanyProfile(
            legal_name="Example Company",
            website="https://example.test",
            work_email_ref="vault://company/work_email/unconfigured",
            use_case="Evaluate documented integration access.",
        ),
        dry_run=dry_run,
    )


def _adapterless(checkpoint: Path) -> DurableOperationsWorkflow:
    return build_graph(
        checkpoint_path=checkpoint,
        encryption_key=secrets.token_bytes(32),
        dependencies=WorkflowDependencies(browser=None, gmail=None),
    )


def test_durable_start_checkpoint_close_reopen_reads_same_thread_state(tmp_path: Path) -> None:
    checkpoint = tmp_path / "private" / "checkpoints.db"
    key = secrets.token_bytes(32)
    thread_id = "local_" + "c" * 32

    workflow = build_graph(
        checkpoint_path=checkpoint,
        encryption_key=key,
        dependencies=WorkflowDependencies(browser=None, gmail=None),
    )
    try:
        started = workflow.start(_request(), thread_id=thread_id)
    finally:
        workflow.close()

    assert started["status"] == "route_selected"
    assert started["access_route"] == "self_serve"
    assert checkpoint.is_file()

    reopened = build_graph(
        checkpoint_path=checkpoint,
        encryption_key=key,
        dependencies=WorkflowDependencies(browser=None, gmail=None),
    )
    try:
        state = reopened.get_state(thread_id)
    finally:
        reopened.close()

    assert state["status"] == "route_selected"
    assert state["access_route"] == "self_serve"


def test_checkpoint_state_values_are_not_stored_in_plaintext(tmp_path: Path) -> None:
    checkpoint = tmp_path / "private" / "checkpoints.db"
    workflow = _adapterless(checkpoint)
    try:
        workflow.start(_request(), thread_id="local_" + "d" * 32)
    finally:
        workflow.close()

    raw = checkpoint.read_bytes()
    # State values live inside the AES-encrypted checkpoint blobs, never plaintext.
    assert b"self_serve" not in raw
    assert b"route_selected" not in raw


def test_execute_when_configured_runs_the_graph_when_workflow_configured(tmp_path: Path) -> None:
    checkpoint = tmp_path / "private" / "checkpoints.db"
    service = RunService.from_paths(db_path=tmp_path / "ops.db", workflow=_adapterless(checkpoint))
    try:
        run = service.create_run(_request(), execution_mode="execute_when_configured")
    finally:
        service.shutdown()

    # Routed through the durable engine, projected to the ledger, no provider action.
    assert run["execution_mode"] == "execute_when_configured"
    assert run["status"] == "route_selected"
    assert run["external_actions"] is False
    stored = service.storage.get_run(run["run_id"])
    assert stored is not None
    assert stored["execution_mode"] == "operations"
    assert stored["state_revision"] == 1


def test_execute_when_configured_without_key_is_configuration_required(tmp_path: Path) -> None:
    # A settings object without an encryption key leaves the workflow unavailable.
    service = RunService.from_paths(db_path=tmp_path / "ops.db", settings=Settings())
    service.startup()
    try:
        run = service.create_run(_request(), execution_mode="execute_when_configured")
    finally:
        service.shutdown()

    assert run["status"] == "configuration_required"
    assert run["external_actions"] is False
