"""End-to-end Pipedrive proof THROUGH the real FastAPI app.

- No new Browser Use session: the already-obtained real browser evidence
  (session cca683da-..., credential_page_ready at developers.pipedrive.com) is
  replayed so the run reaches browser_running honestly.
- No Perplexity/Gemini re-run: a stub enricher keeps the verified P1 baseline.
- Composio is not re-called: the recorded real Pipedrive capability result
  (custom_auth_or_approval_required) is used.
- Credential validation is REAL when PIPEDRIVE_API_TOKEN is set (live request to
  api.pipedrive.com). Without it, a clearly-labeled FIXTURE transport is used to
  prove the create -> submit -> validate -> bundle -> output pipeline.

Flow exercised via TestClient: POST /api/runs -> POST /api/runs/{id}/credentials
-> GET detail -> GET timeline -> GET output.
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

import httpx
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient

from api.app import create_app
from api.service import LocalRunService
from ops.browser_worker import BrowserObservation, BrowserSessionContext
from ops.composio_capability import ComposioCapabilityReport
from ops.config import Settings, load_settings
from ops.credential_validator import (
    HUBSPOT_ACCOUNT_INFO_ENDPOINT,
    PIPEDRIVE_USERS_ME_ENDPOINT,
    CredentialValidator,
    PolicyBoundCredentialValidator,
    hubspot_validation_policy,
    pipedrive_validation_policy,
)
from ops.effect_ledger import SQLiteEffectStore
from ops.graph import WorkflowDependencies, build_graph
from ops.models import OperationalResearch
from ops.operational_research import ResearchEnrichmentOutcome
from ops.run_service import RunService as CoreRunService
from ops.secret_store import SQLiteSecretStore

REAL_SESSION_ID = "cca683da-f409-4c31-a1f6-f361faa2e017"
PIPEDRIVE_START_URL = "https://developers.pipedrive.com/"


class _ReplayBrowser:
    """Replays the real browser proof already obtained; creates no new session."""

    async def start(self, profile_id: str | None) -> BrowserSessionContext:
        return BrowserSessionContext(
            profile_id=profile_id or "pipedrive-demo",
            session_id=REAL_SESSION_ID,
            live_view_available=True,
            allowed_domains=("developers.pipedrive.com",),
            created_at="2026-07-23T06:03:07Z",
            inactivity_expires_at="2026-07-23T06:18:07Z",
            maximum_expires_at="2026-07-23T10:03:07Z",
        )

    async def navigate_onboarding(self, context: object, research: object) -> BrowserObservation:
        del context, research
        return BrowserObservation(
            status="credential_page_ready",
            current_url=PIPEDRIVE_START_URL,
            page_title="Pipedrive Developers Corner (official developer portal)",
        )

    async def resume_after_hitl(self, context: object, signal: object) -> BrowserObservation:
        raise AssertionError("resume is out of scope for this demo")


class _StubPreflight:
    """Returns the recorded real Composio result for Pipedrive (no re-call)."""

    async def evaluate(
        self, *, app_name: str, app_slug: str | None = None, required_tools: object = ()
    ) -> ComposioCapabilityReport:
        del app_name, app_slug, required_tools
        return ComposioCapabilityReport(
            app_slug="pipedrive",
            toolkit_available=True,
            toolkit_slug="pipedrive",
            required_auth_schemes=("oauth2", "api_key"),
            managed_auth_available=False,
            active_connected_account=False,
            required_tools_present=True,
            capability_state="custom_auth_or_approval_required",
            reason_code="composio_custom_auth_or_approval_required",
            detail="Recorded real Composio preflight result for Pipedrive.",
        )


class _StubEnricher:
    """Keeps the verified P1 baseline; performs no Perplexity/Gemini call."""

    async def enrich(
        self, *, app_name: str, p1_record: object, baseline: OperationalResearch
    ) -> ResearchEnrichmentOutcome:
        del app_name, p1_record
        from ops.models import CapabilityAvailability

        return ResearchEnrichmentOutcome(
            research=baseline,
            capability=CapabilityAvailability(
                capability="operational_research",
                status="configuration_required",
                reason_code="enrichment_skipped_for_demo",
                detail="Provider research frozen for this demo; P1 baseline retained.",
            ),
            missing_fields=[],
            documents_fetched=0,
        )


def _pipedrive_fixture_transport() -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.host == "api.pipedrive.com"
        assert request.url.path == "/v1/users/me"
        assert "x-api-token" in request.headers  # token in header, never URL
        return httpx.Response(
            200,
            json={"data": {"id": 987654, "company_id": 123456, "company_name": "Demo Co"}},
        )

    return httpx.MockTransport(handler)


def _company_payload() -> dict[str, object]:
    return {
        "legal_name": "Example Labs, Inc.",
        "website": "https://example.com",
        "work_email_ref": "vault://company/work_email/profile_1",
        "use_case": "Deliver an authorized integration via the Pipedrive developer API.",
        "callback_urls": ["https://example.com/oauth/callback"],
    }


def main() -> None:
    tmp = Path(tempfile.mkdtemp())
    base = load_settings()
    settings = Settings(
        **{
            **base.model_dump(),
            "ops_db_path": tmp / "ops.db",
            "checkpoint_db_path": tmp / "checkpoints.db",
            "secret_vault_db_path": tmp / "vault.db",
            "provider_effects_db_path": tmp / "effects.db",
        }
    )

    token = os.environ.get("PIPEDRIVE_API_TOKEN")
    live = token is not None and token.strip() != ""
    if live:
        client = httpx.AsyncClient(timeout=httpx.Timeout(10.0, connect=5.0), follow_redirects=False)
        mode = "LIVE (real request to api.pipedrive.com)"
    else:
        token = "fixture-pipedrive-token"  # noqa: S105 - clearly labeled fixture
        client = httpx.AsyncClient(transport=_pipedrive_fixture_transport())
        mode = "FIXTURE (no real Pipedrive call; pipeline proof only)"

    vault_key = (
        settings.secret_vault_key.get_secret_value()
        if settings.secret_vault_key is not None
        else Fernet.generate_key().decode()
    )
    vault = SQLiteSecretStore(tmp / "vault.db", vault_key)
    validator = PolicyBoundCredentialValidator(
        validator=CredentialValidator(
            secret_store=vault,
            http_client=client,
            policies=(hubspot_validation_policy(), pipedrive_validation_policy()),
        ),
        endpoints={
            "hubspot": HUBSPOT_ACCOUNT_INFO_ENDPOINT,
            "pipedrive": PIPEDRIVE_USERS_ME_ENDPOINT,
        },
    )

    workflow = build_graph(
        checkpoint_path=tmp / "checkpoints.db",
        encryption_key=settings.langgraph_aes_key,  # type: ignore[arg-type]
        dependencies=WorkflowDependencies(
            browser=_ReplayBrowser(),  # type: ignore[arg-type]
            effect_store=SQLiteEffectStore(tmp / "effects.db"),
        ),
    )
    core = CoreRunService.from_paths(
        db_path=tmp / "ops.db",
        settings=settings,
        workflow=workflow,
        capability_preflight=_StubPreflight(),  # type: ignore[arg-type]
        research_enricher=_StubEnricher(),  # type: ignore[arg-type]
    )
    core._secret_store = vault
    core._credential_validator = validator  # type: ignore[assignment]

    local = LocalRunService(core_service=core, settings=settings)
    app = create_app(service=local)

    print(f"Pipedrive end-to-end API demo -- validation mode: {mode}\n")
    with TestClient(app) as http:
        created = http.post(
            "/api/runs",
            json={
                "app_name": "Pipedrive",
                "company": _company_payload(),
                "execution_mode": "execute_when_configured",
            },
        )
        detail = created.json()
        run_id = detail["run"]["run_id"]
        print(f"1) create run   -> HTTP {created.status_code} run_id={run_id}")
        print(f"   status={detail['run']['status']} route={detail['run'].get('access_route')}")

        submitted = http.post(
            f"/api/runs/{run_id}/credentials",
            json={"company": _company_payload(), "credentials": {"api_token": token}},
        )
        sub = submitted.json()
        print(f"2) submit creds -> HTTP {submitted.status_code} status={sub['run']['status']}")

        got = http.get(f"/api/runs/{run_id}")
        print(f"3) get detail   -> HTTP {got.status_code} status={got.json()['run']['status']}")

        timeline = http.get(f"/api/runs/{run_id}/timeline")
        events = [e["event_type"] for e in timeline.json()["items"]]
        print(f"4) get timeline -> HTTP {timeline.status_code} events={events}")

        output = http.get(f"/api/runs/{run_id}/output")
        print(f"5) get output   -> HTTP {output.status_code}")
        body = output.json()
        print("\n--- IntegratorBundle (API response, secrets redacted by contract) ---")
        print(json.dumps(body, indent=2))

        raw_haystack = created.text + submitted.text + got.text + timeline.text + output.text
        leaked = token in raw_haystack and not live
        print(f"\nvault reference names only: {list(body.get('integrator_bundle', {}).get('credential_refs', {}))}")
        print(f"raw token present in any API response: {token in raw_haystack} (expected False)")
        assert not leaked, "raw fixture token leaked into an API response"


if __name__ == "__main__":
    main()
