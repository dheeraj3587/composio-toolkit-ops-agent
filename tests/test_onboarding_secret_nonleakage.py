"""Property 4 — a credential-shaped value never crosses any boundary.

Companion to ``tests/test_model_input_dlp.py`` (which pins one hand-written canary
per page channel) and to ``tests/test_browser_secret_placeholders.py`` (which pins
that injected login values are referenced by placeholder key, never by value). What
this module adds is the *quantified* claim: for EVERY credential shape the
sanitizers are supposed to know about, planted in EVERY page channel a run reads,
and captured as the run's own credential, the value reaches none of the seven
places it could escape to.

The channels, and why each one is the real thing rather than a stand-in:

* **the model prompt** — assembled by the real ``ops.browser.decider.build_snapshot``
  / ``ops.browser.candidates.generate_candidates`` / ``build_choice_prompt``, with
  ``ops.core.model_input_dlp`` applied between the observation and the projection, which
  is the only ordering Requirement 19.1 permits;
* **log records** — a real ``logging`` logger carrying a real
  ``ops.core.redaction.RedactingFilter``, asserted through ``caplog``;
* **``audit_events.sanitized_payload_json``** — a real SQLite database, written
  through ``ops.core.storage.OperationsStorage.append_audit_event`` and read back as the
  stored column text rather than as the projection of it;
* **the serialized checkpoint** — the workflow state serialized by the exact
  serializer ``ops.workflow.graph_checkpoints`` configures (strict JSON/msgpack, pickle
  disabled), checked as BYTES so an escape cannot hide behind an encoding;
* **API response bodies** — ``/api/runs/{id}`` and ``/api/runs/{id}/timeline`` over
  a real ``TestClient`` against the same database;
* **the captured credential itself** — written through the real broker verb
  (``api.browser_secret_broker._capture_sync``) into a real Fernet vault, which
  hands back a reference and nothing else.

**Why the operator console is asserted at the API boundary.** The console is
TypeScript under ``web/`` and renders exclusively from these response bodies; it has
no second source of run data (``tests/test_frontend_boundaries.py`` pins that its
schemas are strict and that reference fields are typed as vault references). A value
would therefore have to escape into a response body *first* in order to reach
rendered HTML, so asserting the bodies is the stronger and earlier check — standing
up Next.js could only observe a leak that these assertions have already caught.

**One run, every channel.** The run row is created directly so it carries the
onboarding shape the broker's authorization requires (``canonical_v1``,
``playwright``, an active session, the reserved capture phase); the owner API then
projects that same row, and the broker reads it as its authoritative record. So the
credential the vault holds and the run the console shows are the same run, which is
what makes "this value leaked into that body" a meaningful sentence.

**Guarding against a vacuous pass.** Every planted value is asserted to satisfy
``contains_secret_material`` before it is asserted not to leak; every channel is
asserted to be non-empty and to have actually carried the run's material (the vault
reference is looked for positively in each one); and the DLP boundary is asserted to
have *changed* each field it was given, so a sanitizer that silently returned its
input would fail here rather than pass quietly.

**Validates: Requirements 19.1, 19.2, 19.3, 19.4, 19.5, 19.10, 19.11, 19.12, 19.13**

Requirements 19.6 and 19.7 (the projection boundary being the only constructor of
onboarding response models, and those models forbidding extra fields) belong to the
projection module that task 22 introduces and are not asserted here. Requirement
19.9 (screenshot masking) is armed inside the browser service and is pinned by
``tests/test_playwright_live_mask.py``.
"""

from __future__ import annotations

import importlib
import json
import logging
import sqlite3
import threading
from collections.abc import Iterator, Mapping
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, get_type_hints

import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient
from hypothesis import given, settings
from pydantic import TypeAdapter, ValidationError

from api.app import create_app
from api.browser_secret_broker import (
    BrowserCaptureNotAuthorized,
    BrowserCredentialCaptureRequest,
    _capture_sync,
)
from api.models import VaultReference
from api.service import LocalRunService
from ops.browser.candidates import generate_candidates, render_candidates
from ops.browser.decider import build_choice_prompt, build_snapshot, render_snapshot
from ops.core.model_input_dlp import (
    DROPPED,
    REDACTED,
    contains_secret_material,
    sanitize_element_name,
    sanitize_page_text,
    sanitize_reason,
    sanitize_url,
    screen_model_input,
)
from ops.core.redaction import RedactingFilter, install_redacting_filter, redact_data
from ops.core.secret_store import SQLiteSecretStore
from ops.core.state import OperationsState
from ops.onboarding.credentials import credential_value_matches, onboarding_vault_kind
from ops.providers.profile import (
    FieldEvidence,
    FlowSpec,
    ProviderProfile,
    compute_profile_digest,
)
from ops.providers.profile_store import SQLiteProviderProfileStore
from ops.runs.service import RunService as CoreRunService
from tests.support.onboarding_strategies import (
    SECRET_PLACEMENTS,
    PageElement,
    PageFixture,
    adversarial_pages,
    credential_shaped_values,
)

ROOT = Path(__file__).resolve().parents[1]

# A provider with no reviewed recipe, which is the whole point: the capture
# contract has to come from the run's committed profile, and its value contract
# from checked-in code keyed by credential kind.
PROVIDER_SLUG = "acme-labs"
PROVIDER_DOMAIN = "acme-labs.com"
PROVIDER_NAME = "Acme Labs"
ENTRY_URL = "https://app.acme-labs.com/settings/api-keys"
CREDENTIAL_KIND = "api_key"

RUN_ID = "run_" + ("a1b2c3d4" * 4)
SESSION_ID = "bs_" + ("b1c2d3e4" * 4)
OWNER = "nonleakage-owner"
LOGGER_NAME = "composio_ops.tests.onboarding_nonleakage"

# Checked-in prompt scaffolding. Nothing here is page-derived, so a leak found in
# the prompt is always a leak through a sanitized field rather than through the
# harness's own text.
CHECKPOINT_INSTRUCTION = "Open the API keys page and create a key"
CHECKPOINT_SIGNALS: tuple[str, ...] = ()
CREDENTIAL_GOAL = "an API key for this workspace"
TRACE_VERSION = "onboarding-profile-v1"
EXPECTED_POSTCONDITION = "credential_surface_reached"

# Field names a careless caller would reach for when writing a credential into an
# audit payload, a log record, or a state field. Key-aware redaction has to strip
# every one of them, and has to keep a vault reference under the same key.
CREDENTIAL_FIELD_KEYS: tuple[str, ...] = (
    "api_key",
    "client_secret",
    "password",
    "token",
    "access_token",
    "credential",
    "authorization",
    "code",
    "private_key",
)

# The nine placements the fixture plants into. Restated so a tenth placement added
# to the shared vocabulary fails here and gets a deliberate review rather than
# silently going unasserted by a property that claims to cover "every channel".
EXPECTED_PLACEMENTS: frozenset[str] = frozenset(
    {
        "title",
        "accessible_name",
        "label",
        "placeholder",
        "href",
        "query_string",
        "code_block",
        "pre_block",
        "contenteditable",
    }
)
assert frozenset(SECRET_PLACEMENTS) == EXPECTED_PLACEMENTS, (
    "a new secret placement must be reviewed against Property 4 before it is generated"
)


# --- The DLP boundary, applied exactly where the design puts it ---------------


@dataclass(frozen=True, slots=True)
class SanitizedField:
    """One page-derived string, as authored and as the DLP boundary leaves it."""

    channel: str
    raw: str
    sanitized: str


def _element_fields(element: PageElement, index: int) -> tuple[SanitizedField, ...]:
    """Every string one element exposes, paired with its sanitized form."""

    common = {"element_type": element.element_type, "origin": element.origin, "role": element.role}
    fields = [
        SanitizedField(
            channel=f"element[{index}].name",
            raw=element.name,
            sanitized=sanitize_element_name(element.name, **common),
        ),
        SanitizedField(
            channel=f"element[{index}].label",
            raw=element.label,
            sanitized=sanitize_element_name(element.label, **common),
        ),
        SanitizedField(
            channel=f"element[{index}].placeholder",
            raw=element.placeholder,
            sanitized=sanitize_element_name(element.placeholder, **common),
        ),
        SanitizedField(
            channel=f"element[{index}].text",
            raw=element.text,
            sanitized=sanitize_page_text(element.text, origin=element.origin),
        ),
        # An href is a URL, so it loses its query and fragment outright — which is
        # where a token planted in a link actually sits.
        SanitizedField(
            channel=f"element[{index}].href",
            raw=element.href,
            sanitized=sanitize_url(element.href),
        ),
    ]
    return tuple(field for field in fields if field.raw)


def _dlp_fields(page: PageFixture) -> tuple[SanitizedField, ...]:
    """Every page-derived string the run reads, raw and sanitized."""

    fields = [
        SanitizedField(channel="url", raw=page.url, sanitized=sanitize_url(page.url)),
        SanitizedField(channel="title", raw=page.title, sanitized=sanitize_page_text(page.title)),
    ]
    for index, element in enumerate(page.elements):
        fields.extend(_element_fields(element, index))
    return tuple(fields)


def _raw_dict(element: PageElement, *, dlp: bool) -> dict[str, object]:
    """The raw element mapping ``build_snapshot`` consumes, with or without DLP.

    ``dlp=False`` is not a code path the runtime has — it exists so the property can
    show that the boundary is load-bearing, by observing that the same projection
    without it carries the value.
    """

    raw = dict(element.as_raw())
    if not dlp:
        return raw
    common = {"element_type": element.element_type, "origin": element.origin, "role": element.role}
    raw["name"] = sanitize_element_name(element.name, **common)
    raw["label"] = sanitize_element_name(element.label, **common)
    raw["placeholder"] = sanitize_element_name(element.placeholder, **common)
    raw["text"] = sanitize_page_text(element.text, origin=element.origin)
    if "href_path" in raw:
        raw["href_path"] = sanitize_url(str(raw["href_path"]))
    return raw


def _build_prompt(page: PageFixture, *, dlp: bool) -> str:
    """The real choice prompt for this page, built through the real projection."""

    elements = build_snapshot(tuple(_raw_dict(element, dlp=dlp) for element in page.elements))
    candidates = generate_candidates(
        elements=elements,
        checkpoint_signals=CHECKPOINT_SIGNALS,
        checkpoint_order=1,
        trace_version=TRACE_VERSION,
        expected_postcondition=EXPECTED_POSTCONDITION,
    )
    return build_choice_prompt(
        app_name=PROVIDER_NAME,
        credential_goal=CREDENTIAL_GOAL,
        checkpoint_instruction=CHECKPOINT_INSTRUCTION,
        checkpoint_signals=CHECKPOINT_SIGNALS,
        current_url=sanitize_url(page.url) if dlp else page.url,
        page_title=sanitize_page_text(page.title) if dlp else page.title,
        rendered_candidates=render_candidates(candidates),
        rendered_page=render_snapshot(elements),
    )


# --- The run's collaborators: one real database, one real vault ---------------


class _BrokerCore:
    """The narrow surface the broker reads, backed by the REAL run row.

    Mirrors the double in ``tests/test_browser_secret_broker.py``, with one
    deliberate difference: ``storage`` is the same ``OperationsStorage`` the owner
    API projects from, so the broker's authoritative read and the console's
    response body describe one run rather than two.
    """

    def __init__(
        self,
        *,
        storage: Any,
        vault: SQLiteSecretStore,
        profile_store: SQLiteProviderProfileStore,
    ) -> None:
        self.storage = storage
        self._secret_store = vault
        self.provider_profile_store = profile_store
        self._lock = threading.RLock()

    def _run_lock(self, run_id: str) -> threading.RLock:
        del run_id
        return self._lock


class _BrokerService:
    """The ``service`` shape ``_capture_sync`` unwraps to reach the core."""

    def __init__(self, core: _BrokerCore) -> None:
        self._service = core


def _provider_profile() -> ProviderProfile:
    """A committed profile for a provider the repo has never reviewed."""

    evidence = FieldEvidence(
        field="api_key_flow",
        value=ENTRY_URL,
        source_url="https://developers.acme-labs.com/docs",
        source_digest="d" * 64,
        adapters=("fake-discovery",),
        corroborations=2,
        confidence=0.9,
        extracted_at="2025-01-01T00:00:00Z",
    )
    profile = ProviderProfile(
        run_id=RUN_ID,
        provider_name=PROVIDER_NAME,
        app_slug=PROVIDER_SLUG,
        registrable_domain=PROVIDER_DOMAIN,
        auxiliary_hosts=(),
        developer_portal_url="https://developers.acme-labs.com/",
        signup_url="https://acme-labs.com/signup",
        login_url="https://app.acme-labs.com/login",
        developer_docs_url="https://developers.acme-labs.com/docs",
        developer_app_flow=FlowSpec(kind="developer_app", supported=False, entry_url=None),
        oauth_flow=FlowSpec(kind="oauth", supported=False, entry_url=None),
        api_key_flow=FlowSpec(
            kind="api_key",
            supported=True,
            entry_url=ENTRY_URL,
            produces=(CREDENTIAL_KIND,),
            evidence=(evidence,),
        ),
        pat_flow=FlowSpec(kind="pat", supported=False, entry_url=None),
        approval_requirement="none",
        billing_requirement="unknown",
        evidence=(replace(evidence, field="signup_url", value="https://acme-labs.com/signup"),),
        confidence=0.85,
        adapters_engaged=("fake-discovery",),
        built_at="2025-01-01T00:00:01Z",
    )
    return replace(profile, profile_digest=compute_profile_digest(profile))


@dataclass(slots=True)
class LeakHarness:
    """Everything one onboarding run needs to expose all seven channels."""

    client: TestClient
    core: CoreRunService
    vault: SQLiteSecretStore
    broker: _BrokerService
    logger: logging.Logger
    captures: int = 0

    def next_effect_identity(self) -> str:
        """A fresh reserved capture effect, so each example captures once.

        The broker keys a capture on the run's durable ``effect_identity``, so a
        second capture under the same identity is (correctly) a replay. Advancing it
        per example is what makes every example a real first capture rather than a
        deduplicated no-op.
        """

        self.captures += 1
        identity = f"{RUN_ID}:credential-capture:{self.captures}"
        self.core.storage.update_run(RUN_ID, effect_identity=identity)
        return identity

    def capture(self, value: str) -> tuple[str, str]:
        """Write ``value`` through the broker; receive only a reference.

        Returns the grant alongside the reference so the caller can attempt the
        one-time-use violation (19.11) against the exact grant that succeeded.
        """

        effect_identity = self.next_effect_identity()
        grant = self.vault.reserve_browser_secret_grant(
            operation_key=f"{effect_identity}:capture:{CREDENTIAL_KIND}",
            run_id=RUN_ID,
            session_id=SESSION_ID,
            app_slug=PROVIDER_SLUG,
            kind=CREDENTIAL_KIND,
            action="capture",
        )
        return self.capture_with(grant, value), grant

    def capture_with(self, grant: str, value: str) -> str:
        payload = BrowserCredentialCaptureRequest(
            grant=grant,
            app_slug=PROVIDER_SLUG,
            kind=CREDENTIAL_KIND,
            scope_id=RUN_ID,
            session_id=SESSION_ID,
            value=value,
        )
        return _capture_sync(self.broker, payload, authorized=True)

    def vault_entry_count(self) -> int:
        """How many credentials the vault actually holds, for the one-time claim."""

        with sqlite3.connect(self.vault.db_path) as connection:
            row = connection.execute(
                "SELECT COUNT(*) FROM vault_entries WHERE app_slug = ? AND kind = ?",
                (PROVIDER_SLUG, CREDENTIAL_KIND),
            ).fetchone()
        return int(row[0])

    def audit_payloads(self) -> tuple[str, ...]:
        """The stored ``sanitized_payload_json`` column text, unprojected."""

        with sqlite3.connect(self.core.storage.db_path) as connection:
            rows = connection.execute(
                "SELECT sanitized_payload_json FROM audit_events WHERE run_id = ? ORDER BY id",
                (RUN_ID,),
            ).fetchall()
        return tuple(str(row[0]) for row in rows)


@pytest.fixture
def harness(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[LeakHarness]:
    """One onboarding run, wired to a real database, vault, profile store and API.

    Built once per test function and reused across Hypothesis examples: the durable
    rows accumulate, which only strengthens the property — a later example asserts
    over a database that already holds every earlier example's audit rows.
    """

    monkeypatch.setenv("BROWSER_SESSION_CAPABILITY_KEY", "capability-key-" + ("k" * 32))
    db_path = tmp_path / "private" / "ops.db"
    core = CoreRunService.from_paths(db_path=db_path)
    core.storage.create_run(
        run_id=RUN_ID,
        thread_id=f"thread-{RUN_ID}",
        app_name=PROVIDER_NAME,
        app_slug=PROVIDER_SLUG,
        status="browser_running",
        access_route="self_serve",
        execution_mode="operations",
        browser_provider="playwright",
        state_engine="canonical_v1",
        browser_session_id=SESSION_ID,
        phase="credential_capture_reserved",
        effect_identity=f"{RUN_ID}:credential-capture:0",
        route_reason_code="browser_automation_required",
        route_explanation="Driving the provider's API key surface.",
    )
    vault = SQLiteSecretStore(tmp_path / "private" / "vault.db", Fernet.generate_key())
    profile_store = SQLiteProviderProfileStore(
        tmp_path / "private" / "provider_profiles.db",
        owner=OWNER,
    )
    profile_store.put(_provider_profile())
    broker = _BrokerService(
        _BrokerCore(storage=core.storage, vault=vault, profile_store=profile_store)
    )

    logger = logging.getLogger(LOGGER_NAME)
    logger.setLevel(logging.INFO)
    # 19.4: the same filter the API and CLI startup boundaries install.
    install_redacting_filter(logger)

    service = LocalRunService(db_path, core_service=core)
    application = create_app(service=service, cors_origins=[], enable_docs=False)
    with TestClient(application, raise_server_exceptions=False) as client:
        yield LeakHarness(client=client, core=core, vault=vault, broker=broker, logger=logger)


# --- Property 4 ---------------------------------------------------------------


def _assert_absent(haystack: str, forms: tuple[str, ...], channel: str) -> None:
    """No form of the value — raw or percent-encoded — appears in ``channel``."""

    for form in forms:
        assert form not in haystack, f"{channel} leaked credential material ({len(form)} chars)"


def _assert_absent_bytes(haystack: bytes, forms: tuple[str, ...], channel: str) -> None:
    for form in forms:
        assert form.encode("utf-8") not in haystack, f"{channel} leaked credential material"


def _record_text(record: logging.LogRecord) -> str:
    """Everything one log record could carry a value in: message, args, extras."""

    parts = [record.getMessage()]
    for name, value in record.__dict__.items():
        if name in {"msg", "args"}:
            continue
        parts.append(f"{name}={value!r}")
    return "\n".join(parts)


def _workflow_state(*, reference: str, page: PageFixture) -> dict[str, object]:
    """The run's serializable state: references and non-secret identifiers only."""

    state: OperationsState = {
        "run_id": RUN_ID,
        "thread_id": f"thread-{RUN_ID}",
        "app_name": PROVIDER_NAME,
        "app_slug": PROVIDER_SLUG,
        "status": "browser_running",
        "browser_session_id": SESSION_ID,
        "current_url": sanitize_url(page.url),
        "browser_observation": {
            "title": sanitize_page_text(page.title),
            "elements": [field.sanitized for field in _dlp_fields(page)],
        },
        "credential_refs": {CREDENTIAL_KIND: reference},
        "onboarding_phase": "credential_capture",
        "profile_digest": compute_profile_digest(_provider_profile()),
        "provider_registrable_domain": PROVIDER_DOMAIN,
        "onboarding_credential_generation": 1,
    }
    return dict(state)


def _serialize_checkpoint(state: Mapping[str, object]) -> bytes:
    """Serialize state with the exact serializer ``ops.workflow.graph_checkpoints`` builds.

    Pickle and arbitrary module loading are disabled there, so this is the whole
    payload the checkpoint row carries; the encryption layer above it only wraps
    these bytes. Asserting on the bytes means a value cannot hide behind msgpack
    framing or a non-UTF-8 escape.
    """

    module = importlib.import_module("langgraph.checkpoint.serde.jsonplus")
    serializer = module.JsonPlusSerializer(
        pickle_fallback=False,
        allowed_json_modules=None,
        allowed_msgpack_modules=None,
    )
    _kind, payload = serializer.dumps_typed(dict(state))
    return bytes(payload)


# 60 examples rather than the profile's 200: each one drives a real vault write, a
# real audit write and two real HTTP round trips, and the interesting variation is
# the (shape x placement) cross product, which 60 examples cover comfortably.
@settings(max_examples=60)
@given(page=adversarial_pages(domain=PROVIDER_DOMAIN), captured=credential_shaped_values())
def test_no_credential_shaped_value_reaches_any_boundary(
    harness: LeakHarness,
    caplog: pytest.LogCaptureFixture,
    page: PageFixture,
    captured: str,
) -> None:
    """The invariant: no form of a credential-shaped value crosses any boundary."""

    forms = (*page.secret_forms(), captured)

    # --- Non-vacuity, first: these really are values a DLP boundary must catch --
    for value in forms:
        assert contains_secret_material(value) is True, (
            f"planted value is not secret-shaped: {value!r}"
        )
    assert page.planted_secrets, "the fixture planted no secret"
    assert credential_value_matches(CREDENTIAL_KIND, captured), (
        "the generated credential must satisfy the checked-in api_key contract, "
        "or the capture channel would never be exercised"
    )

    # --- Channel 6/7: the credential is captured; only a reference comes back ---
    reference, grant = harness.capture(captured)
    # 19.12: a capture hands back a reference and nothing else.
    TypeAdapter(VaultReference).validate_python(reference)  # 19.8: constrained type
    _assert_absent(reference, forms, "vault reference")
    # 19.10: the plaintext lives in the vault the worker wrote it to, nowhere else.
    assert harness.vault.get(reference) == captured
    assert onboarding_vault_kind(CREDENTIAL_KIND).endswith(CREDENTIAL_KIND)
    # 19.11: the grant that just succeeded is spent. An exact replay is the
    # transport retry the broker is allowed to absorb, so it must consume nothing
    # further — the same reference comes back and no second entry appears; any
    # replay carrying different material is refused outright, and neither outcome
    # names credential material.
    assert harness.capture_with(grant, captured) == reference
    assert harness.vault_entry_count() == harness.captures
    with pytest.raises(BrowserCaptureNotAuthorized) as refusal:
        harness.capture_with(grant, captured + "x")
    _assert_absent(f"{refusal.value!r} {refusal.value}", forms, "grant reuse refusal")

    # --- Channel 1: the model prompt -------------------------------------------
    prompt = _build_prompt(page, dlp=True)
    _assert_absent(prompt, forms, "model prompt")
    assert contains_secret_material(prompt) is False
    decision = screen_model_input(prompt)
    assert decision.allowed is True
    assert decision.prompt == prompt
    # The channel is real: the page was projected, not silently emptied.
    assert "<<<PAGE>>>" in prompt and "CANDIDATES:" in prompt
    assert any(line.startswith("[0]") for line in prompt.splitlines())
    # And the boundary is load-bearing: the same projection without it either
    # carries the value (and is then refused at the inference boundary) or never
    # received it at all, because the snapshot builder does not project that field.
    unsanitized = _build_prompt(page, dlp=False)
    if any(form in unsanitized for form in forms):
        assert screen_model_input(unsanitized).allowed is False
        assert unsanitized != prompt

    # --- Channel 2: log records ------------------------------------------------
    caplog.clear()
    with caplog.at_level(logging.INFO, logger=LOGGER_NAME):
        harness.logger.info(
            "onboarding observation url=%s title=%s",
            sanitize_url(page.url),
            sanitize_page_text(page.title),
        )
        harness.logger.info(
            "credential captured",
            extra={
                "run_id": RUN_ID,
                "credential_ref": reference,
                **{key: captured for key in CREDENTIAL_FIELD_KEYS},
            },
        )
        harness.logger.warning(
            "page projection refused nothing",
            extra={"reason": sanitize_reason(f"observed {page.title}")},
        )
    assert len(caplog.records) == 3, "the log channel was not exercised"
    rendered = "\n".join(_record_text(record) for record in caplog.records)
    _assert_absent(caplog.text, forms, "caplog.text")
    _assert_absent(rendered, forms, "log record fields")
    # Key-aware redaction fired, and the reference survived it (19.4).
    assert REDACTED in rendered
    assert reference in rendered

    # --- Channel 3: audit_events.sanitized_payload_json ------------------------
    harness.core.storage.append_audit_event(
        run_id=RUN_ID,
        event_type="browser_credential_captured",
        payload={
            "run_id": RUN_ID,
            "phase": "credential_capture",
            "credential_ref": reference,
            "current_url": sanitize_url(page.url),
            "page_title": sanitize_page_text(page.title),
            "reason": sanitize_reason(f"captured from {page.title}"),
            "element_names": [field.sanitized for field in _dlp_fields(page)],
            **{key: captured for key in CREDENTIAL_FIELD_KEYS},
        },
    )
    payloads = harness.audit_payloads()
    assert payloads, "the audit channel was not exercised"
    for stored in payloads:
        _assert_absent(stored, forms, "audit_events.sanitized_payload_json")
    assert reference in payloads[-1]
    assert REDACTED in payloads[-1]

    # --- Channel 4: the serialized checkpoint ----------------------------------
    state = _workflow_state(reference=reference, page=page)
    serialized = _serialize_checkpoint(state)
    _assert_absent_bytes(serialized, forms, "serialized checkpoint")
    assert reference.encode("utf-8") in serialized, "the checkpoint channel was not exercised"

    # --- Channel 5: API response bodies (and therefore the console) ------------
    # Page-derived text reaches a durable run column only through the DLP boundary,
    # which is the ordering Requirement 19.1 fixes; the API then projects it.
    harness.core.storage.update_run(
        RUN_ID,
        route_explanation=sanitize_reason(f"reached {page.title} at {sanitize_url(page.url)}"),
        missing_fields=[field.sanitized for field in _dlp_fields(page)][:5],
    )
    detail = harness.client.get(f"/api/runs/{RUN_ID}")
    timeline = harness.client.get(f"/api/runs/{RUN_ID}/timeline")
    assert detail.status_code == 200
    assert timeline.status_code == 200
    assert detail.json()["run"]["run_id"] == RUN_ID
    assert timeline.json()["items"], "the timeline channel was not exercised"
    _assert_absent(detail.text, forms, "/api/runs/{id}")
    _assert_absent(timeline.text, forms, "/api/runs/{id}/timeline")
    # 19.13: no response body carries a credential value or a raw page projection.
    assert reference not in detail.text
    assert "<<<PAGE>>>" not in detail.text


# --- Structural backing asserted in this module -------------------------------
#
# Three claims the property above rests on. Without the first, a sanitizer that
# returned its input unchanged would still pass every channel assertion for the
# placements the projection happens not to read. Without the second, a credential
# written under a credential-shaped key would survive persistence. Without the
# third, a credential value could be assigned to a reference field and reach the
# wire as a well-typed string.


@given(page=adversarial_pages(domain=PROVIDER_DOMAIN))
def test_the_dlp_boundary_neutralizes_every_field_it_is_given(page: PageFixture) -> None:
    """Every planted field is changed, and none of its forms survives (19.1-19.3)."""

    forms = page.secret_forms()
    fields = _dlp_fields(page)
    carrying = tuple(field for field in fields if any(form in field.raw for form in forms))
    assert carrying, "the fixture planted a secret into no field this projection reads"

    for field in carrying:
        _assert_absent(field.sanitized, forms, field.channel)
        assert field.sanitized != field.raw, f"{field.channel} passed through unchanged"

    # 19.3: a URL loses its query and its fragment outright, so a token planted in
    # either is gone rather than filtered.
    for field in fields:
        if field.channel in {"url"} or field.channel.endswith(".href"):
            assert "?" not in field.sanitized and "#" not in field.sanitized

    # 19.2: a region whose origin is code, preformatted or contenteditable is
    # dropped wholesale — the sanitized form is the drop marker, not a redaction.
    unsafe_regions = tuple(
        sanitize_page_text(element.text, origin=element.origin)
        for element in page.elements
        if element.text and element.origin
    )
    assert unsafe_regions, "the fixture always renders at least one code region"
    assert all(region == DROPPED for region in unsafe_regions)


@given(value=credential_shaped_values())
def test_key_aware_redaction_strips_credential_fields_and_keeps_references(value: str) -> None:
    """``redact_data`` removes a value under a credential key, keeps a reference."""

    reference = f"vault://{PROVIDER_SLUG}/{CREDENTIAL_KIND}/abcDEF123_-xyz"
    payload = {
        **{key: value for key in CREDENTIAL_FIELD_KEYS},
        "credential_refs": {CREDENTIAL_KIND: reference},
    }
    redacted = json.dumps(redact_data(payload), sort_keys=True)
    assert value not in redacted
    assert redacted.count(REDACTED) >= len(CREDENTIAL_FIELD_KEYS)
    # The reference is the intended public boundary and must survive the same pass,
    # or every projection built on it would be empty.
    assert reference in redacted


@given(value=credential_shaped_values())
def test_the_vault_reference_type_refuses_credential_material(value: str) -> None:
    """A credential value cannot be assigned to a reference field (19.8)."""

    adapter = TypeAdapter(VaultReference)
    with pytest.raises(ValidationError):
        adapter.validate_python(value)
    with pytest.raises(ValidationError):
        adapter.validate_python(f"vault://{PROVIDER_SLUG}/{CREDENTIAL_KIND}/{value} {value}")
    assert (
        adapter.validate_python(f"vault://{PROVIDER_SLUG}/{CREDENTIAL_KIND}/abcDEF123_-xyz")
        is not None
    )


def test_the_workflow_state_schema_declares_no_credential_value_field() -> None:
    """19.5: state and checkpoint carry references, never a value field."""

    annotations = get_type_hints(OperationsState)
    assert "credential_refs" in annotations
    for name in annotations:
        assert "plaintext" not in name
        assert not name.endswith("_value")
        # The onboarding additions are references or non-secret identifiers; the
        # one field naming an account carries a ``vault://`` reference.
        assert name not in {"credential", "credentials", "api_key", "password", "secret"}
    assert "onboarding_account_ref" in annotations


def test_the_redaction_filter_is_installed_at_both_startup_boundaries() -> None:
    """19.4: every log record passes redaction, on both entrypoints."""

    api_source = (ROOT / "api" / "app.py").read_text(encoding="utf-8")
    cli_source = (ROOT / "ops" / "cli.py").read_text(encoding="utf-8")
    assert "install_redacting_filter" in api_source
    assert "install_redacting_filter" in cli_source
    logger = logging.getLogger(LOGGER_NAME)
    install_redacting_filter(logger)
    assert any(isinstance(item, RedactingFilter) for item in logger.filters)
