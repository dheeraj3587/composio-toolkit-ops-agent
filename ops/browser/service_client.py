"""API-side RPC client for the isolated browser service.

Implements the same provider surface as ``PlaywrightBrowserWorker`` so
``RunService`` can swap the in-process harness for the out-of-process service
without any graph/workflow change. The important behavioral difference:

``supports_restart_reattach = True`` — Chromium lives in the browser service, so
an API restart no longer kills a session. Reattachment is only claimed after
QUERYING the service: a persisted session id is never trusted on its own
(``reconcile_session`` returns ``session_lost`` when the service has no such
session).

The shared token travels in a header, never a query string, and is never logged
or returned. Credential VALUES never cross this control RPC — only ``vault://``
references, which the service redeems through a separate private broker.
"""

from __future__ import annotations

import contextlib
import logging
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Literal, get_args

import httpx
from pydantic import SecretStr

from ops.browser.host_policy import (
    BrowserAllowedHosts,
    first_denied_navigation,
    navigation_target_urls,
)
from ops.browser.session_capability import (
    CAPABILITY_HEADER,
    BrowserSessionCapabilityError,
    derive_browser_session_capability,
)
from ops.browser.setup_values import normalize_browser_setup_fields
from ops.browser.signup import normalize_signup_fields
from ops.browser.takeover import ClearanceObservation, ClearanceProbeReason
from ops.browser.worker import BrowserObservation, BrowserSessionContext, HumanActionType
from ops.core.models import validate_vault_reference
from ops.core.secret_store import parse_vault_reference
from ops.providers.errors import ConfigurationRequiredError, ProviderOperationError

LOGGER = logging.getLogger("composio_ops.browser_service_client")

TOKEN_HEADER = "X-Browser-Service-Token"
OWNER_HEADER = "X-Browser-Session-Owner"

ReconcileOutcome = Literal["resumable", "session_lost", "unreachable"]
StartReconcileOutcome = Literal[
    "no_session",
    "orphan_closed",
    "unreachable",
    "close_failed",
]

_PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
_MAX_SCREENSHOT_BYTES = 8 * 1024 * 1024

# Health states mirrored from the service (no Browser Use wording here).
ProviderHealthState = Literal[
    "disabled",
    "not_configured",
    "configured_not_verified",
    "ready",
    "degraded",
    "capacity_exhausted",
    "unreachable",
    "version_mismatch",
]

# The RPC contract version this client speaks; a mismatch is reported, not guessed.
SUPPORTED_SERVICE_MAJOR = 1
_HEALTH_TIMEOUT_SECONDS = 2.0
# Mirrors ``Settings.onboarding_takeover_probe_timeout_seconds`` — default and
# bounds both. The value is clamped rather than trusted so an injected timeout
# cannot make one clearance probe outlive the interval it is polled on.
_DEFAULT_TAKEOVER_PROBE_TIMEOUT_SECONDS = 5.0
_MIN_TAKEOVER_PROBE_TIMEOUT_SECONDS = 1.0
_MAX_TAKEOVER_PROBE_TIMEOUT_SECONDS = 15.0
_HEALTH_STATES = frozenset(
    {
        "disabled",
        "not_configured",
        "configured_not_verified",
        "ready",
        "degraded",
        "capacity_exhausted",
        "unreachable",
        "version_mismatch",
    }
)


@dataclass(frozen=True, slots=True)
class BrowserServiceHealth:
    """Sanitized provider health for the Playwright path."""

    state: ProviderHealthState
    reason_code: str
    version: str = ""
    chromium_installed: bool = False
    context_launch_ok: bool = False
    capacity_total: int = 0
    capacity_in_use: int = 0
    janitor_running: bool = False


class BrowserServiceClient:
    """Provider-shaped RPC client for the out-of-process browser service."""

    provider_name = "playwright"
    # HITL uses either the screenshot endpoint or a short-lived interactive grant;
    # neither is a durable hosted URL, so this stays False.
    supports_live_url = False
    supports_screenshot = True
    # Chromium is in its OWN process now: an API restart cannot kill it, and
    # reattachment is verified against the service before being claimed.
    supports_restart_reattach = True
    # Generic orchestration adapters use this marker to pass the run scope only to
    # the isolated RPC client, without changing in-process/hosted provider contracts.
    requires_session_capability_scope = True
    # Canonical runtime uses this explicit marker to reserve and pass durable
    # one-operation broker grants. In-process providers never receive them.
    requires_secret_broker_grants = True
    # Only the isolated service can compare a continuation against its live,
    # process-local HITL generation at the same boundary that starts resume.
    supports_hitl_generation_cas = True

    def __init__(
        self,
        *,
        base_url: str,
        token: SecretStr | str,
        owner: str,
        capability_key: SecretStr | str | None = None,
        timeout_seconds: float = 315.0,
        takeover_probe_timeout_seconds: float = _DEFAULT_TAKEOVER_PROBE_TIMEOUT_SECONDS,
        client: httpx.AsyncClient | None = None,
        sync_client: httpx.Client | None = None,
    ) -> None:
        if not base_url:
            raise ConfigurationRequiredError(
                phase=3, capability="browser service", reason_code="browser_service_url_missing"
            )
        self._base_url = base_url.rstrip("/")
        self._token = token if isinstance(token, SecretStr) else SecretStr(token)
        self._capability_key = (
            capability_key
            if isinstance(capability_key, SecretStr)
            else SecretStr(capability_key)
            if capability_key is not None
            else None
        )
        self._owner = owner
        self._timeout = timeout_seconds
        # A clearance probe is bounded on its own, far tighter than the operation
        # budget above: it is polled on a 5 second interval, so a slow read must be
        # abandoned and reported as unread rather than queue behind its own poll.
        self._takeover_probe_timeout = max(
            _MIN_TAKEOVER_PROBE_TIMEOUT_SECONDS,
            min(float(takeover_probe_timeout_seconds), _MAX_TAKEOVER_PROBE_TIMEOUT_SECONDS),
        )
        self._client = client
        self._sync_client = sync_client
        # Sanitized per-session bookkeeping (never a URL with a query string).
        self._sessions: dict[str, str] = {}
        # The run allow-list the SERVICE confirmed it will enforce for a session.
        # Kept so the caller checks the same boundary before spending an RPC.
        self._session_hosts: dict[str, BrowserAllowedHosts] = {}

    # --- transport ------------------------------------------------------------
    def _derive_capability(self, scope: str) -> str:
        if self._capability_key is None:
            raise ConfigurationRequiredError(
                phase=3,
                capability="browser session authorization",
                reason_code="browser_session_capability_key_missing",
            )
        try:
            return derive_browser_session_capability(
                key=self._capability_key.get_secret_value(),
                owner=self._owner,
                scope=scope,
            )
        except BrowserSessionCapabilityError as exc:
            raise ProviderOperationError(
                capability="browser session authorization",
                reason_code=exc.reason_code,
            ) from None

    def _headers(self, *, capability_scope: str | None = None) -> dict[str, str]:
        # Token in a HEADER, never a query string (those land in access logs).
        headers = {
            TOKEN_HEADER: self._token.get_secret_value(),
            OWNER_HEADER: self._owner,
            "Content-Type": "application/json",
        }
        if capability_scope is not None:
            headers[CAPABILITY_HEADER] = self._derive_capability(capability_scope)
        return headers

    async def _request(
        self,
        method: str,
        path: str,
        *,
        json_body: Mapping[str, object] | None = None,
        timeout: float | None = None,
        capability_scope: str | None = None,
    ) -> httpx.Response:
        url = f"{self._base_url}{path}"
        client = self._client
        owns_client = client is None
        if client is None:
            client = httpx.AsyncClient(
                timeout=httpx.Timeout(timeout or self._timeout, connect=10.0),
                follow_redirects=False,
            )
        try:
            return await client.request(
                method,
                url,
                json=json_body,
                headers=self._headers(capability_scope=capability_scope),
                timeout=timeout or self._timeout,
            )
        finally:
            if owns_client:
                await client.aclose()

    @staticmethod
    def _reason(response: httpx.Response) -> str:
        """Extract the service's sanitized reason code (never its body text)."""

        try:
            payload = response.json()
        except ValueError:
            return f"http_{response.status_code}"
        if isinstance(payload, dict):
            detail = payload.get("detail") or payload.get("reason_code")
            if isinstance(detail, str) and detail and len(detail) <= 100:
                return detail
        return f"http_{response.status_code}"

    # --- provider surface -----------------------------------------------------
    async def start(
        self,
        profile_id: str | None,
        *,
        recipe: Any = None,
        app_slug: str = "",
        account_ref: str | None = None,
        secret_scope: str | None = None,
        use_storage_state: bool = False,
        live_view_mode: str = "screenshot",
        allowed_hosts: BrowserAllowedHosts | None = None,
        run_id: str | None = None,
    ) -> BrowserSessionContext:
        resolved_slug = app_slug or "unknown"
        # The run's allow-list travels as the flat pattern list plus the app slug,
        # and the service rebuilds it on the other side. Nothing ad-hoc crosses.
        patterns: tuple[str, ...] = ()
        if allowed_hosts is not None:
            if allowed_hosts.app_slug != resolved_slug:
                raise ProviderOperationError(
                    capability="browser service",
                    reason_code="browser_allow_list_app_mismatch",
                )
            patterns = allowed_hosts.patterns()
            if not patterns:
                raise ProviderOperationError(
                    capability="browser service",
                    reason_code="browser_allow_list_empty",
                )
        body: dict[str, object] = {
            "app_slug": resolved_slug,
            "profile_id": profile_id,
            "account_ref": account_ref,
            "secret_scope": secret_scope or "",
            "run_id": run_id or secret_scope or "",
            "live_view_mode": live_view_mode,
            "use_storage_state": use_storage_state,
            "allowed_host_patterns": list(patterns),
        }
        if recipe is not None:
            body["recipe_snapshot"] = (
                recipe.model_dump(mode="json") if hasattr(recipe, "model_dump") else recipe
            )
        try:
            response = await self._request(
                "POST",
                "/internal/browser/sessions",
                json_body=body,
                capability_scope=secret_scope or "",
            )
        except httpx.RequestError:
            raise ProviderOperationError(
                capability="browser service", reason_code="browser_service_unreachable"
            ) from None
        if response.status_code >= 400:
            raise ProviderOperationError(
                capability="browser service", reason_code=self._reason(response)
            )
        payload = response.json()
        session_id = str(payload.get("session_id") or "")
        if not session_id:
            raise ProviderOperationError(
                capability="browser service", reason_code="session_id_missing"
            )
        if allowed_hosts is not None:
            # Confinement is only real once the SERVICE confirms the allow-list it
            # will enforce. An older or misconfigured service that silently ignored
            # the list would otherwise leave an unconfined session running.
            enforced = payload.get("allowed_host_patterns")
            if not isinstance(enforced, list) or set(map(str, enforced)) != set(patterns):
                await self._abandon_session(session_id, capability_scope=secret_scope or "")
                raise ProviderOperationError(
                    capability="browser service",
                    reason_code="browser_allow_list_not_enforced",
                )
            self._session_hosts[session_id] = allowed_hosts
        self._sessions[session_id] = str(payload.get("app_slug") or "")
        now = datetime.now(UTC)
        return BrowserSessionContext(
            profile_id=profile_id or session_id,
            session_id=session_id,
            live_view_available=bool(payload.get("live_view_available", True)),
            allowed_domains=patterns,
            created_at=str(payload.get("created_at") or now.isoformat()),
            inactivity_expires_at=str(payload.get("maximum_expires_at") or now.isoformat()),
            maximum_expires_at=str(payload.get("maximum_expires_at") or now.isoformat()),
            capability_scope=secret_scope or "",
        )

    async def _abandon_session(self, session_id: str, *, capability_scope: str) -> None:
        """Best-effort teardown of a session this client refuses to use.

        A refused session must not be left holding capacity (or a browser) in the
        service. Teardown failure is not fatal here: the janitor and reconciliation
        remain the backstop, and the caller is about to receive a typed error.
        """

        with contextlib.suppress(Exception):
            await self._request(
                "DELETE",
                f"/internal/browser/sessions/{session_id}",
                timeout=30.0,
                capability_scope=capability_scope,
            )

    async def navigate_onboarding(
        self,
        context: BrowserSessionContext,
        research: Any,
        *,
        recipe: Any = None,
        sensitive_data: Mapping[str, str] | None = None,
        secret_grants: Mapping[str, str] | None = None,
        account_creation_requested: bool = False,
        signup_fields: Mapping[str, str] | None = None,
        setup_fields: Mapping[str, str] | None = None,
        credential_creation_policy: str = "reuse_only",
    ) -> BrowserObservation:
        return await self._drive(
            context,
            research,
            path="navigate",
            credential_refs=sensitive_data,
            secret_grants=secret_grants,
            recipe=recipe,
            signal=None,
            account_creation_requested=account_creation_requested,
            signup_fields=signup_fields,
            setup_fields=setup_fields,
            credential_creation_policy=credential_creation_policy,
        )

    async def resume_after_hitl(
        self,
        context: BrowserSessionContext,
        signal: str,
        research: Any = None,
        *,
        recipe: Any = None,
        sensitive_data: Mapping[str, str] | None = None,
        secret_grants: Mapping[str, str] | None = None,
        account_creation_requested: bool = False,
        signup_fields: Mapping[str, str] | None = None,
        setup_fields: Mapping[str, str] | None = None,
        credential_creation_policy: str = "reuse_only",
        provider_session_id: str | None = None,
        expected_hitl_generation: int | None = None,
    ) -> BrowserObservation:
        del provider_session_id  # the service session id IS the provider id here
        return await self._drive(
            context,
            research,
            path="resume",
            credential_refs=sensitive_data,
            secret_grants=secret_grants,
            recipe=recipe,
            signal=signal,
            account_creation_requested=account_creation_requested,
            signup_fields=signup_fields,
            setup_fields=setup_fields,
            credential_creation_policy=credential_creation_policy,
            expected_hitl_generation=expected_hitl_generation,
        )

    async def _drive(
        self,
        context: BrowserSessionContext,
        research: Any,
        *,
        path: str,
        credential_refs: Mapping[str, str] | None,
        secret_grants: Mapping[str, str] | None,
        recipe: Any = None,
        signal: str | None,
        account_creation_requested: bool = False,
        signup_fields: Mapping[str, str] | None = None,
        setup_fields: Mapping[str, str] | None = None,
        credential_creation_policy: str = "reuse_only",
        expected_hitl_generation: int | None = None,
    ) -> BrowserObservation:
        # Caller-side half of confinement: refuse to spend an RPC on a payload
        # whose destinations are outside the run's allow-list. The service enforces
        # the same boundary again on its own side, so neither half is load-bearing
        # alone.
        allowed = self._session_hosts.get(context.session_id)
        if allowed is not None and research is not None:
            denial = first_denied_navigation(navigation_target_urls(research), allowed)
            if denial is not None:
                raise ProviderOperationError(
                    capability="browser service",
                    reason_code=denial.reason_code,
                )
        refs = _vault_references_only(credential_refs)
        grants = _exact_broker_grants(refs, secret_grants)
        body: dict[str, object] = {
            "credential_refs": refs,
            "secret_grants": grants,
        }
        try:
            body["setup_fields"] = normalize_browser_setup_fields(setup_fields)
        except ValueError:
            raise ProviderOperationError(
                capability="browser service",
                reason_code="setup_fields_invalid",
            ) from None
        if recipe is not None:
            body["recipe_snapshot"] = (
                recipe.model_dump(mode="json") if hasattr(recipe, "model_dump") else recipe
            )
        if account_creation_requested:
            body["account_creation_requested"] = True
            try:
                body["signup_fields"] = normalize_signup_fields(signup_fields)
            except ValueError:
                raise ProviderOperationError(
                    capability="browser service",
                    reason_code="signup_fields_invalid",
                ) from None
        body["credential_creation_policy"] = credential_creation_policy
        if research is not None:
            body["research"] = (
                research.model_dump(mode="json") if hasattr(research, "model_dump") else research
            )
        elif path == "navigate":
            raise ProviderOperationError(
                capability="browser service", reason_code="verified_research_required"
            )
        if signal is not None:
            body["signal"] = signal
        if expected_hitl_generation is not None:
            if type(expected_hitl_generation) is not int or expected_hitl_generation <= 0:
                raise ProviderOperationError(
                    capability="browser service",
                    reason_code="hitl_generation_invalid",
                )
            body["expected_hitl_generation"] = expected_hitl_generation
        try:
            response = await self._request(
                "POST",
                f"/internal/browser/sessions/{context.session_id}/{path}",
                json_body=body,
                capability_scope=context.capability_scope,
            )
        except httpx.RequestError:
            raise ProviderOperationError(
                capability="browser service", reason_code="browser_service_unreachable"
            ) from None
        if response.status_code >= 400:
            raise ProviderOperationError(
                capability="browser service", reason_code=self._reason(response)
            )
        payload = response.json()
        session_payload = payload.get("session")
        raw_hitl_generation = (
            session_payload.get("hitl_generation") if isinstance(session_payload, dict) else None
        )
        hitl_generation = (
            raw_hitl_generation
            if type(raw_hitl_generation) is int and raw_hitl_generation >= 0
            else 0
        )
        observation_status = payload.get("status", "failed")
        if observation_status == "human_action_required" and hitl_generation <= 0:
            raise ProviderOperationError(
                capability="browser service",
                reason_code="hitl_generation_invalid",
            )
        return BrowserObservation(
            status=observation_status,
            current_url=payload.get("current_url", "https://unknown.invalid/"),
            page_title=payload.get("page_title") or "Browser step",
            developer_app_id=payload.get("developer_app_id"),
            human_action_type=payload.get("human_action_type"),
            human_instruction=payload.get("human_instruction"),
            credential_field_labels=tuple(payload.get("credential_field_labels") or ()),
            non_secret_notes=tuple(payload.get("non_secret_notes") or ()),
            reason_code=payload.get("reason_code"),
            hitl_generation=hitl_generation,
        )

    async def auto_capture_credentials(
        self,
        handle: str,
        app_slug: str,
        secret_store: object | None = None,
        *,
        recipe: Any = None,
        capability_scope: str,
        broker_grants: Mapping[str, str] | None = None,
        broker_grant: str | None = None,
    ) -> dict[str, str] | None:
        """Ask the service to capture into its vault; accept references only."""

        del secret_store  # the service uses its narrow API broker boundary
        known_slug = self._sessions.get(handle)
        if known_slug and known_slug != app_slug:
            raise ProviderOperationError(
                capability="browser service credential capture",
                reason_code="capture_app_mismatch",
            )
        capture_body: dict[str, object] = {
            "recipe_snapshot": (
                recipe.model_dump(mode="json") if hasattr(recipe, "model_dump") else recipe
            ),
        }
        if broker_grants:
            validated_grants = {
                kind: _validate_broker_grant(grant)
                for kind, grant in broker_grants.items()
                if isinstance(kind, str)
                and re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,99}", kind) is not None
            }
            if set(validated_grants) != set(broker_grants):
                raise ProviderOperationError(
                    capability="browser service credential capture",
                    reason_code="browser_secret_grant_invalid",
                )
            capture_body["broker_grants"] = validated_grants
        elif broker_grant is not None:
            capture_body["broker_grant"] = _validate_broker_grant(broker_grant)
        else:
            raise ProviderOperationError(
                capability="browser service credential capture",
                reason_code="browser_secret_grant_invalid",
            )
        try:
            response = await self._request(
                "POST",
                f"/internal/browser/sessions/{handle}/capture-credentials",
                json_body=capture_body,
                capability_scope=capability_scope,
            )
        except httpx.RequestError:
            raise ProviderOperationError(
                capability="browser service", reason_code="browser_service_unreachable"
            ) from None
        if response.status_code >= 400:
            raise ProviderOperationError(
                capability="browser service credential capture",
                reason_code=self._reason(response),
            )
        try:
            payload = response.json()
            if not isinstance(payload, dict) or set(payload) != {"credential_refs"}:
                raise ValueError("invalid response shape")
            raw_refs = payload["credential_refs"]
            if not isinstance(raw_refs, dict):
                raise ValueError("invalid reference mapping")
            refs: dict[str, str] = {}
            for kind, reference in raw_refs.items():
                if (
                    not isinstance(kind, str)
                    or re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,99}", kind) is None
                ):
                    raise ValueError("invalid credential kind")
                if not isinstance(reference, str):
                    raise ValueError("invalid credential reference")
                validated = validate_vault_reference(reference)
                parts = parse_vault_reference(validated)
                if parts.app_slug != app_slug or parts.kind != kind:
                    raise ValueError("credential reference binding mismatch")
                refs[kind] = validated
        except (ValueError, TypeError, KeyError):
            raise ProviderOperationError(
                capability="browser service credential capture",
                reason_code="invalid_capture_response",
            ) from None
        return refs or None

    async def session_status(self, session_id: str, *, capability_scope: str) -> tuple[bool, str]:
        """(exists, reason_code) straight from the service — never inferred."""

        try:
            response = await self._request(
                "GET",
                f"/internal/browser/sessions/{session_id}/status",
                timeout=15.0,
                capability_scope=capability_scope,
            )
        except httpx.RequestError:
            return False, "browser_service_unreachable"
        if response.status_code == 404:
            return False, "session_not_found"
        if response.status_code >= 400:
            return False, self._reason(response)
        payload = response.json()
        lifecycle = str(payload.get("lifecycle") or "")
        return lifecycle == "ACTIVE", lifecycle.casefold() or "unknown"

    async def probe_gate_clearance(
        self, session_id: str, *, capability_scope: str
    ) -> ClearanceObservation:
        """Read whether the human gate a paused run waits on is still present.

        Fail-closed mapping:

        * ``404`` with detail exactly ``session_not_found`` — absent session
          (pauses the run with ``session_unreattachable``, R2.6).
        * any other ``404`` — an older worker without this route, so nothing was
          read: ``probe_failed``, and the run keeps waiting.
        * ``410`` — ``session_max_age_exceeded`` (R2.5).
        * any other status, a bad body, a transport error, or the timeout —
          ``probe_failed``, never clearance.
        """

        try:
            response = await self._request(
                "GET",
                f"/internal/browser/sessions/{session_id}/gate-clearance",
                timeout=self._takeover_probe_timeout,
                capability_scope=capability_scope,
            )
        except (TypeError, AttributeError, AssertionError, NameError):
            raise  # a programming error must surface, never look like a probe result
        except Exception:
            # A transport error, the bounded timeout, or a configuration refusal
            # while building the request: nothing was read either way.
            return _unread_clearance()
        if response.status_code == 404:
            if self._reason(response) == "session_not_found":
                return _absent_clearance("session_not_found")
            return _unread_clearance()
        if response.status_code == 410:
            return _absent_clearance("session_max_age_exceeded")
        if response.status_code >= 400:
            return _unread_clearance()
        try:
            payload = response.json()
        except ValueError:
            return _unread_clearance()
        observation = _clearance_observation(payload)
        return observation if observation is not None else _unread_clearance()

    async def reconcile_session(
        self, session_id: str | None, *, capability_scope: str
    ) -> ReconcileOutcome:
        """Decide whether a PERSISTED session id is still usable after a restart.

        A stored id is never trusted on its own: the service is queried, and only
        an ACTIVE session is reported ``resumable``.
        """

        if not session_id:
            return "session_lost"
        exists, reason = await self.session_status(session_id, capability_scope=capability_scope)
        if exists:
            return "resumable"
        if reason == "browser_service_unreachable":
            return "unreachable"
        return "session_lost"

    async def reconcile_bound_sessions(
        self,
        *,
        app_slug: str,
        secret_scope: str,
        account_ref: str,
        run_id: str | None = None,
    ) -> tuple[str, ...]:
        """Find only sessions bound to this exact run-start authority.

        This closes the response-loss gap after create: the API can re-derive the
        run capability and discover its own orphan without enumerating another
        run's sessions.
        """

        try:
            response = await self._request(
                "POST",
                "/internal/browser/sessions/reconcile",
                json_body={
                    "app_slug": app_slug,
                    "secret_scope": secret_scope,
                    "account_ref": account_ref,
                    "run_id": run_id or secret_scope,
                },
                timeout=15.0,
                capability_scope=secret_scope,
            )
        except httpx.RequestError:
            raise ProviderOperationError(
                capability="browser service reconciliation",
                reason_code="browser_service_unreachable",
            ) from None
        if response.status_code >= 400:
            raise ProviderOperationError(
                capability="browser service reconciliation",
                reason_code=self._reason(response),
            )
        payload = response.json()
        session_ids = payload.get("session_ids") if isinstance(payload, dict) else None
        if not isinstance(session_ids, list):
            raise ProviderOperationError(
                capability="browser service reconciliation",
                reason_code="invalid_reconcile_response",
            )
        normalized: list[str] = []
        for session_id in session_ids:
            if (
                not isinstance(session_id, str)
                or re.fullmatch(r"[A-Za-z0-9_-]{1,180}", session_id) is None
            ):
                raise ProviderOperationError(
                    capability="browser service reconciliation",
                    reason_code="invalid_reconcile_response",
                )
            normalized.append(session_id)
        return tuple(normalized)

    async def screenshot(self, session_id: str, *, capability_scope: str) -> bytes | None:
        try:
            response = await self._request(
                "GET",
                f"/internal/browser/sessions/{session_id}/screenshot",
                timeout=30.0,
                capability_scope=capability_scope,
            )
        except httpx.RequestError:
            return None
        if response.status_code != 200:
            return None
        data = response.content
        return data if isinstance(data, bytes) and data else None

    def latest_screenshot(
        self, session_id: str, *, capability_scope: str
    ) -> tuple[bytes, str] | None:
        """Fetch one current masked frame through the isolated-service RPC.

        ``RunService`` exposes a synchronous projection surface, so the production
        RPC adapter needs a synchronous counterpart to :meth:`screenshot`. The
        previous adapter omitted this method entirely; consequently every
        Playwright live-view request reported unavailable even while Chromium was
        active. The service remains the authority for capture safety and returns
        409 whenever a frame cannot be exposed.
        """

        url = f"{self._base_url}/internal/browser/sessions/{session_id}/screenshot"
        client = self._sync_client
        owns_client = client is None
        if client is None:
            client = httpx.Client(
                timeout=httpx.Timeout(30.0, connect=10.0),
                follow_redirects=False,
            )
        try:
            response = client.get(
                url,
                headers=self._headers(capability_scope=capability_scope),
                timeout=30.0,
            )
        except httpx.RequestError:
            return None
        finally:
            if owns_client:
                client.close()
        if response.status_code != 200:
            return None
        data = response.content
        if not data.startswith(_PNG_SIGNATURE) or len(data) > _MAX_SCREENSHOT_BYTES:
            return None
        return data, datetime.now(UTC).isoformat()

    async def request_live_view(
        self, session_id: str, *, capability_scope: str
    ) -> tuple[str, str | None, str, bool]:
        """Request a live grant: (mode, url_or_None, expires_at, control_allowed).

        The URL is for IMMEDIATE operator use and must never be persisted to run
        state, logs, or checkpoints.
        """

        try:
            response = await self._request(
                "POST",
                f"/internal/browser/sessions/{session_id}/live-view",
                timeout=20.0,
                capability_scope=capability_scope,
            )
        except httpx.RequestError:
            return "screenshot", None, "", False
        if response.status_code >= 400:
            return "screenshot", None, "", False
        payload = response.json()
        return (
            str(payload.get("mode") or "screenshot"),
            payload.get("url"),
            str(payload.get("expires_at") or ""),
            payload.get("control_allowed") is True,
        )

    def request_live_view_sync(
        self, session_id: str, *, capability_scope: str
    ) -> tuple[str, str, str, bool] | None:
        """Mint one fresh view/control grant for immediate server-side projection.

        The returned URL is intentionally not cached on this client. Its only
        consumer converts it to a same-origin path in the Next.js server action.
        """

        url = f"{self._base_url}/internal/browser/sessions/{session_id}/live-view"
        client = self._sync_client
        owns_client = client is None
        if client is None:
            client = httpx.Client(
                timeout=httpx.Timeout(20.0, connect=10.0),
                follow_redirects=False,
            )
        try:
            response = client.post(
                url,
                headers=self._headers(capability_scope=capability_scope),
                timeout=20.0,
            )
        except httpx.RequestError:
            return None
        finally:
            if owns_client:
                client.close()
        if response.status_code >= 400:
            return None
        try:
            payload = response.json()
        except ValueError:
            return None
        mode = payload.get("mode")
        grant_url = payload.get("url")
        expires_at = payload.get("expires_at")
        if mode != "interactive_remote" or not isinstance(grant_url, str):
            return None
        return mode, grant_url, str(expires_at or ""), payload.get("control_allowed") is True

    async def stop(self, context: BrowserSessionContext) -> None:
        try:
            response = await self._request(
                "DELETE",
                f"/internal/browser/sessions/{context.session_id}",
                timeout=60.0,
                capability_scope=context.capability_scope,
            )
        except httpx.RequestError:
            LOGGER.warning("browser service unreachable while stopping a session")
            return
        if response.status_code >= 400:
            LOGGER.warning("browser service refused session teardown")
            return
        try:
            reason_code = str(response.json().get("reason_code") or "")
        except (AttributeError, ValueError):
            LOGGER.warning("browser service returned an invalid teardown response")
            return
        if reason_code.endswith(":teardown_failed"):
            # Keep local bookkeeping so reconciliation/another stop can retry.
            LOGGER.warning("browser service session teardown remains pending")
            return
        self._sessions.pop(context.session_id, None)
        self._session_hosts.pop(context.session_id, None)

    async def close(self) -> None:
        """Close the owned HTTP client (sessions live on in the service)."""

        if self._client is not None:
            return  # an injected client is owned by the caller
        return

    def provider_session_id(self, handle: str) -> str | None:
        """The service session id IS the durable provider id."""

        return handle if handle in self._sessions or handle else None

    def live_url(self, session_id: str) -> str | None:
        """No durable hosted URL exists for this provider."""

        del session_id
        return None

    async def health(
        self, *, timeout_seconds: float = _HEALTH_TIMEOUT_SECONDS
    ) -> BrowserServiceHealth:
        """Fast cached health, including strict RPC version compatibility."""

        try:
            response = await self._request(
                "GET",
                "/internal/health",
                timeout=max(0.25, min(float(timeout_seconds), 5.0)),
            )
        except httpx.RequestError:
            return BrowserServiceHealth(
                state="unreachable", reason_code="browser_service_unreachable"
            )
        if response.status_code >= 400:
            return BrowserServiceHealth(state="degraded", reason_code=self._reason(response))
        try:
            payload = response.json()
        except ValueError:
            return BrowserServiceHealth(
                state="degraded", reason_code="browser_service_health_invalid"
            )
        if not isinstance(payload, dict):
            return BrowserServiceHealth(
                state="degraded", reason_code="browser_service_health_invalid"
            )
        version_value = payload.get("version")
        version = version_value if isinstance(version_value, str) else ""
        reason_value = payload.get("reason_code")
        reason_code = reason_value if isinstance(reason_value, str) else ""
        if len(version) > 64 or re.fullmatch(r"[a-z0-9][a-z0-9_:-]{0,63}", reason_code) is None:
            return BrowserServiceHealth(
                state="degraded", reason_code="browser_service_health_invalid"
            )
        major = version.split(".", 1)[0] if version else ""
        if not major.isdigit():
            return BrowserServiceHealth(
                state="version_mismatch",
                reason_code="service_version_invalid",
                version=version,
            )
        if int(major) != SUPPORTED_SERVICE_MAJOR:
            return BrowserServiceHealth(
                state="version_mismatch",
                reason_code=f"service_major_{major}_client_major_{SUPPORTED_SERVICE_MAJOR}",
                version=version,
            )
        state = str(payload.get("state") or "configured_not_verified")
        boolean_fields = (
            "chromium_installed",
            "context_launch_ok",
            "janitor_running",
        )
        capacity_fields = ("capacity_total", "capacity_in_use")
        if (
            state not in _HEALTH_STATES
            or any(type(payload.get(name)) is not bool for name in boolean_fields)
            or any(
                type(payload.get(name)) is not int or int(payload[name]) < 0
                for name in capacity_fields
            )
            or int(payload["capacity_in_use"]) > int(payload["capacity_total"])
        ):
            return BrowserServiceHealth(
                state="degraded",
                reason_code="browser_service_health_invalid",
                version=version,
            )
        return BrowserServiceHealth(
            state=state,  # type: ignore[arg-type]
            reason_code=reason_code,
            version=version,
            chromium_installed=payload["chromium_installed"],
            context_launch_ok=payload["context_launch_ok"],
            capacity_total=payload["capacity_total"],
            capacity_in_use=payload["capacity_in_use"],
            janitor_running=payload["janitor_running"],
        )


# The lifecycle values a clearance report may name, and the probe reasons the
# SERVICE side may name (``session_not_found`` is the client's own answer to a 404
# and can never arrive in a body). Both are membership tables rather than sets so
# a validated value keeps its closed type: an unrecognised spelling is refused,
# not passed through.
_CLEARANCE_LIFECYCLES: frozenset[str] = frozenset({"ACTIVE", "CLOSING", "CLOSED"})
_SERVICE_PROBE_REASONS: dict[str, ClearanceProbeReason] = {
    "observed": "observed",
    "operation_in_flight": "operation_in_flight",
    "probe_failed": "probe_failed",
    "session_max_age_exceeded": "session_max_age_exceeded",
}
# A gate value the decision function does not recognise would compare unequal to
# the gate that parked the run and be read as "the gate is gone", so an unknown
# gate is refused here instead of becoming a continuation.
_CLEARANCE_GATES: dict[str, HumanActionType] = {
    str(value): value for value in get_args(HumanActionType)
}
_CLEARANCE_BOOLEAN_FIELDS = ("hitl_pending", "attached", "final_probe_owed", "cleared")


def _unread_clearance() -> ClearanceObservation:
    """The observation for a read that could not happen.

    ``lifecycle``/``hitl_pending`` restate what the run is already known to be, so
    an unread probe never pauses it for a session state nobody observed.
    """

    return ClearanceObservation(
        session_present=True,
        lifecycle="ACTIVE",
        hitl_pending=True,
        attached=False,
        final_probe_owed=False,
        gate=None,
        probe_reason_code="probe_failed",
        hitl_generation=0,
    )


def _absent_clearance(reason: ClearanceProbeReason) -> ClearanceObservation:
    """The observation for a session the service no longer has.

    One shape for both causes; the ``reason`` is what the decision reads.
    """

    return ClearanceObservation(
        session_present=False,
        lifecycle="",
        hitl_pending=False,
        attached=False,
        final_probe_owed=False,
        gate=None,
        probe_reason_code=reason,
        hitl_generation=0,
    )


def _clearance_observation(payload: object) -> ClearanceObservation | None:
    """Validate one clearance report, or ``None`` when it cannot be trusted.

    ``cleared`` must agree with "the page was read and no gate was on it"; a body
    that disagrees with itself is refused rather than reconciled.
    """

    if not isinstance(payload, dict):
        return None
    if any(type(payload.get(name)) is not bool for name in _CLEARANCE_BOOLEAN_FIELDS):
        return None
    lifecycle = payload.get("lifecycle")
    if not isinstance(lifecycle, str) or lifecycle not in _CLEARANCE_LIFECYCLES:
        return None
    raw_reason = payload.get("probe_reason_code")
    reason_code = _SERVICE_PROBE_REASONS.get(raw_reason) if isinstance(raw_reason, str) else None
    if reason_code is None:
        return None
    generation = payload.get("hitl_generation")
    if type(generation) is not int or generation < 0:
        return None
    raw_gate = payload.get("gate")
    gate: HumanActionType | None = None
    if raw_gate is not None:
        gate = _CLEARANCE_GATES.get(raw_gate) if isinstance(raw_gate, str) else None
        if gate is None:
            return None
    if payload["cleared"] is not (reason_code == "observed" and gate is None):
        return None
    return ClearanceObservation(
        session_present=True,
        lifecycle=lifecycle,
        hitl_pending=payload["hitl_pending"],
        attached=payload["attached"],
        final_probe_owed=payload["final_probe_owed"],
        gate=gate,
        probe_reason_code=reason_code,
        hitl_generation=generation,
    )


# The only credential field names that may cross the RPC boundary. An unknown name
# is refused rather than forwarded, so a new secret cannot be added by accident.
_ALLOWED_BROWSER_SECRET_FIELDS: frozenset[str] = frozenset(
    {"login_email", "login_password", "login_otp", "login_verification_url"}
)
_BROKER_GRANT = re.compile(r"^bsg_[A-Za-z0-9_-]{43}$")


def _validate_broker_grant(value: str) -> str:
    if not isinstance(value, str) or _BROKER_GRANT.fullmatch(value) is None:
        raise ProviderOperationError(
            capability="browser secret broker",
            reason_code="browser_secret_grant_invalid",
        )
    return value


def _exact_broker_grants(
    references: Mapping[str, str],
    values: Mapping[str, str] | None,
) -> dict[str, str]:
    grants = dict(values or {})
    if set(grants) != set(references):
        raise ProviderOperationError(
            capability="browser secret broker",
            reason_code="browser_secret_grant_invalid",
        )
    return {name: _validate_broker_grant(grant) for name, grant in grants.items()}


def _vault_references_only(values: Mapping[str, str] | None) -> dict[str, str]:
    """Validate that every credential is an opaque ``vault://`` reference.

    Previously a raw value was silently DROPPED here. That looked safe but broke
    login in a way nobody could diagnose: the service received an empty mapping and
    reported a generic navigation failure, with no indication that credentials had
    been discarded. Raw values are now a typed ERROR, so the caller learns it must
    store a transient reference first.

    An unrecognised field name is likewise refused rather than forwarded.
    """

    if not values:
        return {}
    refs: dict[str, str] = {}
    for name, value in values.items():
        if name not in _ALLOWED_BROWSER_SECRET_FIELDS:
            raise ProviderOperationError(
                capability="browser service secrets",
                reason_code="browser_secret_field_not_allowed",
            )
        if not (isinstance(value, str) and value.startswith("vault://")):
            raise ProviderOperationError(
                capability="browser service secrets",
                reason_code="raw_credentials_not_allowed_over_rpc",
            )
        try:
            refs[name] = validate_vault_reference(value)
        except ValueError:
            raise ProviderOperationError(
                capability="browser service secrets",
                reason_code="malformed_vault_reference",
            ) from None
    return refs


__all__ = [
    "ALLOWED_BROWSER_SECRET_FIELDS",
    "CAPABILITY_HEADER",
    "OWNER_HEADER",
    "SUPPORTED_SERVICE_MAJOR",
    "TOKEN_HEADER",
    "BrowserServiceClient",
    "BrowserServiceHealth",
    "ProviderHealthState",
    "ReconcileOutcome",
]

# Public alias for tests and callers that need to know the permitted field set.
ALLOWED_BROWSER_SECRET_FIELDS = _ALLOWED_BROWSER_SECRET_FIELDS
