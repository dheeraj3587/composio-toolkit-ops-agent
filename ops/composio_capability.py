"""Read-only Composio toolkit capability preflight.

Before any gated outreach is attempted, this boundary answers a single
question: can Composio itself already integrate the app, and if so, in what
state? It performs no side effect (no email, no browser, no credential write)
and no mutation. The Composio SDK is imported lazily and only when configured;
tests inject a fake catalog/connection client so the classification is fully
offline.

Routing precedence encoded by :func:`classify_capability`:

* A ``composio_ready`` — toolkit available and an active connected account
  already covers the requested tools: neither outreach nor browser onboarding
  is needed.
* B ``connection_required`` — toolkit available with managed auth but no active
  connection: a Composio connect flow is surfaced; no outreach.
* C ``custom_auth_or_approval_required`` — toolkit available but custom auth or
  vendor approval is required: the verified P1 gated route is preserved and
  outreach is allowed only when verified research shows approval/contact is
  required.
* D ``toolkit_unavailable`` — no Composio toolkit matches: fall back entirely to
  the verified P1 route (self_serve -> browser, gated -> controlled outreach).
* ``configuration_required`` — Composio is not configured, so the capability
  cannot be checked and no external action is taken.
"""

from __future__ import annotations

import asyncio
import importlib
import unicodedata
from collections.abc import Sequence
from typing import Any, Literal, Protocol

from pydantic import Field

from ops.config import Settings
from ops.models import StrictModel

CapabilityState = Literal[
    "composio_ready",
    "connection_required",
    "custom_auth_or_approval_required",
    "toolkit_unavailable",
    "configuration_required",
]


class ComposioPreflightError(RuntimeError):
    """A non-authoritative Composio failure (auth, timeout, transport, unknown).

    This is intentionally distinct from an authoritative "toolkit not found"
    result. It is never silently converted into ``toolkit_unavailable``; the
    preflight fails closed to ``configuration_required`` instead so a provider
    outage cannot fabricate readiness or unlock the P1 fallback route.
    """

    def __init__(self, reason_code: str) -> None:
        super().__init__(reason_code)
        self.reason_code = reason_code


class ToolkitInfo(StrictModel):
    """A sanitized Composio toolkit descriptor (no secrets, no tokens)."""

    slug: str = Field(min_length=1, max_length=120)
    available: bool
    auth_schemes: tuple[str, ...] = ()
    managed_auth: bool = False
    tools: tuple[str, ...] = ()


class ComposioCapabilityReport(StrictModel):
    """The truthful, sanitized outcome of a single capability preflight."""

    app_slug: str = Field(min_length=1, max_length=120)
    toolkit_available: bool
    toolkit_slug: str | None
    required_auth_schemes: tuple[str, ...]
    managed_auth_available: bool
    active_connected_account: bool
    required_tools_present: bool
    capability_state: CapabilityState
    reason_code: str = Field(min_length=1, max_length=100)
    detail: str = Field(min_length=1, max_length=500)

    @property
    def p1_fallback_allowed(self) -> bool:
        """The verified P1 route (gated outreach or self-serve browser) may run.

        This is true only when Composio cannot already integrate the app: either
        it needs custom auth/vendor approval, or no toolkit exists. composio_ready
        and connection_required suppress the P1 fallback, and an unconfigured or
        errored preflight fails closed.
        """

        return self.capability_state in {
            "custom_auth_or_approval_required",
            "toolkit_unavailable",
        }

    @property
    def outreach_allowed(self) -> bool:
        """Gated Gmail outreach may proceed (same predicate as the P1 fallback)."""

        return self.p1_fallback_allowed


class ComposioToolkitCatalog(Protocol):
    """Read-only Composio catalog + connection queries; injected as a fake in tests."""

    async def get_toolkit(self, slug: str) -> ToolkitInfo | None: ...

    async def has_active_connection(self, toolkit_slug: str) -> bool: ...


def normalize_app_slug(value: str) -> str:
    """Normalize an app name/slug to the catalog lookup key."""

    normalized = unicodedata.normalize("NFKC", value).strip().casefold()
    collapsed = "-".join(part for part in normalized.replace("_", "-").split() if part)
    return collapsed or normalized


def classify_capability(
    *,
    toolkit: ToolkitInfo | None,
    active_connection: bool,
    required_tools: Sequence[str],
) -> tuple[CapabilityState, str, str]:
    """Apply the A-D routing precedence to a toolkit descriptor."""

    if toolkit is None or not toolkit.available:
        return (
            "toolkit_unavailable",
            "composio_toolkit_absent",
            "No Composio toolkit matches this app; the verified P1 route is used.",
        )
    tools_present = not required_tools or set(required_tools).issubset(set(toolkit.tools))
    if active_connection and tools_present:
        return (
            "composio_ready",
            "composio_connection_active",
            "A Composio toolkit and an active connected account already cover this app.",
        )
    if not active_connection and toolkit.managed_auth:
        return (
            "connection_required",
            "composio_connection_missing",
            "The Composio toolkit supports managed auth; connect an account before use.",
        )
    return (
        "custom_auth_or_approval_required",
        "composio_custom_auth_or_approval_required",
        "The Composio toolkit needs custom auth or vendor approval; the gated route is preserved.",
    )


class ComposioCapabilityPreflight:
    """Evaluate Composio capability for an app without any side effect."""

    def __init__(
        self,
        *,
        settings: Settings | None = None,
        catalog: ComposioToolkitCatalog | None = None,
    ) -> None:
        self._settings = settings or Settings.from_env()
        self._catalog = catalog

    async def evaluate(
        self,
        *,
        app_name: str,
        app_slug: str | None = None,
        required_tools: Sequence[str] = (),
    ) -> ComposioCapabilityReport:
        del app_name  # normalization uses the slug; the name is accepted for parity
        slug = normalize_app_slug(app_slug or "")
        catalog = self._catalog or self._build_catalog()
        if catalog is None:
            return ComposioCapabilityReport(
                app_slug=slug,
                toolkit_available=False,
                toolkit_slug=None,
                required_auth_schemes=(),
                managed_auth_available=False,
                active_connected_account=False,
                required_tools_present=False,
                capability_state="configuration_required",
                reason_code="composio_not_configured",
                detail="Composio is not configured; the toolkit capability cannot be checked.",
            )

        try:
            toolkit = await catalog.get_toolkit(slug)
            active = False
            if toolkit is not None and toolkit.available:
                active = await catalog.has_active_connection(toolkit.slug)
        except ComposioPreflightError as exc:
            # Fail closed: a provider error is never a toolkit-absence signal.
            return ComposioCapabilityReport(
                app_slug=slug,
                toolkit_available=False,
                toolkit_slug=None,
                required_auth_schemes=(),
                managed_auth_available=False,
                active_connected_account=False,
                required_tools_present=False,
                capability_state="configuration_required",
                reason_code=exc.reason_code,
                detail=(
                    "The Composio capability could not be verified due to a provider error; "
                    "no external action is taken and the P1 fallback stays closed."
                ),
            )
        state, reason_code, detail = classify_capability(
            toolkit=toolkit,
            active_connection=active,
            required_tools=required_tools,
        )
        return ComposioCapabilityReport(
            app_slug=slug,
            toolkit_available=bool(toolkit is not None and toolkit.available),
            toolkit_slug=toolkit.slug if toolkit is not None else None,
            required_auth_schemes=toolkit.auth_schemes if toolkit is not None else (),
            managed_auth_available=bool(toolkit is not None and toolkit.managed_auth),
            active_connected_account=active,
            required_tools_present=(
                not required_tools
                or (toolkit is not None and set(required_tools).issubset(set(toolkit.tools)))
            ),
            capability_state=state,
            reason_code=reason_code,
            detail=detail,
        )

    def _build_catalog(self) -> ComposioToolkitCatalog | None:
        if self._settings.composio_api_key is None:
            return None
        return _ComposioToolkitCatalog(self._settings)


class _ComposioToolkitCatalog:
    """Best-effort live Composio catalog adapter (lazy SDK import, fail-closed).

    Any SDK error is treated as an absent toolkit or inactive connection so a
    catalog failure never fabricates readiness or blocks the verified P1 route.
    Offline tests always inject a fake catalog, so this path is not exercised
    by the default suite.
    """

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._client: object | None = None

    def _client_instance(self) -> object:
        if self._client is None:
            module = importlib.import_module("composio")
            client_type = module.Composio
            if self._settings.composio_api_key is None:  # pragma: no cover - guarded above
                raise RuntimeError("Composio configuration is missing")
            self._client = client_type(
                api_key=self._settings.composio_api_key.get_secret_value(),
                allow_tracking=False,
            )
        return self._client

    async def get_toolkit(self, slug: str) -> ToolkitInfo | None:
        return await asyncio.to_thread(self._get_toolkit_sync, slug)

    def _get_toolkit_sync(self, slug: str) -> ToolkitInfo | None:  # pragma: no cover - live only
        client = self._client_instance()
        try:
            toolkit = client.toolkits.get(slug=slug)  # type: ignore[attr-defined]
        except Exception as exc:
            if _is_not_found(exc):
                return None
            raise ComposioPreflightError(_provider_reason_code(exc)) from None
        data = _model_dump(toolkit)
        resolved_slug = str(data.get("slug") or slug)
        enabled = data.get("enabled")
        available = True if enabled is None else bool(enabled)
        managed = bool(data.get("composio_managed_auth", False))
        schemes: list[str] = [
            str(scheme)
            for scheme in (data.get("composio_managed_auth_schemes") or [])
            if scheme
        ]
        for detail in data.get("auth_config_details") or []:
            if isinstance(detail, dict) and detail.get("mode"):
                schemes.append(str(detail["mode"]))
        auth_schemes = tuple(dict.fromkeys(schemes))
        return ToolkitInfo(
            slug=resolved_slug,
            available=available,
            auth_schemes=auth_schemes,
            managed_auth=managed,
            tools=(),
        )

    async def has_active_connection(self, toolkit_slug: str) -> bool:
        return await asyncio.to_thread(self._has_active_connection_sync, toolkit_slug)

    def _has_active_connection_sync(
        self, toolkit_slug: str
    ) -> bool:  # pragma: no cover - live only
        client = self._client_instance()
        try:
            accounts = client.connected_accounts.list(  # type: ignore[attr-defined]
                toolkit_slugs=[toolkit_slug],
                user_ids=[self._settings.composio_user_id],
                statuses=["ACTIVE"],
                limit=1,
            )
        except Exception as exc:
            raise ComposioPreflightError(_provider_reason_code(exc)) from None
        data = _model_dump(accounts)
        items = data.get("items") or []
        for item in items:
            if isinstance(item, dict) and str(item.get("status", "")).upper() == "ACTIVE":
                return True
        return False


def _model_dump(value: object) -> dict[str, Any]:  # pragma: no cover - live only
    """Read documented public fields only; never import generated response models."""

    dump = getattr(value, "model_dump", None)
    if callable(dump):
        result = dump(mode="python")
        if isinstance(result, dict):
            return result
    return {}


def _is_not_found(exc: Exception) -> bool:  # pragma: no cover - live only
    if getattr(exc, "status_code", None) == 404:
        return True
    return type(exc).__name__ == "NotFoundError"


def _provider_reason_code(exc: Exception) -> str:  # pragma: no cover - live only
    name = type(exc).__name__
    status = getattr(exc, "status_code", None)
    if name in {"AuthenticationError", "PermissionDeniedError"} or status in {401, 403}:
        return "composio_authentication_failed"
    if name in {"APITimeoutError"} or status in {408}:
        return "composio_request_timeout"
    if name in {"RateLimitError"} or status == 429:
        return "composio_rate_limited"
    if name in {"APIConnectionError", "APIConnectionTimeoutError"}:
        return "composio_transport_error"
    return "composio_preflight_failed"


__all__ = [
    "CapabilityState",
    "ComposioCapabilityPreflight",
    "ComposioCapabilityReport",
    "ComposioPreflightError",
    "ComposioToolkitCatalog",
    "ToolkitInfo",
    "classify_capability",
    "normalize_app_slug",
]
