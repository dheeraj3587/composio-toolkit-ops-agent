"""Browser-service configuration (environment-backed, secret-safe).

Deliberately separate from ``ops.config.Settings``: the browser service is its
own process with its own, much smaller, configuration surface. The shared RPC
token is a ``SecretStr`` so it can never be printed by ``repr``/``str``.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field, SecretStr, model_validator


class BrowserServiceSettings(BaseModel):
    """Runtime configuration for the isolated browser service."""

    model_config = ConfigDict(extra="forbid", frozen=True, hide_input_in_errors=True)

    # Shared secret for internal RPC. Absent => the service refuses every request
    # (fail closed), so an unconfigured deployment is inert rather than open.
    service_token: SecretStr | None = Field(default=None, repr=False)

    # Bind address/port. In Compose this is reachable only on the private network.
    host: str = "0.0.0.0"  # noqa: S104 - private Compose network only, never published
    port: int = Field(default=8081, ge=1, le=65_535)

    # Session bounds (the service, not the caller, owns these).
    max_sessions: int = Field(default=2, ge=1, le=10)
    inactivity_seconds: int = Field(default=900, ge=30, le=86_400)
    maximum_age_seconds: int = Field(default=14_400, ge=60, le=172_800)
    # How long the janitor waits for in-flight operations before cancelling them.
    drain_seconds: float = Field(default=10.0, ge=0.5, le=120.0)

    # Request bounds.
    max_request_bytes: int = Field(default=256 * 1024, ge=1_024, le=8 * 1024 * 1024)
    operation_timeout_seconds: float = Field(default=120.0, ge=1.0, le=600.0)

    # Interactive HITL (noVNC). OFF by default AND currently REJECTED when set true
    # (see the validator below): the end-to-end operator-facing surface — a
    # same-origin noVNC HTML client, an authenticated API WebSocket proxy, and
    # per-session display isolation — is not implemented, so enabling it would only
    # hand out an unusable URL. Screenshot HITL is unaffected. This flag is retained
    # so the eventual implementation has a switch, but it fails closed today.
    interactive_hitl_enabled: bool = False
    novnc_port: int = Field(default=6080, ge=1, le=65_535)
    # x11vnc's port INSIDE this container. Only ever reached over loopback, so it
    # is never published and never accepted from a caller.
    vnc_port: int = Field(default=5900, ge=1, le=65_535)
    live_view_token_seconds: int = Field(default=300, ge=30, le=3_600)
    # Private-network base for the grant URL. Configuration-supplied ONLY — never
    # derived from a request header, page content, or a redirect (a Host-header
    # derived URL would let a caller point an operator at an attacker's origin).
    novnc_base_url: str = "http://browser-worker:8081"

    # Encrypted authenticated-browser-state directory (owner-only, 0700).
    storage_state_dir: Path = Path("/browser-data/storage-state")
    # Key used to encrypt storage state at rest. Absent => storage state is not
    # persisted at all (rather than persisted in the clear).
    storage_state_key: SecretStr | None = Field(default=None, repr=False)

    @model_validator(mode="after")
    def _reject_unusable_interactive_hitl(self) -> BrowserServiceSettings:
        """Fail closed on interactive HITL rather than serving an unusable URL.

        The interactive path is not yet operator-usable (no same-origin noVNC HTML
        client, no authenticated API WebSocket proxy, no per-session display
        isolation). Until that end-to-end surface exists and is tested, enabling
        the flag is a configuration error — a flag that *looks* functional but
        produces a dead URL is worse than an honestly disabled one.
        """

        if self.interactive_hitl_enabled:
            raise ValueError(
                "interactive HITL is not yet operator-usable; "
                "BROWSER_INTERACTIVE_HITL_ENABLED must remain false "
                "(screenshot HITL is unaffected)"
            )
        return self

    @property
    def token_configured(self) -> bool:
        return self.service_token is not None

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> BrowserServiceSettings:
        source: Mapping[str, str] = env if env is not None else os.environ

        def _text(name: str) -> str | None:
            value = source.get(name)
            if value is None:
                return None
            stripped = value.strip()
            return stripped or None

        def _int(name: str, default: int) -> int:
            raw = _text(name)
            if raw is None:
                return default
            try:
                return int(raw)
            except ValueError:
                raise ValueError(f"{name} must be an integer") from None

        def _float(name: str, default: float) -> float:
            raw = _text(name)
            if raw is None:
                return default
            try:
                return float(raw)
            except ValueError:
                raise ValueError(f"{name} must be a number") from None

        def _bool(name: str, default: bool) -> bool:
            raw = _text(name)
            if raw is None:
                return default
            lowered = raw.casefold()
            if lowered in {"1", "true", "yes", "on"}:
                return True
            if lowered in {"0", "false", "no", "off"}:
                return False
            raise ValueError(f"{name} must be true or false")

        token = _text("BROWSER_SERVICE_TOKEN")
        storage_key = _text("BROWSER_STORAGE_STATE_KEY") or _text("SECRET_VAULT_KEY")
        return cls(
            service_token=SecretStr(token) if token else None,
            host=_text("BROWSER_SERVICE_HOST") or "0.0.0.0",  # noqa: S104 - private network
            port=_int("BROWSER_SERVICE_PORT", 8081),
            max_sessions=_int("PLAYWRIGHT_MAX_SESSIONS", 2),
            inactivity_seconds=_int("BROWSER_SESSION_INACTIVITY_SECONDS", 900),
            maximum_age_seconds=_int("BROWSER_SESSION_MAX_AGE_SECONDS", 14_400),
            drain_seconds=_float("BROWSER_SESSION_DRAIN_SECONDS", 10.0),
            max_request_bytes=_int("BROWSER_SERVICE_MAX_REQUEST_BYTES", 256 * 1024),
            operation_timeout_seconds=_float("BROWSER_OPERATION_TIMEOUT_SECONDS", 120.0),
            interactive_hitl_enabled=_bool("BROWSER_INTERACTIVE_HITL_ENABLED", False),
            novnc_port=_int("BROWSER_NOVNC_PORT", 6080),
            vnc_port=_int("BROWSER_VNC_PORT", 5900),
            live_view_token_seconds=_int("BROWSER_LIVE_VIEW_TOKEN_SECONDS", 300),
            novnc_base_url=(_text("BROWSER_NOVNC_BASE_URL") or "http://browser-worker:8081").rstrip(
                "/"
            ),
            storage_state_dir=Path(
                _text("BROWSER_STORAGE_STATE_DIR") or "/browser-data/storage-state"
            ),
            storage_state_key=SecretStr(storage_key) if storage_key else None,
        )


__all__ = ["BrowserServiceSettings"]
