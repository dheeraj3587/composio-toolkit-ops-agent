"""Browser-service configuration (environment-backed, secret-safe).

Deliberately separate from ``ops.config.Settings``: the browser service is its
own process with its own, much smaller, configuration surface. The shared RPC
token is a ``SecretStr`` so it can never be printed by ``repr``/``str``.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from pathlib import Path
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator, model_validator

from browser_service.display_pool import MAX_DISPLAY_SLOTS


class BrowserServiceSettings(BaseModel):
    """Runtime configuration for the isolated browser service."""

    model_config = ConfigDict(extra="forbid", frozen=True, hide_input_in_errors=True)

    # Shared secret for internal RPC. Absent => the service refuses every request
    # (fail closed), so an unconfigured deployment is inert rather than open.
    service_token: SecretStr | None = Field(default=None, repr=False)
    # A separate capability token for the two-method API secret broker. It must
    # never be the browser-service RPC token or the web/API control-plane token.
    secret_broker_token: SecretStr | None = Field(default=None, repr=False)
    secret_broker_url: str = "http://api:8000"
    secret_broker_timeout_seconds: float = Field(default=10.0, ge=1.0, le=30.0)

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

    # Interactive HITL (noVNC). OFF by default. The container runs ONE display
    # stack per session slot (see browser_service.display_pool), so interactive
    # mode is no longer restricted to a single session: session i leases display
    # :(display_num_base + i) served by x11vnc on (vnc_port_base + i).
    interactive_hitl_enabled: bool = False
    novnc_port: int = Field(default=6080, ge=1, le=65_535)
    # BASE of the per-slot X display numbers. Slot i uses :(base + i).
    display_num_base: int = Field(default=99, ge=1, le=1_000)
    # BASE of x11vnc's ports INSIDE this container. Slot i is served on
    # (base + i). Only ever reached over loopback, so these are never published
    # and never accepted from a caller.
    vnc_port_base: int = Field(default=5900, ge=1, le=65_535)
    # Separate x11vnc listener started with ``-viewonly``. Routing a view grant to
    # this port is the server-side enforcement boundary; noVNC's client-side
    # ``viewOnly`` flag is only a UX aid and is never trusted as authorization.
    view_vnc_port_base: int = Field(default=5910, ge=1, le=65_535)
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

    @field_validator("service_token")
    @classmethod
    def _validate_service_token(cls, value: SecretStr | None) -> SecretStr | None:
        if value is None:
            return None
        token = value.get_secret_value()
        if len(token) < 32:
            raise ValueError("BROWSER_SERVICE_TOKEN must be at least 32 characters")
        if any(marker in token.casefold() for marker in ("replace-with", "change-me", "example")):
            raise ValueError("BROWSER_SERVICE_TOKEN contains a placeholder")
        return value

    @model_validator(mode="after")
    def _validate_interactive_hitl(self) -> BrowserServiceSettings:
        """Ensure every session slot can own a PRIVATE display stack.

        Interactive HITL used to require ``max_sessions == 1`` because a single
        Xvfb/x11vnc pair was shared. Concurrency is now allowed, but the invariant
        that replaces the old cap is stricter and checked here: there must be one
        display per session, and the derived port range must not collide with the
        service's own listeners — a collision would silently point the relay at
        the HTTP server (or at noVNC's asset port) instead of x11vnc.
        """

        broker_url = urlsplit(self.secret_broker_url)
        if (
            broker_url.scheme != "http"
            or not broker_url.hostname
            or broker_url.username
            or broker_url.password
            or broker_url.query
            or broker_url.fragment
            or broker_url.path not in {"", "/"}
        ):
            raise ValueError(
                "BROWSER_SECRET_BROKER_URL must be a private HTTP origin without credentials"
            )
        if self.secret_broker_token is not None:
            broker_token = self.secret_broker_token.get_secret_value()
            if len(broker_token) < 32:
                raise ValueError("BROWSER_SECRET_BROKER_TOKEN must be at least 32 characters")
            if (
                self.service_token is not None
                and broker_token == self.service_token.get_secret_value()
            ):
                raise ValueError(
                    "BROWSER_SECRET_BROKER_TOKEN must differ from BROWSER_SERVICE_TOKEN"
                )

        if not self.interactive_hitl_enabled:
            return self
        if self.max_sessions > MAX_DISPLAY_SLOTS:
            raise ValueError(
                f"interactive HITL supports at most {MAX_DISPLAY_SLOTS} concurrent "
                "sessions (PLAYWRIGHT_MAX_SESSIONS)"
            )
        highest_vnc_port = self.vnc_port_base + self.max_sessions - 1
        highest_view_vnc_port = self.view_vnc_port_base + self.max_sessions - 1
        if highest_vnc_port > 65_535 or highest_view_vnc_port > 65_535:
            raise ValueError("a VNC port base is too high for the requested session count")
        reserved = {self.port, self.novnc_port}
        control_ports = set(range(self.vnc_port_base, highest_vnc_port + 1))
        view_ports = set(range(self.view_vnc_port_base, highest_view_vnc_port + 1))
        collisions = reserved & (control_ports | view_ports)
        collisions |= control_ports & view_ports
        if collisions:
            raise ValueError(
                "the per-session VNC port range collides with the service port or "
                "BROWSER_NOVNC_PORT; move BROWSER_VNC_PORT"
            )
        return self

    @property
    def token_configured(self) -> bool:
        return self.service_token is not None

    @property
    def secret_broker_configured(self) -> bool:
        return self.secret_broker_token is not None

    @property
    def display_slots(self) -> int:
        """How many private display stacks this deployment owns.

        Zero when interactive HITL is off: a headless deployment renders nothing
        to an X server, so it needs no display and pays for none.
        """

        return self.max_sessions if self.interactive_hitl_enabled else 0

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
        storage_key = _text("BROWSER_STORAGE_STATE_KEY")
        secret_broker_token = _text("BROWSER_SECRET_BROKER_TOKEN")
        vnc_port_base = _int("BROWSER_VNC_PORT", 5900)
        return cls(
            service_token=SecretStr(token) if token else None,
            secret_broker_token=(SecretStr(secret_broker_token) if secret_broker_token else None),
            secret_broker_url=(_text("BROWSER_SECRET_BROKER_URL") or "http://api:8000").rstrip("/"),
            secret_broker_timeout_seconds=_float("BROWSER_SECRET_BROKER_TIMEOUT_SECONDS", 10.0),
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
            # Both are now the BASE of a per-slot range, keeping the existing env
            # var names so an existing single-session deployment is unchanged.
            display_num_base=_int("BROWSER_DISPLAY_NUM", 99),
            vnc_port_base=vnc_port_base,
            view_vnc_port_base=_int(
                "BROWSER_VIEW_ONLY_VNC_PORT", vnc_port_base + MAX_DISPLAY_SLOTS
            ),
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
