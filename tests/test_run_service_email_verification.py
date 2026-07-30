"""Tests for the RunService side of autonomous email verification.

The concern here is not extraction (covered in ``test_email_verification.py``) but
the wiring: which binding level a run gets, whether a deployment can require proof
that a message belongs to the run, that the attempt budget really bounds polling,
and that nothing secret reaches the sanitized log.
"""

from __future__ import annotations

import logging
import threading
from datetime import UTC, datetime
from typing import Any

from pydantic import SecretStr

from ops.core.config import Settings
from ops.email.verification import (
    ResolvedVerification,
    VerificationDecision,
    VerificationEvidence,
)
from ops.runs.service import RunService, _verification_backoff

_LOGIN_EMAIL = "ops.signup+pipedrive@gmail.com"
_ACCOUNT_REF = "acct_0123456789abcdef0123456789abcdef"


class _StubStorage:
    """Minimal storage stub exposing only what the resolver reads."""

    def __init__(self, record: dict[str, Any]) -> None:
        self._record = record

    def get_run(self, run_id: str) -> dict[str, Any] | None:
        return self._record if self._record.get("run_id") == run_id else None

    def list_runs(self, *, limit: int = 100, offset: int = 0) -> list[dict[str, Any]]:
        del limit, offset
        return [self._record]


class _StubLoginStore:
    def __init__(self, values: dict[str, str] | None) -> None:
        self._values = values or {}

    def get_account_login(self, *, app_slug: str, account_ref: str, field: str) -> str | None:
        del app_slug
        if account_ref != _ACCOUNT_REF:
            return None
        return self._values.get(field)


def _service(
    *,
    app_slug: str = "pipedrive",
    login: dict[str, str] | None = None,
    settings: Settings | None = None,
) -> RunService:
    """Build a RunService without touching its normal provider wiring."""

    service = RunService.__new__(RunService)
    record = {
        "run_id": "run_1",
        "status": "waiting_for_hitl",
        "app_slug": app_slug,
        "browser_account_ref": _ACCOUNT_REF,
        "hitl_request": {
            "type": "email_otp",
            "verification_requested_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        },
    }
    service.storage = _StubStorage(record)  # type: ignore[assignment]
    service._settings = settings or Settings(
        gmail_verification_max_attempts=2,
        gmail_verification_poll_seconds=0.0,
    )
    service._secret_store = _StubLoginStore(login)  # type: ignore[assignment]
    service._gmail_worker = object()  # type: ignore[assignment]
    service._otp_attempts = {}
    service._workflow = None
    service._email_poller_stop = threading.Event()
    return service


def _decision(kind: str = "link") -> VerificationDecision:
    return VerificationDecision(
        resolved=ResolvedVerification(
            secret=SecretStr("https://app.pipedrive.com/verify?token=zzz"),
            evidence=VerificationEvidence(
                purpose="login_verification",
                verification_kind=kind,  # type: ignore[arg-type]
                message_id="m1",
                sender_domain="pipedrive.com",
                recipient_binding="exact",
                sender_reviewed=True,
                received_at_ms=1,
                age_seconds=12,
                link_host="app.pipedrive.com",
                code_length=0 if kind == "link" else 6,
            ),
        ),
        reason_code="verification_resolved",
    )


# --- binding levels -----------------------------------------------------------
def test_binding_uses_the_remembered_login_email() -> None:
    service = _service(login={"login_email": _LOGIN_EMAIL, "login_password": "x"})
    binding = service._verification_binding("pipedrive", account_ref=_ACCOUNT_REF)
    assert binding is not None
    assert binding.expected_recipient == _LOGIN_EMAIL
    assert binding.allowed_link_host_patterns == (
        "www.pipedrive.com",
        "app.pipedrive.com",
    )


def test_explicit_recipient_wins_so_a_signup_can_bind_its_new_identity() -> None:
    service = _service(login={"login_email": _LOGIN_EMAIL, "login_password": "x"})
    binding = service._verification_binding(
        "pipedrive", expected_recipient="ops.signup+fresh@gmail.com"
    )
    assert binding is not None
    assert binding.expected_recipient == "ops.signup+fresh@gmail.com"


def test_binding_without_a_recipient_still_restricts_link_hosts() -> None:
    service = _service(login=None)
    binding = service._verification_binding("pipedrive")
    assert binding is not None
    assert binding.expected_recipient is None
    assert binding.allowed_link_host_patterns  # host restriction survives


def test_app_without_a_reviewed_host_set_has_no_binding() -> None:
    service = _service(app_slug="whatsapp-business")
    assert service._verification_binding("whatsapp-business") is None


def test_unknown_app_has_no_binding() -> None:
    service = _service(app_slug="not-a-real-app")
    assert service._verification_binding("not-a-real-app") is None


# --- fail-closed switch -------------------------------------------------------
def test_require_binding_refuses_an_unbindable_run() -> None:
    settings = Settings(
        gmail_verification_require_binding=True,
        gmail_verification_poll_seconds=0.0,
    )
    service = _service(app_slug="whatsapp-business", settings=settings)
    calls: list[str] = []
    service._fetch_bound_verification = lambda **kwargs: (  # type: ignore[assignment]
        calls.append("called") or _decision()
    )
    assert service.resolve_email_verification("run_1") is None
    # The inbox is never even read when the deployment demands proof of ownership.
    assert calls == []


def test_binding_not_required_by_default_preserves_existing_deployments() -> None:
    service = _service(
        app_slug="whatsapp-business",
        settings=Settings(
            gmail_verification_require_binding=False,
            gmail_verification_poll_seconds=0.0,
        ),
    )
    service._fetch_bound_verification = lambda **kwargs: _decision()  # type: ignore[assignment]
    service.resume_run = lambda run_id, **kwargs: {"run_id": run_id, **kwargs}  # type: ignore[assignment]
    assert service.resolve_email_verification("run_1") is not None


# --- attempt budget and injection shape ---------------------------------------
def test_polling_is_bounded_by_the_attempt_budget() -> None:
    service = _service(login={"login_email": _LOGIN_EMAIL, "login_password": "x"})
    attempts = {"count": 0}

    def _never_resolves(**kwargs: object) -> VerificationDecision:
        attempts["count"] += 1
        return VerificationDecision(resolved=None, reason_code="verification_message_not_found")

    service._fetch_bound_verification = _never_resolves  # type: ignore[assignment]
    assert service.resolve_email_verification("run_1") is None
    # Two polls inside one call (the configured budget), not an unbounded loop.
    assert attempts["count"] == 2


def test_repeated_sweeps_continue_until_persisted_freshness_deadline() -> None:
    service = _service(login={"login_email": _LOGIN_EMAIL, "login_password": "x"})
    fetches = 0

    def _missing(**kwargs: Any) -> VerificationDecision:
        nonlocal fetches
        del kwargs
        fetches += 1
        return VerificationDecision(resolved=None, reason_code="verification_message_not_found")

    service._fetch_bound_verification = _missing  # type: ignore[assignment]
    service.resolve_email_verification("run_1")
    service.resolve_email_verification("run_1")
    service.resolve_email_verification("run_1")
    assert service._otp_attempts["run_1"] == 3
    assert fetches == 6

    # The persisted gate timestamp, rather than an in-memory call count, bounds
    # future sweeps and survives a process restart.
    service.storage._record["hitl_request"]["verification_requested_at"] = (  # type: ignore[index,attr-defined]
        "2000-01-01T00:00:00Z"
    )
    service._fetch_bound_verification = lambda **kwargs: VerificationDecision(  # type: ignore[assignment]
        resolved=None, reason_code="verification_message_not_found"
    )
    assert service.resolve_email_verification("run_1") is None
    assert service._otp_attempts["run_1"] == 3


def test_a_link_is_injected_as_the_verification_url_field() -> None:
    service = _service(login={"login_email": _LOGIN_EMAIL, "login_password": "x"})
    captured: dict[str, Any] = {}

    def _resume(run_id: str, **kwargs: Any) -> dict[str, Any]:
        captured.update({"run_id": run_id, **kwargs})
        return {"run_id": run_id}

    service._fetch_bound_verification = lambda **kwargs: _decision("link")  # type: ignore[assignment]
    service.resume_run = _resume  # type: ignore[assignment]
    service.resolve_email_verification("run_1")
    assert set(captured["browser_login"]) == {"login_verification_url"}
    assert isinstance(captured["browser_login"]["login_verification_url"], SecretStr)


def test_a_code_is_injected_as_the_otp_field() -> None:
    service = _service(login={"login_email": _LOGIN_EMAIL, "login_password": "x"})
    captured: dict[str, Any] = {}
    service._fetch_bound_verification = lambda **kwargs: _decision("code")  # type: ignore[assignment]
    service.resume_run = lambda run_id, **kwargs: captured.update(kwargs) or {}  # type: ignore[assignment]
    service.resolve_email_verification("run_1")
    assert set(captured["browser_login"]) == {"login_otp"}


def test_purpose_is_passed_through_as_verification_metadata() -> None:
    service = _service(login={"login_email": _LOGIN_EMAIL, "login_password": "x"})
    seen: dict[str, Any] = {}

    def _fetch(**kwargs: Any) -> VerificationDecision:
        seen.update(kwargs)
        return _decision()

    service._fetch_bound_verification = _fetch  # type: ignore[assignment]
    service.resume_run = lambda run_id, **kwargs: {}  # type: ignore[assignment]
    service.resolve_email_verification("run_1", purpose="signup_confirmation")
    assert seen["purpose"] == "signup_confirmation"
    assert isinstance(seen["verification_requested_at_ms"], int)


def test_signup_verification_binds_to_the_run_scoped_staged_email() -> None:
    service = _service(login=None)
    service.storage._record["request"] = {"account_mode": "create_account"}  # type: ignore[attr-defined]
    service._staged_signup_login_values = lambda **kwargs: {  # type: ignore[method-assign]
        "login_email": SecretStr("ops.signup+pipedrive@gmail.com"),
        "login_password": SecretStr("generated-password"),
    }
    seen: dict[str, Any] = {}

    def _fetch(**kwargs: Any) -> VerificationDecision:
        seen.update(kwargs)
        return _decision()

    service._fetch_bound_verification = _fetch  # type: ignore[assignment]
    service.resume_run = lambda run_id, **kwargs: {}  # type: ignore[assignment]
    service.resolve_email_verification("run_1", purpose="signup_confirmation")
    binding = seen["binding"]
    assert binding.expected_recipient == "ops.signup+pipedrive@gmail.com"


# --- log safety ---------------------------------------------------------------
def test_resolved_log_line_carries_no_secret() -> None:
    # The sanitized "blink" logger does not propagate and its handler binds the
    # original stream, so attach a handler to the real logger and read the record
    # it actually emits (after the redaction filter has run).
    service = _service(login={"login_email": _LOGIN_EMAIL, "login_password": "x"})
    service._fetch_bound_verification = lambda **kwargs: _decision("link")  # type: ignore[assignment]
    service.resume_run = lambda run_id, **kwargs: {}  # type: ignore[assignment]

    emitted: list[str] = []

    class _Capture(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            emitted.append(record.getMessage())

    logger = logging.getLogger("composio_ops.browser_link")
    handler = _Capture(level=logging.DEBUG)
    logger.addHandler(handler)
    try:
        service.resolve_email_verification("run_1")
    finally:
        logger.removeHandler(handler)

    text = "\n".join(emitted)
    assert text, "the resolver must emit a sanitized diagnostic line"
    assert "token=zzz" not in text
    assert "app.pipedrive.com" in text  # host only, useful for diagnosis
    # The field is named to survive redaction while staying non-credential.
    assert "verification_kind" in text


# --- backoff ------------------------------------------------------------------
def test_backoff_grows_and_stays_jittered_within_bounds() -> None:
    assert _verification_backoff(0.0, 0) == 0.0
    first = [_verification_backoff(5.0, 0) for _ in range(50)]
    second = [_verification_backoff(5.0, 1) for _ in range(50)]
    assert all(4.0 <= value <= 6.0 for value in first)
    assert all(8.0 <= value <= 12.0 for value in second)
    assert len(set(first)) > 1  # jittered, so parallel runs do not poll in lockstep


def test_backoff_is_capped() -> None:
    assert all(_verification_backoff(5.0, 20) <= 30.0 * 1.2 for _ in range(20))
