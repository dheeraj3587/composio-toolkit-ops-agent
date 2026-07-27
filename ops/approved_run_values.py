"""Immutable, per-run values approved for deterministic browser automation.

The model deliberately contains only bounded non-secret values and opaque vault
references. Raw email addresses and passwords are resolved inside the trusted
browser boundary and never enter prompts, checkpoints, or the operations ledger.
"""

from __future__ import annotations

import re
import threading
from collections.abc import Mapping
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from ops.models import CompanyProfile, OperationsRequest, validate_vault_reference

_SAFE_ID = re.compile(r"^[A-Za-z0-9_-]{1,180}$")


class ApprovedRunValues(BaseModel):
    """One immutable value bundle bound to exactly one run and browser session."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        hide_input_in_errors=True,
        str_strip_whitespace=True,
    )

    run_id: str
    session_id: str | None = None
    legal_name: str = Field(min_length=1, max_length=200)
    company_website: str = Field(min_length=8, max_length=2048)
    use_case: str = Field(min_length=1, max_length=2000)
    expected_volume: str | None = Field(default=None, max_length=200)
    callback_urls: tuple[str, ...] = Field(default=(), max_length=20)
    signup_email_ref: str
    account_password_ref: str
    generated_application_name: str = Field(min_length=1, max_length=200)
    account_display_name: str = Field(min_length=1, max_length=200)
    workspace_name: str = Field(min_length=1, max_length=200)
    first_name: str | None = Field(default=None, max_length=100)
    last_name: str | None = Field(default=None, max_length=100)
    job_title: str | None = Field(default=None, max_length=160)
    country: str | None = Field(default=None, max_length=100)

    @field_validator("run_id")
    @classmethod
    def _run_id_is_bounded(cls, value: str) -> str:
        if _SAFE_ID.fullmatch(value) is None:
            raise ValueError("run id is invalid")
        return value

    @field_validator("session_id")
    @classmethod
    def _session_id_is_bounded(cls, value: str | None) -> str | None:
        if value is not None and _SAFE_ID.fullmatch(value) is None:
            raise ValueError("session id is invalid")
        return value

    @field_validator("company_website")
    @classmethod
    def _website_is_https(cls, value: str) -> str:
        return _validated_https(value)

    @field_validator("callback_urls")
    @classmethod
    def _callback_urls_are_https(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(_validated_https(value) for value in values)

    @field_validator("signup_email_ref", "account_password_ref")
    @classmethod
    def _references_only(cls, value: str) -> str:
        return validate_vault_reference(value)

    @model_validator(mode="after")
    def _distinct_secret_kinds(self) -> ApprovedRunValues:
        if self.signup_email_ref == self.account_password_ref:
            raise ValueError("signup email and password references must be distinct")
        return self

    def bind_to_session(self, session_id: str) -> ApprovedRunValues:
        """Bind once; rebinding to another browser session is forbidden."""

        if _SAFE_ID.fullmatch(session_id) is None:
            raise ValueError("session id is invalid")
        if self.session_id is None:
            return self.model_copy(update={"session_id": session_id})
        if self.session_id != session_id:
            raise ValueError("approved values are already bound to another session")
        return self

    def assert_binding(self, *, run_id: str, session_id: str) -> None:
        if self.run_id != run_id or self.session_id != session_id:
            raise PermissionError("approved values do not belong to this run and session")

    def prompt_safe_projection(self) -> dict[str, object]:
        """Return names of available fields, never their values or vault refs."""

        available = [
            name
            for name in (
                "legal_name",
                "company_website",
                "use_case",
                "expected_volume",
                "callback_urls",
                "signup_email",
                "account_password",
                "generated_application_name",
                "account_display_name",
                "workspace_name",
                "first_name",
                "last_name",
                "job_title",
                "country",
            )
            if name not in {"expected_volume", "first_name", "last_name", "job_title", "country"}
            or getattr(self, name, None) is not None
        ]
        return {"run_id": self.run_id, "available_semantic_fields": available}


class ApprovedRunValuesRegistry:
    """Process-local session binding that prevents cross-run value access."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._by_session: dict[str, ApprovedRunValues] = {}

    def bind(self, values: ApprovedRunValues, *, session_id: str) -> ApprovedRunValues:
        bound = values.bind_to_session(session_id)
        with self._lock:
            existing = self._by_session.get(session_id)
            if existing is not None and existing != bound:
                raise PermissionError("browser session is already bound to another run")
            self._by_session[session_id] = bound
        return bound

    def get(self, *, run_id: str, session_id: str) -> ApprovedRunValues:
        with self._lock:
            values = self._by_session.get(session_id)
        if values is None:
            raise KeyError("approved values were not found for browser session")
        values.assert_binding(run_id=run_id, session_id=session_id)
        return values

    def release(self, *, run_id: str, session_id: str) -> None:
        with self._lock:
            values = self._by_session.get(session_id)
            if values is None:
                return
            values.assert_binding(run_id=run_id, session_id=session_id)
            self._by_session.pop(session_id, None)


def build_approved_run_values(
    *,
    run_id: str,
    request: OperationsRequest,
    signup_email_ref: str,
    account_password_ref: str,
    generated_application_name: str | None = None,
    account_display_name: str | None = None,
    workspace_name: str | None = None,
    profile_fields: Mapping[str, str | None] | None = None,
) -> ApprovedRunValues:
    """Build a run-owned bundle from the request instead of global Settings."""

    company: CompanyProfile = request.company
    profile = dict(profile_fields or {})
    default_name = company.legal_name
    return ApprovedRunValues(
        run_id=run_id,
        legal_name=company.legal_name,
        company_website=company.website,
        use_case=company.use_case,
        expected_volume=company.expected_volume,
        callback_urls=tuple(company.callback_urls),
        signup_email_ref=signup_email_ref,
        account_password_ref=account_password_ref,
        generated_application_name=generated_application_name
        or f"{default_name} Integration"[:200],
        account_display_name=account_display_name or default_name,
        workspace_name=workspace_name or default_name,
        first_name=profile.get("first_name"),
        last_name=profile.get("last_name"),
        job_title=profile.get("job_title"),
        country=profile.get("country"),
    )


def _validated_https(value: str) -> str:
    parsed = urlsplit(value)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("an absolute credential-free HTTPS URL is required")
    return value


__all__ = [
    "ApprovedRunValues",
    "ApprovedRunValuesRegistry",
    "build_approved_run_values",
]
