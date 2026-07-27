"""Canonical automation policies with strict legacy-input normalization.

The public API, encrypted workflow checkpoints, SQLite rows, and browser RPC
all use the same three policy values. Older payloads remain readable through
one deterministic conversion boundary rather than carrying duplicate flags
throughout the system.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Literal, TypeAlias, cast

AccountPolicy: TypeAlias = Literal["reuse_existing", "create_if_missing"]
DeveloperAppPolicy: TypeAlias = Literal["reuse_existing", "create_if_missing"]
CredentialPolicy: TypeAlias = Literal["reuse_existing", "create_if_missing"]

# Historical API/checkpoint vocabulary retained only at compatibility edges.
CredentialCreationPolicy: TypeAlias = Literal["reuse_only", "create_if_missing"]

_CANONICAL_POLICIES = frozenset({"reuse_existing", "create_if_missing"})
_LEGACY_CREDENTIAL_POLICIES = frozenset({"reuse_only", "create_if_missing"})


@dataclass(frozen=True, slots=True)
class AutomationPolicies:
    """One validated policy set shared by every provider boundary."""

    account: AccountPolicy
    developer_app: DeveloperAppPolicy
    credential: CredentialPolicy

    @property
    def account_creation_requested(self) -> bool:
        return self.account == "create_if_missing"

    @property
    def credential_creation_policy(self) -> CredentialCreationPolicy:
        return "reuse_only" if self.credential == "reuse_existing" else "create_if_missing"


def normalize_legacy_policy_payload(value: object) -> object:
    """Return a canonical policy mapping while accepting historical fields.

    This runs in Pydantic ``mode='before'`` validators, before ``extra='forbid'``.
    Conflicting old/new values fail closed instead of silently preferring one.
    The input mapping is copied and never mutated in place.
    """

    if not isinstance(value, Mapping):
        return value
    data = dict(value)

    if "account_creation_requested" in data:
        legacy_account = data.pop("account_creation_requested")
        if not isinstance(legacy_account, bool):
            raise ValueError("account_creation_requested must be a boolean")
        mapped_account: AccountPolicy = "create_if_missing" if legacy_account else "reuse_existing"
        current = data.get("account_policy")
        if current is not None and current != mapped_account:
            raise ValueError("account policy fields conflict")
        data["account_policy"] = mapped_account

    if "credential_creation_policy" in data:
        legacy_credential = data.pop("credential_creation_policy")
        if legacy_credential not in _LEGACY_CREDENTIAL_POLICIES:
            raise ValueError("credential_creation_policy is invalid")
        mapped_credential: CredentialPolicy = (
            "reuse_existing" if legacy_credential == "reuse_only" else "create_if_missing"
        )
        current = data.get("credential_policy")
        if current is not None and current != mapped_credential:
            raise ValueError("credential policy fields conflict")
        data["credential_policy"] = mapped_credential

    return data


def validate_account_policy(value: str | None) -> AccountPolicy:
    candidate = value or "reuse_existing"
    if candidate not in _CANONICAL_POLICIES:
        raise ValueError("account policy is invalid")
    return cast(AccountPolicy, candidate)


def validate_developer_app_policy(value: str | None) -> DeveloperAppPolicy:
    candidate = value or "reuse_existing"
    if candidate not in _CANONICAL_POLICIES:
        raise ValueError("developer application policy is invalid")
    return cast(DeveloperAppPolicy, candidate)


def validate_credential_policy(value: str | None) -> CredentialPolicy:
    candidate = value or "reuse_existing"
    if candidate not in _CANONICAL_POLICIES:
        raise ValueError("credential policy is invalid")
    return cast(CredentialPolicy, candidate)


def resolve_automation_policies(
    *,
    account_policy: str | None = None,
    developer_app_policy: str | None = None,
    credential_policy: str | None = None,
    account_creation_requested: bool | None = None,
    credential_creation_policy: str | None = None,
) -> AutomationPolicies:
    """Resolve canonical and historical arguments with conflict detection.

    Provider adapters call this single function instead of maintaining subtly
    different compatibility rules. Invalid historical values and contradictory
    old/new fields are rejected; they are never silently downgraded to read-only.
    """

    payload: dict[str, object] = {}
    if account_policy is not None:
        payload["account_policy"] = account_policy
    if developer_app_policy is not None:
        payload["developer_app_policy"] = developer_app_policy
    if credential_policy is not None:
        payload["credential_policy"] = credential_policy
    if account_creation_requested is not None:
        payload["account_creation_requested"] = account_creation_requested
    if credential_creation_policy is not None:
        payload["credential_creation_policy"] = credential_creation_policy

    normalized = normalize_legacy_policy_payload(payload)
    if not isinstance(normalized, Mapping):  # pragma: no cover - fixed dict input
        raise TypeError("policy normalization returned an invalid shape")
    return AutomationPolicies(
        account=validate_account_policy(cast(str | None, normalized.get("account_policy"))),
        developer_app=validate_developer_app_policy(
            cast(str | None, normalized.get("developer_app_policy"))
        ),
        credential=validate_credential_policy(
            cast(str | None, normalized.get("credential_policy"))
        ),
    )


def account_creation_requested(policy: AccountPolicy) -> bool:
    return policy == "create_if_missing"


def legacy_credential_creation_policy(
    policy: CredentialPolicy,
) -> CredentialCreationPolicy:
    return "reuse_only" if policy == "reuse_existing" else "create_if_missing"


__all__ = [
    "AccountPolicy",
    "AutomationPolicies",
    "CredentialCreationPolicy",
    "CredentialPolicy",
    "DeveloperAppPolicy",
    "account_creation_requested",
    "legacy_credential_creation_policy",
    "normalize_legacy_policy_payload",
    "resolve_automation_policies",
    "validate_account_policy",
    "validate_credential_policy",
    "validate_developer_app_policy",
]
