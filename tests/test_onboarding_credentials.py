"""Credential kinds and value contracts: total, anchored, and slug-free.

Three claims in ``ops.onboarding.credentials`` are load-bearing enough to assert
rather than trust.

The mapping is total over ``CredentialKind``. A missing kind on a capture path
either raises inside the broker or tempts a caller into a permissive default, so
totality is checked here as well as at import.

The keys are credential kinds and never app slugs. That is what makes the value
contract independent of research: an app slug is something the run discovers,
while a credential kind is a closed vocabulary in the repo. The test states it
positively (keys are exactly the vocabulary) and negatively (no reviewed recipe
slug is a key, and no key is even shaped like a slug).

The patterns are whole-value anchored. ``re.fullmatch`` at the broker already
requires a whole-value match, but the pattern also travels into structures a
future consumer might apply with ``re.search``; anchoring means a credential
found inside a paragraph of page text still fails.

Reuse is asserted against the modules that own the reused kinds, so a rename in
``ops.core.secret_store`` or ``api.browser_secret_broker`` fails there and here.
"""

from __future__ import annotations

import asyncio
import re
from dataclasses import replace
from typing import get_args

import pytest

from api.browser_secret_broker import _ALLOWED_TRANSIENT_KINDS
from ops.core.effect_ledger import SQLiteEffectStore
from ops.core.secret_store import REUSABLE_LOGIN_FIELDS, parse_vault_reference
from ops.credentials.validator import CredentialValidationResult
from ops.onboarding.credentials import (
    CREDENTIAL_KINDS,
    CREDENTIAL_VALUE_PATTERNS,
    ONBOARDING_VAULT_KINDS,
    SIGNUP_LOGIN_VAULT_KINDS,
    TRANSIENT_LOGIN_VAULT_KINDS,
    VALIDATION_AUTH_SCHEMES,
    CredentialLifecycleDeps,
    CredentialStep,
    capture_store_validate_publish,
    credential_value_matches,
    credential_value_pattern,
    is_credential_kind,
    onboarding_vault_kind,
    profile_validation_policy,
)
from ops.providers.profile import (
    CredentialKind,
    FlowSpec,
    ProviderProfile,
    compute_profile_digest,
)
from ops.recipes.app_recipes import load_app_recipe_catalog

# The reviewed kind column of design LL-5.3, written out so deriving the mapping
# from the ``Literal`` cannot quietly rename a kind that already has stored rows.
_REVIEWED_VAULT_KINDS = {
    "oauth_client_id": "onboarding_oauth_client_id",
    "oauth_client_secret": "onboarding_oauth_client_secret",  # pragma: allowlist secret
    "api_key": "onboarding_api_key",  # pragma: allowlist secret
    "personal_access_token": "onboarding_personal_access_token",
    "client_credentials_pair": "onboarding_client_credentials_pair",
}

# One representative accepted value and two obviously invalid ones per kind: a
# value carrying a character outside the class, and a value below the length
# floor. Synthetic throughout — no shape here is a real credential.
_REPRESENTATIVE_VALUES: dict[str, tuple[str, str, str]] = {
    "oauth_client_id": ("client-id.example~0123", "client id example", "short"),
    "oauth_client_secret": ("secret-value.example~1234567890+/=", "secret value example", "short"),
    "api_key": ("example-api-key-value-0000000000", "example api key value", "short"),
    "personal_access_token": ("example-pat-value-0000000000", "example pat value!", "short"),
    "client_credentials_pair": ("example-client-credentials-0000", "example pair\n0000", "short"),
}

# The app slug grammar ``ProviderProfile`` and the broker request models enforce.
# Restated locally because the point of the test is that no key satisfies it.
_APP_SLUG = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*")


def test_credential_kinds_are_derived_from_the_literal() -> None:
    assert CREDENTIAL_KINDS == get_args(CredentialKind)
    assert len(set(CREDENTIAL_KINDS)) == len(CREDENTIAL_KINDS)


def test_both_mappings_are_total_over_credential_kind() -> None:
    """Requirement 10.5: every credential kind has a vault kind and a contract."""

    assert set(ONBOARDING_VAULT_KINDS) == set(CREDENTIAL_KINDS)
    assert set(CREDENTIAL_VALUE_PATTERNS) == set(CREDENTIAL_KINDS)


def test_vault_kinds_match_the_reviewed_table() -> None:
    assert dict(ONBOARDING_VAULT_KINDS) == _REVIEWED_VAULT_KINDS


def test_every_vault_kind_is_addressable_as_a_vault_reference() -> None:
    """A kind outside the reference grammar would be unwritable at capture time."""

    for kind in (
        set(ONBOARDING_VAULT_KINDS.values())
        | set(SIGNUP_LOGIN_VAULT_KINDS.values())
        | TRANSIENT_LOGIN_VAULT_KINDS
    ):
        parts = parse_vault_reference(f"vault://acme/{kind}/abcd1234")
        assert parts.kind == kind


@pytest.mark.parametrize("kind", CREDENTIAL_KINDS)
def test_pattern_accepts_a_representative_value_and_rejects_invalid_ones(kind: str) -> None:
    accepted, forbidden_character, too_short = _REPRESENTATIVE_VALUES[kind]

    assert credential_value_matches(kind, accepted) is True
    assert credential_value_matches(kind, forbidden_character) is False
    assert credential_value_matches(kind, too_short) is False
    assert credential_value_matches(kind, "") is False


@pytest.mark.parametrize("kind", CREDENTIAL_KINDS)
def test_patterns_are_anchored_so_a_substring_never_passes(kind: str) -> None:
    """A credential-shaped run inside surrounding text is not a credential."""

    accepted = _REPRESENTATIVE_VALUES[kind][0]
    pattern = credential_value_pattern(kind)
    embedded = f"your key is {accepted} - keep it secret"

    # ``search`` is the weakest plausible application of the pattern; anchoring
    # is what makes it as strict as ``fullmatch``.
    assert re.search(pattern, embedded) is None
    assert re.match(pattern, embedded) is None
    assert credential_value_matches(kind, embedded) is False
    assert re.fullmatch(pattern, accepted) is not None


def test_no_key_is_an_app_slug() -> None:
    """The value contract is keyed by kind only, so research cannot select one."""

    reviewed_slugs = {recipe.app_slug for recipe in load_app_recipe_catalog().apps}
    assert reviewed_slugs  # the catalog is non-empty, so the check is not vacuous

    for mapping in (ONBOARDING_VAULT_KINDS, CREDENTIAL_VALUE_PATTERNS):
        keys = set(mapping)
        assert keys.isdisjoint(reviewed_slugs)
        # Every credential kind carries an underscore, which no app slug may, so
        # a slug is not even expressible as a key of these mappings.
        for key in keys:
            assert _APP_SLUG.fullmatch(key) is None, key


def test_signup_and_transient_kinds_reuse_the_existing_vocabulary() -> None:
    """Requirement 19.8 / LL-5.3: onboarding introduces no new vault kind."""

    assert set(SIGNUP_LOGIN_VAULT_KINDS) == REUSABLE_LOGIN_FIELDS
    assert set(SIGNUP_LOGIN_VAULT_KINDS.values()) == {
        "account_login_login_email",
        "account_login_login_password",
    }
    # The four kinds the broker already admits, asserted against the broker.
    assert TRANSIENT_LOGIN_VAULT_KINDS == _ALLOWED_TRANSIENT_KINDS
    assert len(TRANSIENT_LOGIN_VAULT_KINDS) == 4


def test_the_three_kind_namespaces_stay_disjoint() -> None:
    """A durable credential must not be readable through a sign-in or one-shot path."""

    captured = set(ONBOARDING_VAULT_KINDS.values())
    signin = set(SIGNUP_LOGIN_VAULT_KINDS.values())

    assert captured.isdisjoint(signin)
    assert captured.isdisjoint(TRANSIENT_LOGIN_VAULT_KINDS)
    assert signin.isdisjoint(TRANSIENT_LOGIN_VAULT_KINDS)


@pytest.mark.parametrize("unknown", ["pipedrive", "api_token", "API_KEY", "", "oauth_client"])
def test_lookups_refuse_a_kind_outside_the_vocabulary(unknown: str) -> None:
    assert is_credential_kind(unknown) is False
    for lookup in (onboarding_vault_kind, credential_value_pattern):
        with pytest.raises(ValueError):
            lookup(unknown)
    with pytest.raises(ValueError):
        credential_value_matches(unknown, "example-api-key-value-0000000000")


def test_rejection_never_carries_the_value() -> None:
    """A refusal message is a reason, not a leak (Requirement 19.8)."""

    value = "example-api-key-value-0000000000"
    with pytest.raises(ValueError) as excinfo:
        credential_value_matches("not_a_kind", value)

    assert value not in str(excinfo.value)


def test_mappings_are_read_only() -> None:
    """A security contract that a caller can mutate at runtime is not a contract."""

    with pytest.raises(TypeError):
        CREDENTIAL_VALUE_PATTERNS["api_key"] = ".*"  # type: ignore[index]
    with pytest.raises(TypeError):
        ONBOARDING_VAULT_KINDS["api_key"] = "secrets"  # type: ignore[index]


def _profile() -> ProviderProfile:
    """A minimal committed profile whose api-key flow lives on its own domain."""

    profile = ProviderProfile(
        run_id="run-validation-001",
        provider_name="Provider",
        app_slug="provider",
        registrable_domain="provider.com",
        auxiliary_hosts=(),
        developer_portal_url="https://developers.provider.com/",
        signup_url="https://provider.com/signup",
        login_url="https://app.provider.com/login",
        developer_docs_url=None,
        developer_app_flow=FlowSpec(kind="developer_app", supported=False, entry_url=None),
        oauth_flow=FlowSpec(kind="oauth", supported=False, entry_url=None),
        api_key_flow=FlowSpec(
            kind="api_key",
            supported=True,
            entry_url="https://app.provider.com/settings/api",
            produces=("api_key",),
        ),
        pat_flow=FlowSpec(kind="pat", supported=False, entry_url=None),
        approval_requirement="none",
        billing_requirement="none",
        evidence=(),
        confidence=0.85,
        adapters_engaged=("fake-discovery",),
        built_at="2025-01-01T00:00:01Z",
    )
    return replace(profile, profile_digest=compute_profile_digest(profile))


def test_profile_validation_policy_builds_a_domain_confined_bearer_probe() -> None:
    """Requirements 10.8, 10.9: endpoint from the profile domain, scheme from code."""

    profile = _profile()

    policy = profile_validation_policy(
        profile,
        kind="api_key",
        research_endpoint="https://api.provider.com/v1/me",
    )

    assert policy is not None
    assert policy.app_slug == "provider"
    assert policy.allowed_endpoints == ("https://api.provider.com/v1/me",)
    assert policy.auth_scheme == VALIDATION_AUTH_SCHEMES["api_key"] == "bearer"
    assert policy.credential_field == "api_key"

    # Requirement 10.11: unprovable is None, which the caller turns into a pause.
    # An endpoint off the profile's domain and a kind with no derivable probe
    # shape are both unprovable, never a permissive policy.
    assert (
        profile_validation_policy(
            profile, kind="api_key", research_endpoint="https://api.evil.io/v1/me"
        )
        is None
    )
    assert profile_validation_policy(profile, kind="oauth_client_id") is None


# --- the credential lifecycle (task 17.2) -----------------------------------


class _Journal:
    """The phase journal, recording boundaries and counters in memory."""

    def __init__(self) -> None:
        self.boundaries: list[tuple[str | None, str, str]] = []
        self.generation = 0
        self.validation_attempts = 0
        self.generation_advances = 0

    def commit_phase(
        self,
        *,
        run_id: str,
        from_phase: str | None,
        to_phase: str,
        reason_code: str,
        profile_digest: str,
        attempt: int,
        correlation_id: str,
    ) -> bool:
        self.boundaries.append((from_phase, to_phase, reason_code))
        return True

    def current_generation(self, *, run_id: str, effect: str) -> int:
        return self.generation

    def next_generation(self, *, run_id: str, effect: str) -> int:
        self.generation_advances += 1
        self.generation += 1
        return self.generation

    def next_validation_attempt(self, *, run_id: str) -> int:
        self.validation_attempts += 1
        return self.validation_attempts


class _Vault:
    """The three vault verbs the lifecycle may call, and nothing else."""

    def __init__(self) -> None:
        self.retired: list[tuple[str, str]] = []

    def reserve_browser_secret_grant(
        self,
        *,
        operation_key: str,
        run_id: str,
        session_id: str,
        app_slug: str,
        kind: str,
        action: str,
        reference: str | None = None,
        ttl_seconds: int = 900,
    ) -> str:
        assert action == "capture"
        return f"bsg_{operation_key}"

    def mark_credential_superseded(self, reference: str) -> str:
        self.retired.append((reference, "superseded"))
        return "superseded"

    def mark_credential_unusable(self, reference: str) -> str:
        self.retired.append((reference, "unusable"))
        return "unusable"


class _Session:
    """The browser seam: it arms, then hands back a reference and never a value."""

    session_id = "bs_" + "0" * 32

    def __init__(self) -> None:
        self.armed_before_capture = False
        self.captured_kind: str | None = None

    async def arm_credential_surface(self) -> bool:
        self.armed_before_capture = self.captured_kind is None
        return True

    async def capture_credential(self, *, grant: str, kind: str) -> str:
        assert grant.startswith("bsg_")
        self.captured_kind = kind
        return f"vault://provider/{kind}/captured-row-0001"


class _Validator:
    """A probe that answers ``valid`` and never sees a credential value."""

    async def validate(self, *, reference: str, policy: object) -> CredentialValidationResult:
        return CredentialValidationResult(
            status="valid",
            endpoint="https://api.provider.com/v1/me",
            http_status=200,
            checked_at="2025-01-01T00:00:00Z",
            reason_code="credential_valid",
        )


class _Publisher:
    def __init__(self) -> None:
        self.published: list[tuple[str, str, str, str]] = []

    def publish_provider_configuration(
        self,
        *,
        run_id: str,
        reference: str,
        kind: str,
        result: CredentialValidationResult,
        completed_at: str,
    ) -> None:
        self.published.append((run_id, reference, result.status, completed_at))


def test_capture_store_validate_publish_walks_the_happy_path(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """Requirements 10.1, 10.7, 10.12, 10.13, 10.14: store, prove, then publish."""

    journal = _Journal()
    session = _Session()
    publisher = _Publisher()
    deps = CredentialLifecycleDeps(
        journal=journal,
        effects=SQLiteEffectStore(tmp_path / "effects.db"),
        vault=_Vault(),
        validator=_Validator(),
        publisher=publisher,
        research_endpoint="https://api.provider.com/v1/me",
    )

    step = asyncio.run(
        capture_store_validate_publish(
            run_id="run-credential-001",
            profile=_profile(),
            developer_app_id="dev-app-1",
            kind="api_key",
            session=session,
            deps=deps,
            attempt=1,
            correlation_id="corr-credential-001",
        )
    )

    # Masking was armed before anything could render, and the captured credential
    # crossed back as a reference in the durable onboarding kind namespace.
    assert session.armed_before_capture is True
    assert session.captured_kind == "onboarding_api_key"

    # Requirement 10.7: vault storage is committed, then validation, in that order.
    assert [(source, target) for source, target, _ in journal.boundaries] == [
        ("credential_generation", "vault_storage"),
        ("vault_storage", "credential_validation"),
    ]

    # Requirements 10.12 through 10.14: published for a `valid` reference only,
    # with the validation timestamp preceding the recorded completion.
    assert step == CredentialStep.advance("completed", "credential_valid")
    assert len(publisher.published) == 1
    _, reference, status, completed_at = publisher.published[0]
    assert reference == "vault://provider/onboarding_api_key/captured-row-0001"
    assert status == "valid"
    assert completed_at > "2025-01-01T00:00:00Z"

    # Requirement 13.12: nothing on the happy path advances the generation counter.
    assert journal.generation_advances == 0
