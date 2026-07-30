"""The ``profile_declared`` authority path: what it requires, and what it refuses.

``ops.access.gate_policy`` grants ``legal_acceptance`` autonomy from a reviewed recipe,
and a provider the repo has never seen has no recipe to grant it from. The
profile path is the runtime substitute, so the interesting assertions are the
ones about its *limits*: the authority is only as strong as the durable facts it
carries, it is confined to the profile's one registrable domain, and it cannot
widen the gate set it applies to.

Gate classification proper — every gate type against every app slug — belongs to
``tests`` written for task 10.7. This module covers only the authority record and
the confinement rule added alongside it.
"""

from __future__ import annotations

from ops.access.gate_policy import (
    HUMAN_ONLY_GATES,
    PROFILE_DECLARABLE_GATES,
    ProfileGateAuthority,
    resolve_gate,
)

# A provider with no checked-in recipe: the only reason `legal_acceptance` could
# resolve for it is the run's own profile.
NEW_PROVIDER = "brand-new-provider"

# 64 hex characters, because a profile digest is a sha256 content address.
COMMITTED_DIGEST = "a" * 64


def _authority(**overrides: str) -> ProfileGateAuthority:
    """An authority a run holds after an operator approved account creation."""

    fields: dict[str, str] = {
        "profile_digest": COMMITTED_DIGEST,
        "registrable_domain": "provider.example",
        "gate_url": "https://signup.provider.example/register",
        "admission_route": "signup",
        "admission_decided_by": "operator",
        "admission_profile_digest": COMMITTED_DIGEST,
    }
    fields.update(overrides)
    return ProfileGateAuthority(**fields)


def test_the_authority_is_confined_to_the_profile_registrable_domain() -> None:
    """A grant earned for one provider cannot travel to another host."""

    inside = resolve_gate("legal_acceptance", app_slug=NEW_PROVIDER, profile_authority=_authority())
    look_alike = resolve_gate(
        "legal_acceptance",
        app_slug=NEW_PROVIDER,
        profile_authority=_authority(gate_url="https://provider.example.evil.test/register"),
    )
    userinfo = resolve_gate(
        "legal_acceptance",
        app_slug=NEW_PROVIDER,
        profile_authority=_authority(gate_url="https://provider.example@evil.test/register"),
    )
    insecure = resolve_gate(
        "legal_acceptance",
        app_slug=NEW_PROVIDER,
        profile_authority=_authority(gate_url="http://signup.provider.example/register"),
    )
    malformed = resolve_gate(
        "legal_acceptance",
        app_slug=NEW_PROVIDER,
        profile_authority=_authority(gate_url="https://[::1/register"),
    )
    # A host posing as the profile's domain is not the profile's domain.
    subdomain_as_domain = resolve_gate(
        "legal_acceptance",
        app_slug=NEW_PROVIDER,
        profile_authority=_authority(registrable_domain="signup.provider.example"),
    )

    assert inside == "profile_declared"
    assert look_alike == "human_only"
    assert userinfo == "human_only"
    assert insecure == "human_only"
    assert malformed == "human_only"
    assert subdomain_as_domain == "human_only"


def test_the_decision_must_name_the_profile_the_run_committed() -> None:
    """Attribution, not just approval: the operator saw one specific profile."""

    other_profile = resolve_gate(
        "legal_acceptance",
        app_slug=NEW_PROVIDER,
        profile_authority=_authority(admission_profile_digest="b" * 64),
    )
    uncommitted = resolve_gate(
        "legal_acceptance",
        app_slug=NEW_PROVIDER,
        profile_authority=_authority(profile_digest="", admission_profile_digest=""),
    )
    unaddressed = resolve_gate(
        "legal_acceptance",
        app_slug=NEW_PROVIDER,
        profile_authority=_authority(
            profile_digest="not-a-digest",
            admission_profile_digest="not-a-digest",
        ),
    )

    assert other_profile == "human_only"
    assert uncommitted == "human_only"
    assert unaddressed == "human_only"


def test_only_an_affirmative_operator_admission_grants_the_authority() -> None:
    """A refusal and the system's own routing are both non-grants."""

    operator_cancel = resolve_gate(
        "legal_acceptance",
        app_slug=NEW_PROVIDER,
        profile_authority=_authority(admission_route="cancelled"),
    )
    system_signup = resolve_gate(
        "legal_acceptance",
        app_slug=NEW_PROVIDER,
        profile_authority=_authority(admission_decided_by="system"),
    )
    system_login = resolve_gate(
        "legal_acceptance",
        app_slug=NEW_PROVIDER,
        profile_authority=_authority(admission_route="login", admission_decided_by="system"),
    )

    assert operator_cancel == "human_only"
    assert system_signup == "human_only"
    assert system_login == "human_only"


def test_the_authority_cannot_widen_the_set_of_gates_it_applies_to() -> None:
    """Holding a profile authority classifies no gate the policy withholds."""

    assert PROFILE_DECLARABLE_GATES.isdisjoint(HUMAN_ONLY_GATES)
    for gate in sorted(HUMAN_ONLY_GATES):
        assert (
            resolve_gate(gate, app_slug=NEW_PROVIDER, profile_authority=_authority())
            == "human_only"
        )
    # An unclassified gate stays fail-closed with an authority in hand.
    assert (
        resolve_gate("newly_invented_gate", app_slug=NEW_PROVIDER, profile_authority=_authority())
        == "human_only"
    )
    assert resolve_gate(None, app_slug=NEW_PROVIDER, profile_authority=_authority()) == "human_only"


def test_the_reviewed_catalog_keeps_precedence_where_it_speaks() -> None:
    """An app whose recipe declares acceptance resolves through the recipe."""

    assert (
        resolve_gate("legal_acceptance", app_slug="pipedrive", profile_authority=_authority())
        == "recipe_declared"
    )
    # And a recipe that does not declare it still needs the profile path.
    assert resolve_gate("legal_acceptance", app_slug=NEW_PROVIDER) == "human_only"
