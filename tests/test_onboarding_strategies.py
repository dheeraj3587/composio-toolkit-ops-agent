"""Smoke tests for the shared onboarding strategies (offline only).

A generator that never runs is a generator that is wrong: these draw from every
primitive in ``tests/support/onboarding_strategies.py`` and assert the guarantees
the property suites rely on — a generated domain is its own registrable domain, a
generated URL is inside it, a "credential-shaped" value really is credential-shaped
to the repo's own DLP boundary, and a page fixture actually contains what it claims
to have planted.
"""

from __future__ import annotations

from urllib.parse import urlsplit

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from ops.browser.decider import build_snapshot
from ops.browser.host_policy import BrowserAllowedHosts, evaluate_navigation, registrable_domain
from ops.core.model_input_dlp import (
    _PROVIDER_KEY_PATTERNS,
    contains_secret_material,
    redact_secrets,
)
from ops.onboarding.phase import (
    INITIAL_PHASE,
    ONBOARDING_PHASES,
    TERMINAL_PHASES,
    IllegalPhaseTransition,
    OnboardingPhase,
    is_legal_phase_transition,
    validate_phase_transition,
)
from ops.providers.profile import ProviderProfile, compute_profile_digest
from tests.support.onboarding_strategies import (
    CREDENTIAL_SHAPES,
    ILLEGAL_PHASE_PAIRS,
    INJECTED_INSTRUCTIONS,
    MAX_CRASHES_PER_RUN,
    MAX_RETRIES,
    OFF_DOMAIN_MUTATIONS,
    RESERVED_APP_SLUGS,
    SECRET_PLACEMENTS,
    DivergentProfile,
    PageFixture,
    adversarial_pages,
    crash_points,
    crash_schedules,
    credential_shaped_values,
    divergent_profiles,
    https_urls,
    illegal_phase_pairs,
    phase_sequences,
    provider_profiles,
    registrable_domains,
    retry_counts,
    worker_interleavings,
)


@settings(max_examples=50)
@given(domain=registrable_domains())
def test_generated_domain_is_its_own_registrable_domain(domain: str) -> None:
    assert registrable_domain(domain) == domain
    assert ":" not in domain and "/" not in domain


@settings(max_examples=50)
@given(data=st.data())
def test_generated_https_url_stays_inside_its_domain(data: st.DataObject) -> None:
    domain = data.draw(registrable_domains())
    url = data.draw(https_urls(domain))

    parsed = urlsplit(url)
    assert parsed.scheme == "https"
    assert parsed.hostname is not None
    assert registrable_domain(parsed.hostname) == domain

    allowed = BrowserAllowedHosts(
        app_slug="generated",
        exact_hosts=(domain,),
        vendor_wildcard_domains=(domain,),
    )
    assert evaluate_navigation(url, allowed).allowed is True


@settings(max_examples=50)
@given(value=credential_shaped_values())
def test_generated_credential_value_is_credential_shaped(value: str) -> None:
    # If this fails, every secret-non-leakage property built on it is vacuous.
    assert contains_secret_material(value) is True
    assert value not in redact_secrets(value)


def test_credential_shapes_cover_every_provider_key_pattern() -> None:
    matched: set[int] = set()
    for shape in CREDENTIAL_SHAPES:
        for seed in range(4):
            value = shape.render(body_length=shape.min_body, seed=seed)
            matched.update(
                index
                for index, pattern in enumerate(_PROVIDER_KEY_PATTERNS)
                if pattern.search(value)
            )
    assert matched == set(range(len(_PROVIDER_KEY_PATTERNS)))


@settings(max_examples=50)
@given(page=adversarial_pages())
def test_adversarial_page_contains_everything_it_reports_planting(page: PageFixture) -> None:
    exposed = " ".join(page.strings())
    assert urlsplit(page.url).scheme == "https"

    for planted in (*page.planted_secrets, *page.planted_instructions):
        assert planted.placement in SECRET_PLACEMENTS
        # The rendered form is what the page carries; a URL placement encodes it.
        assert planted.rendered in exposed
    for planted in page.planted_secrets:
        assert contains_secret_material(planted.value) is True
    for planted in page.planted_instructions:
        assert planted.value in INJECTED_INSTRUCTIONS
    assert set(page.secret_forms()) >= {planted.value for planted in page.planted_secrets}

    # The fixture must be consumable by the real observation layer, not just by a
    # bespoke fake, or the properties would be testing the fixture's own shape.
    assert build_snapshot(page.raw_elements())


@settings(max_examples=50)
@given(schedule=crash_schedules(), point=crash_points(), retries=retry_counts())
def test_schedules_are_ordered_deduplicated_and_bounded(
    schedule: list[int], point: int, retries: int
) -> None:
    assert 1 <= len(schedule) <= MAX_CRASHES_PER_RUN
    assert schedule == sorted(set(schedule))
    assert all(ordinal >= 0 for ordinal in schedule)
    assert point >= 0
    assert 0 <= retries <= MAX_RETRIES


@settings(max_examples=50)
@given(order=worker_interleavings())
def test_worker_interleaving_gives_every_worker_a_turn(order: list[int]) -> None:
    workers = set(order)
    assert 2 <= len(workers) <= 4
    assert workers == set(range(len(workers)))
    assert len(order) >= len(workers)


@settings(max_examples=50)
@given(walk=phase_sequences(min_transitions=1, max_transitions=6))
def test_phase_sequence_is_a_legal_walk_from_the_initial_phase(
    walk: list[OnboardingPhase],
) -> None:
    # A walk whose steps the phase driver would refuse would make every property
    # built on it assert against a run that never advanced.
    assert walk[0] == INITIAL_PHASE
    assert is_legal_phase_transition(None, walk[0]) is True
    assert 2 <= len(walk) <= 7

    for previous, following in zip(walk[:-1], walk[1:], strict=True):
        assert is_legal_phase_transition(previous, following) is True
        # Every element is a real move, so replaying a prefix is the only
        # repetition an idempotency property introduces.
        assert previous != following

    # A terminal phase declares no targets, so it can only end the walk.
    assert all(phase not in TERMINAL_PHASES for phase in walk[:-1])


@settings(max_examples=50)
@given(pair=illegal_phase_pairs())
def test_illegal_phase_pair_is_rejected_by_the_phase_machine(
    pair: tuple[OnboardingPhase, OnboardingPhase],
) -> None:
    source, target = pair
    assert is_legal_phase_transition(source, target) is False
    # Identity transitions are always legal, so they can never be drawn here.
    assert source != target

    # The reason code is carried through the refusal untouched; any member of the
    # closed list serves to check that.
    with pytest.raises(IllegalPhaseTransition) as caught:
        validate_phase_transition(source, target, "step_retried")
    assert caught.value.previous_phase == source
    assert caught.value.next_phase == target


def test_illegal_phase_pairs_is_the_exact_complement_of_the_legal_table() -> None:
    every_pair = {(source, target) for source in ONBOARDING_PHASES for target in ONBOARDING_PHASES}
    legal = {pair for pair in every_pair if is_legal_phase_transition(*pair)}

    assert set(ILLEGAL_PHASE_PAIRS) == every_pair - legal
    assert len(ILLEGAL_PHASE_PAIRS) == len(set(ILLEGAL_PHASE_PAIRS))

    # Terminal sources come first, so the reported minimum is a terminal run that
    # advanced rather than a skip inside a live walk.
    terminal_sourced = [pair for pair in ILLEGAL_PHASE_PAIRS if pair[0] in TERMINAL_PHASES]
    assert list(ILLEGAL_PHASE_PAIRS[: len(terminal_sourced)]) == terminal_sourced
    assert terminal_sourced


@settings(max_examples=50)
@given(profile=provider_profiles(), divergent=divergent_profiles())
def test_generated_profile_admits_its_own_urls_and_denies_the_mutated_one(
    profile: ProviderProfile, divergent: DivergentProfile
) -> None:
    # The guarantee the allow-list confinement property rests on: a generated
    # profile derives an allow-list that admits everything it declares, and a
    # mutated URL is never in it.
    for candidate in (profile, divergent.profile):
        assert candidate.app_slug not in RESERVED_APP_SLUGS
        assert candidate.profile_digest == compute_profile_digest(candidate)

        # Raises for a slug a reviewed recipe governs, so reaching here is itself
        # the catalog-disjointness check the property depends on.
        allowed = candidate.allowed_hosts()
        assert allowed.vendor_wildcard_domains == (candidate.registrable_domain,)
        for url in candidate.operational_urls():
            assert evaluate_navigation(url, allowed).allowed is True

    assert divergent.mutation in OFF_DOMAIN_MUTATIONS
    denied = evaluate_navigation(divergent.url, divergent.profile.allowed_hosts())
    assert denied.allowed is False
