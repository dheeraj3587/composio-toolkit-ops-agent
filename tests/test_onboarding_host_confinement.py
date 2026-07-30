"""Property 3 — the registrable-domain allow-list is never left.

Companion to ``tests/test_browser_host_policy.py`` (which pins the reviewed
recipe-derived boundary) and to the example-based projection tests in
``tests/test_provider_profile.py``. What this module adds is the *dynamic* claim:
drive a browser through a hostile page whose links point at look-alike domains, and
every navigation it actually performs is still inside the run's allow-list.

Two independent boundaries are exercised on every example, deliberately:

* the **caller-side** oracle, ``evaluate_navigation(url, profile.allowed_hosts())``,
  which is what the orchestrator checks before proposing a navigation;
* the **container-side** enforcement, ``ManagedSession.authorize_navigation``, which
  is what actually moves the fake browser here. The session is built from the flat
  pattern list the client sends and the service rebuilds
  (``allowed_hosts_from_patterns``), so the wire form is in the loop too — a list
  that could be widened in transit would show up as an admitted look-alike.

Neither boundary is trusted to judge itself. :func:`_admissible` is an independent
oracle written from Requirement 5's own words (https only, no userinfo, host equal
to or under the single registrable domain, or an exact auxiliary host), and the
denial count is compared against *it*. If ``evaluate_navigation`` and the oracle
ever disagree, the counts diverge and the property fails — which is the point: a
confinement test that asks the boundary whether the boundary is right proves
nothing.

**Validates: Requirements 5.1, 5.2, 5.3, 5.4, 5.5, 5.6, 5.7, 5.8, 5.11**

Requirements 5.9, 5.10 and 5.12-5.15 belong to the action loop's counters and the
orchestrator's durable facts (tasks 13.3, 14.x) and are not asserted here; the one
part of 5.9 that is structural — a denial leaves the current URL unchanged — is,
because the fake browser below is the thing that would otherwise move.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import urlsplit, urlunsplit

import pytest
from hypothesis import given
from hypothesis import strategies as st

from browser_service.session_manager import ManagedSession
from ops.browser.host_policy import (
    BrowserAllowedHosts,
    BrowserHostDecision,
    allowed_hosts_from_patterns,
    evaluate_navigation,
    first_denied_navigation,
    registrable_domain,
)
from ops.providers.profile import ProviderProfile
from tests.support.onboarding_strategies import (
    OFF_DOMAIN_MUTATIONS,
    PageFixture,
    adversarial_pages,
    divergent_profiles,
    https_urls,
    provider_profiles,
)

# The two denial codes Requirement 5 closes over: 5.7 for a host outside the
# allow-list, 5.8 for a non-https or malformed target. Keyed by mutation class so a
# shrunk counterexample naming ``punycode`` is checked against the code that class
# must produce, not merely against "some denial".
_EXPECTED_DENIAL_REASON: dict[str, str] = {
    "suffix_append": "browser_host_not_in_app_policy",
    "punycode": "browser_host_not_in_app_policy",
    "scheme_downgrade": "browser_url_not_https_or_malformed",
    "userinfo_embedded": "browser_url_not_https_or_malformed",
}

assert set(_EXPECTED_DENIAL_REASON) == set(OFF_DOMAIN_MUTATIONS), (
    "a new off-domain mutation class must declare the denial code it expects"
)


# --- The independent oracle ---------------------------------------------------


def _host_of(url: str) -> str:
    """The host a URL targets, folded, or ``""`` when there is none."""

    return (urlsplit(url).hostname or "").rstrip(".").casefold()


def _auxiliary_hosts(profile: ProviderProfile) -> frozenset[str]:
    return frozenset(host.host.strip().rstrip(".").casefold() for host in profile.auxiliary_hosts)


def _admissible(url: str, profile: ProviderProfile) -> bool:
    """Whether Requirement 5 says this URL may be navigated to, read literally.

    Written from the acceptance criteria rather than from
    ``ops.browser.host_policy``: 5.1/5.3 (one registrable domain and its
    subdomains), 5.4 (auxiliary hosts as exact entries only), 5.5 (fold case, drop
    one trailing dot), 5.8 (https, well formed). Kept deliberately naive — it is a
    yardstick, not an implementation.
    """

    parsed = urlsplit(url)
    if parsed.scheme != "https" or parsed.username or parsed.password:
        return False
    host = _host_of(url)
    if not host:
        return False
    if host in _auxiliary_hosts(profile):
        return True
    domain = profile.registrable_domain.casefold()
    return host == domain or host.endswith(f".{domain}")


# --- A browser that cannot move unless the container admits the URL -----------


@dataclass(slots=True)
class ConfinedBrowser:
    """A fake browser driven exclusively through the container-side check.

    It has no navigate path that skips :meth:`propose`, which is the whole point:
    the property can then talk about "every URL the browser was asked to navigate"
    without having to trust a caller to have checked first (5.6). On a denial the
    current URL is left exactly as it was (5.9).
    """

    session: ManagedSession
    current_url: str = ""
    decisions: list[BrowserHostDecision] = field(default_factory=list)
    visited: list[str] = field(default_factory=list)
    denials: list[BrowserHostDecision] = field(default_factory=list)

    def propose(self, url: str) -> BrowserHostDecision:
        before = self.current_url
        decision = self.session.authorize_navigation(url)
        self.decisions.append(decision)
        if not decision.allowed:
            self.denials.append(decision)
            self.current_url = before
            return decision
        self.visited.append(url)
        self.current_url = url
        return decision

    def visited_hosts(self) -> frozenset[str]:
        return frozenset(_host_of(url) for url in self.visited)


def _session_for(profile: ProviderProfile, allowed: BrowserAllowedHosts) -> ManagedSession:
    """A container session carrying the run allow-list, rebuilt from the wire form.

    ``allowed_hosts_from_patterns`` is the service's own rebuild path
    (``browser_service/main.py`` session creation), so a pattern list that could be
    widened or truncated in transit is inside the property rather than assumed away.
    """

    rebuilt = allowed_hosts_from_patterns(profile.app_slug, allowed.patterns())
    return ManagedSession(
        session_id=f"session-{profile.app_slug}",
        owner="owner-onboarding",
        app_slug=profile.app_slug,
        run_id=profile.run_id,
        allowed_hosts=rebuilt,
    )


# --- The scenario -------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ConfinementScenario:
    """One run's worth of proposed navigations, half of them hostile.

    ``mutation`` leads the repr for the same reason
    :class:`~tests.support.onboarding_strategies.DivergentProfile` puts it first: a
    shrunk failure should name the mutation class before the profile body.
    """

    mutation: str
    divergent_url: str
    profile: ProviderProfile
    page: PageFixture
    proposals: tuple[str, ...]


def _same_host_retry(url: str) -> str:
    """The same target reached again by a different path.

    A denial that "degrades into an allow" on the second look is the failure mode
    this exists to catch, so every scenario proposes the denied host twice.
    """

    parsed = urlsplit(url)
    return urlunsplit((parsed.scheme, parsed.netloc, "/retry", "", ""))


@st.composite
def confinement_scenarios(draw: st.DrawFn) -> ConfinementScenario:
    """A profile, a hostile page inside its domain, and the URLs a model would take.

    The page's outgoing link is pointed at the divergent URL through
    ``adversarial_pages(link_urls=...)``, which is how "actions synthesized from
    adversarial page content" get into the trace: the look-alike is not handed to
    the browser by the test, it is read off a page the run legitimately visited.
    """

    divergent = draw(divergent_profiles())
    profile = divergent.profile
    page = draw(
        adversarial_pages(
            domain=profile.registrable_domain,
            link_urls=st.just(divergent.url),
        )
    )
    inside = draw(st.lists(https_urls(profile.registrable_domain), max_size=2))
    proposals = (
        # What the run would walk through on its own authority ...
        *profile.operational_urls(),
        page.url,
        *inside,
        *(f"https://{host}/authorize" for host in sorted(_auxiliary_hosts(profile))),
        # ... and what the page tries to talk it into, twice.
        *page.links(),
        divergent.url,
        _same_host_retry(divergent.url),
    )
    return ConfinementScenario(
        mutation=divergent.mutation,
        divergent_url=divergent.url,
        profile=profile,
        page=page,
        proposals=proposals,
    )


# --- Property 3 ---------------------------------------------------------------


@given(scenario=confinement_scenarios())
def test_a_confined_browser_never_leaves_the_run_allow_list(
    scenario: ConfinementScenario,
) -> None:
    """Every navigation performed is inside the allow-list; every other one is denied."""

    profile = scenario.profile
    caller_allowed = profile.allowed_hosts()
    session = _session_for(profile, caller_allowed)

    # 5.11: confinement is only real once the container reports the same allow-list
    # the caller derived. This is the echo ``ops.browser.service_client`` verifies.
    assert set(session.summary().allowed_host_patterns) == set(caller_allowed.patterns())
    assert session.is_confined is True

    browser = ConfinedBrowser(session=session)
    for url in scenario.proposals:
        browser.propose(url)

    # Every proposal was evaluated, exactly once, before anything moved (5.6).
    assert len(browser.decisions) == len(scenario.proposals)

    # The invariant: every URL the browser was actually asked to navigate to — that
    # is, every one it acted on — is admitted by the caller-side allow-list as well
    # as by the container's, and by the independent oracle.
    for url in browser.visited:
        assert evaluate_navigation(url, caller_allowed).allowed is True, url
        assert _admissible(url, profile) is True, url

    # The denial count equals the off-domain proposal count, counted by the oracle
    # rather than by the boundary under test (5.7, 5.8).
    off_domain = tuple(url for url in scenario.proposals if not _admissible(url, profile))
    assert len(browser.denials) == len(off_domain)
    assert len(browser.visited) == len(scenario.proposals) - len(off_domain)
    assert {denial.reason_code for denial in browser.denials} <= set(
        _EXPECTED_DENIAL_REASON.values()
    )

    # The mutation class the generator applied is denied with the code Requirement 5
    # assigns to it, on both of its appearances.
    expected = _EXPECTED_DENIAL_REASON[scenario.mutation]
    divergent_decisions = [
        decision
        for url, decision in zip(scenario.proposals, browser.decisions, strict=True)
        if url == scenario.divergent_url
    ]
    assert divergent_decisions
    for decision in divergent_decisions:
        assert decision.allowed is False
        assert decision.reason_code == expected

    # No denial is followed by a navigation to the denied host. A host-based denial
    # taints the host itself; a scheme downgrade does not, because its host was
    # inside the allow-list all along and only the scheme was wrong.
    tainted = frozenset(
        denial.blocked_hostname
        for denial in browser.denials
        if denial.blocked_hostname
        and not _admissible(f"https://{denial.blocked_hostname}/", profile)
    )
    assert browser.visited_hosts().isdisjoint(tainted)
    assert {denial.current_url for denial in browser.denials}.isdisjoint(browser.visited)

    # A denial leaves the browser where it was (5.9): the last visited URL, or
    # nowhere at all if the whole trace was refused.
    assert browser.current_url == (browser.visited[-1] if browser.visited else "")

    # 5.2: the page was observed, its links were read, and the allow-list is the
    # same object it was before — page content is never an input to it.
    assert profile.allowed_hosts().patterns() == caller_allowed.patterns()
    assert session.allowed_hosts is not None
    assert session.allowed_hosts.patterns() == caller_allowed.patterns()

    # The set-level seam the browser service uses to refuse a whole payload before
    # driving the worker agrees with the per-URL walk above.
    first_denied = first_denied_navigation(scenario.proposals, caller_allowed)
    if off_domain:
        assert first_denied is not None
        assert first_denied.current_url == off_domain[0]
    else:
        assert first_denied is None


# --- Structural backing asserted in this module ------------------------------
#
# Two structural claims the property above rests on. Without the first, an
# allow-list that failed to build would admit everything and the property would
# pass vacuously; without the second, the allow-list could grow a second domain and
# still satisfy every assertion above.


@given(profile=provider_profiles())
def test_evaluate_navigation_is_fail_closed(profile: ProviderProfile) -> None:
    """No allow-list means no navigation — never navigation by omission."""

    empty = BrowserAllowedHosts(
        app_slug=profile.app_slug,
        exact_hosts=(),
        vendor_wildcard_domains=(),
    )
    targets = (*profile.operational_urls(), f"https://{profile.registrable_domain}/")
    for url in targets:
        # The same URLs the profile's own allow-list admits are refused here, so the
        # refusal is the absence of authority rather than a property of the URL.
        assert evaluate_navigation(url, profile.allowed_hosts()).allowed is True, url
        decision = evaluate_navigation(url, empty)
        assert decision.allowed is False, url
        assert decision.reason_code == "browser_host_not_in_app_policy"

    # A container session created without a run allow-list denies every URL rather
    # than falling back to "unconfined means unrestricted".
    unconfined = ManagedSession(
        session_id="session-unconfined",
        owner="owner-onboarding",
        app_slug=profile.app_slug,
    )
    assert unconfined.is_confined is False
    for url in targets:
        assert unconfined.authorize_navigation(url).allowed is False, url

    # And the wire rebuild refuses to hand back a partial or widened allow-list: an
    # empty pattern list is a failure, not an empty policy, and a wildcard wider
    # than one registrable domain is refused outright.
    with pytest.raises(ValueError):
        allowed_hosts_from_patterns(profile.app_slug, ())
    with pytest.raises(ValueError):
        allowed_hosts_from_patterns(
            profile.app_slug,
            (f"*.{profile.registrable_domain.split('.', 1)[1]}",),
        )


@given(profile=provider_profiles())
def test_vendor_wildcard_never_grows_past_the_single_registrable_domain(
    profile: ProviderProfile,
) -> None:
    """One wildcard, over one domain, whatever else the profile declares (5.3, 5.4)."""

    allowed = profile.allowed_hosts()
    auxiliary = _auxiliary_hosts(profile)

    assert allowed.vendor_wildcard_domains == (profile.registrable_domain,)
    assert registrable_domain(profile.registrable_domain) == profile.registrable_domain
    assert [pattern for pattern in allowed.patterns() if pattern.startswith("*.")] == [
        f"*.{profile.registrable_domain}"
    ]

    # Auxiliary hosts are additive EXACT entries and nothing else: reachable
    # themselves, never extended to their own subdomains (5.4).
    assert auxiliary <= set(allowed.exact_hosts)
    assert auxiliary.isdisjoint(allowed.vendor_wildcard_domains)
    for host in auxiliary:
        assert evaluate_navigation(f"https://{host}/authorize", allowed).allowed is True
        assert evaluate_navigation(f"https://evil.{host}/authorize", allowed).allowed is False

    # The round trip through the wire form cannot widen either set.
    rebuilt = allowed_hosts_from_patterns(profile.app_slug, allowed.patterns())
    assert rebuilt.vendor_wildcard_domains == allowed.vendor_wildcard_domains
    assert rebuilt.exact_hosts == allowed.exact_hosts


@given(profile=provider_profiles())
def test_host_comparison_folds_case_and_one_trailing_dot(profile: ProviderProfile) -> None:
    """5.5: fold to lower case, drop one trailing dot — on both sides of the answer."""

    allowed = profile.allowed_hosts()
    domain = profile.registrable_domain

    for host in (domain.upper(), f"{domain}.", f"{domain.upper()}.", f"APP.{domain.upper()}."):
        assert evaluate_navigation(f"https://{host}/login", allowed).allowed is True, host

    # Folding is not a way in: the same normalization applied to a look-alike still
    # leaves it outside.
    for host in (f"{domain.upper()}.EVIL.EXAMPLE.", f"{domain.upper()}-LOOKALIKE.EXAMPLE"):
        decision = evaluate_navigation(f"https://{host}/login", allowed)
        assert decision.allowed is False, host
        assert decision.reason_code == "browser_host_not_in_app_policy"
