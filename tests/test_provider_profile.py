"""Construction-time invariants and content addressing of the per-run provider profile.

Most assertions here are about a REJECTION path: the profile's value is that a
consumer holding one never has to re-check where its URLs point, which is only
true if construction refuses the bad shapes. The closing section covers the
content address, whose value is that the same conclusions digest the same way.
"""

from __future__ import annotations

from dataclasses import replace

import pytest

from ops.browser.host_policy import BrowserPolicyInactiveError, evaluate_navigation
from ops.providers.profile import (
    SOURCE_DIGEST_LENGTH,
    AuxiliaryHost,
    FieldEvidence,
    FlowSpec,
    ProviderProfile,
    compute_profile_digest,
)

DIGEST = "a" * 64
# A userinfo-embedded target: the credential shape here is the point of the
# fixture, not a real credential.
USERINFO_URL = "https://user:pass@provider.com/signup"  # pragma: allowlist secret


def _evidence(**overrides: object) -> FieldEvidence:
    values: dict[str, object] = {
        "field": "signup_url",
        "value": "https://provider.com/signup",
        "source_url": "https://provider.com/docs",
        "source_digest": DIGEST,
        "adapters": ("fake-discovery",),
        "corroborations": 2,
        "confidence": 0.9,
        "extracted_at": "2025-01-01T00:00:00Z",
    }
    values.update(overrides)
    return FieldEvidence(**values)  # type: ignore[arg-type]


def _flow(kind: str = "api_key", **overrides: object) -> FlowSpec:
    values: dict[str, object] = {
        "kind": kind,
        "supported": False,
        "entry_url": None,
    }
    values.update(overrides)
    return FlowSpec(**values)  # type: ignore[arg-type]


def _profile(**overrides: object) -> ProviderProfile:
    values: dict[str, object] = {
        "run_id": "run-1",
        "provider_name": "Provider",
        "app_slug": "provider",
        "registrable_domain": "provider.com",
        "auxiliary_hosts": (),
        "developer_portal_url": "https://developers.provider.com/",
        "signup_url": "https://provider.com/signup",
        "login_url": "https://app.provider.com/login",
        "developer_docs_url": "https://developers.provider.com/docs",
        "developer_app_flow": _flow("developer_app"),
        "oauth_flow": _flow("oauth"),
        "api_key_flow": _flow(
            "api_key",
            supported=True,
            entry_url="https://app.provider.com/settings/api",
        ),
        "pat_flow": _flow("pat"),
        "approval_requirement": "unknown",
        "billing_requirement": "unknown",
        "evidence": (_evidence(),),
        "confidence": 0.85,
        "adapters_engaged": ("fake-discovery",),
        "built_at": "2025-01-01T00:00:00Z",
    }
    values.update(overrides)
    return ProviderProfile(**values)  # type: ignore[arg-type]


# --- FieldEvidence ---------------------------------------------------------


@pytest.mark.parametrize("confidence", [-0.01, 1.01])
def test_field_evidence_rejects_out_of_range_confidence(confidence: float) -> None:
    with pytest.raises(ValueError, match="confidence is out of range"):
        _evidence(confidence=confidence)


def test_field_evidence_rejects_zero_corroborations() -> None:
    with pytest.raises(ValueError, match="at least one corroboration"):
        _evidence(corroborations=0)


@pytest.mark.parametrize("digest", ["", "a" * 63, "a" * 65])
def test_field_evidence_rejects_a_non_sha256_source_digest(digest: str) -> None:
    with pytest.raises(ValueError, match="sha256 source digest"):
        _evidence(source_digest=digest)


def test_field_evidence_admits_the_closed_confidence_bounds() -> None:
    assert _evidence(confidence=0.0).confidence == 0.0
    assert _evidence(confidence=1.0).confidence == 1.0


# --- FlowSpec --------------------------------------------------------------


def test_flow_spec_rejects_a_supported_flow_without_an_entry_url() -> None:
    with pytest.raises(ValueError, match="supported flow requires an entry url"):
        _flow("oauth", supported=True, entry_url=None)


def test_flow_spec_rejects_more_than_eight_steps() -> None:
    with pytest.raises(ValueError, match="steps exceed their bound"):
        _flow("oauth", steps=tuple(f"step {index}" for index in range(9)))


def test_flow_spec_rejects_a_step_longer_than_two_hundred_characters() -> None:
    with pytest.raises(ValueError, match="steps exceed their bound"):
        _flow("oauth", steps=("s" * 201,))


def test_flow_spec_admits_an_unsupported_flow_with_no_entry_url() -> None:
    flow = _flow("pat", steps=tuple("s" * 200 for _ in range(8)))

    assert flow.supported is False
    assert flow.entry_url is None
    assert len(flow.steps) == 8


# --- ProviderProfile: domain confinement ----------------------------------


@pytest.mark.parametrize(
    "url",
    [
        "http://provider.com/signup",  # scheme downgrade
        USERINFO_URL,  # userinfo embedded
        "https://provider.com.evil.io/signup",  # suffix append
        "https://xn--prvider-4za.com/signup",  # punycode look-alike
        "/signup",  # not absolute
    ],
)
def test_profile_rejects_a_url_outside_its_registrable_domain(url: str) -> None:
    with pytest.raises(ValueError, match="signup_url"):
        _profile(signup_url=url)


def test_profile_rejects_a_flow_entry_url_outside_its_registrable_domain() -> None:
    with pytest.raises(ValueError, match="flow entry url"):
        _profile(
            api_key_flow=_flow(
                "api_key",
                supported=True,
                entry_url="https://provider.com.evil.io/settings/api",
            )
        )


def test_profile_admits_a_subdomain_url_folding_case_and_a_trailing_dot() -> None:
    profile = _profile(login_url="https://APP.Provider.com./login")

    assert "https://APP.Provider.com./login" in profile.operational_urls()


def test_profile_admits_a_multi_label_public_suffix_domain() -> None:
    profile = _profile(
        registrable_domain="provider.co.uk",
        developer_portal_url="https://developers.provider.co.uk/",
        signup_url="https://provider.co.uk/signup",
        login_url="https://app.provider.co.uk/login",
        developer_docs_url="https://developers.provider.co.uk/docs",
        api_key_flow=_flow(
            "api_key",
            supported=True,
            entry_url="https://app.provider.co.uk/settings/api",
        ),
    )

    assert profile.registrable_domain == "provider.co.uk"


# --- ProviderProfile: exactly one primary registrable domain --------------


@pytest.mark.parametrize(
    "domain",
    ["app.provider.com", "Provider.com", "provider.com.", "com", "provider"],
)
def test_profile_rejects_a_non_canonical_primary_registrable_domain(domain: str) -> None:
    with pytest.raises(ValueError, match="exactly one canonical registrable domain"):
        _profile(registrable_domain=domain)


def test_profile_rejects_an_auxiliary_host_restating_the_primary_domain() -> None:
    with pytest.raises(ValueError, match="restate the primary registrable domain"):
        _profile(
            auxiliary_hosts=(
                AuxiliaryHost(host="Provider.com.", kind="static_assets", source_digest=DIGEST),
            )
        )


def test_profile_rejects_an_untyped_auxiliary_host() -> None:
    with pytest.raises(ValueError, match="auxiliary host kind"):
        _profile(
            auxiliary_hosts=(
                AuxiliaryHost(
                    host="login.identity.example",
                    kind="analytics",  # type: ignore[arg-type]
                    source_digest=DIGEST,
                ),
            )
        )


def test_profile_rejects_a_malformed_auxiliary_host() -> None:
    with pytest.raises(ValueError, match="resolvable hostname"):
        _profile(
            auxiliary_hosts=(
                AuxiliaryHost(
                    host="https://cdn.example/assets",
                    kind="static_assets",
                    source_digest=DIGEST,
                ),
            )
        )


def test_profile_admits_typed_off_domain_auxiliary_hosts() -> None:
    profile = _profile(
        auxiliary_hosts=(
            AuxiliaryHost(host="login.okta.com", kind="identity_provider", source_digest=DIGEST),
            AuxiliaryHost(host="cdn.provider.net", kind="static_assets", source_digest=DIGEST),
            AuxiliaryHost(
                host="links.mailer.example", kind="email_link_host", source_digest=DIGEST
            ),
        )
    )

    assert len(profile.auxiliary_hosts) == 3
    # An auxiliary host is never an operational URL, so it can never widen the
    # profile's own navigation surface.
    assert all("okta" not in url for url in profile.operational_urls())


# --- ProviderProfile: declared vocabularies and bounds --------------------


def test_profile_rejects_an_approval_requirement_outside_the_vocabulary() -> None:
    with pytest.raises(ValueError, match="approval requirement"):
        _profile(approval_requirement="probably_fine")


def test_profile_rejects_a_billing_requirement_outside_the_vocabulary() -> None:
    with pytest.raises(ValueError, match="billing requirement"):
        _profile(billing_requirement="maybe")


@pytest.mark.parametrize(
    "requirements",
    [
        ("none", "none"),
        ("manual_review", "card_required"),
        ("invite_only", "paid_plan_required"),
        ("unknown", "unknown"),
    ],
)
def test_profile_admits_every_declared_requirement_value(requirements: tuple[str, str]) -> None:
    approval, billing = requirements

    profile = _profile(approval_requirement=approval, billing_requirement=billing)

    assert (profile.approval_requirement, profile.billing_requirement) == (approval, billing)


def test_profile_rejects_out_of_range_confidence() -> None:
    with pytest.raises(ValueError, match="confidence is out of range"):
        _profile(confidence=1.5)


def test_profile_rejects_a_non_sha256_digest() -> None:
    with pytest.raises(ValueError, match="sha256 hex digest"):
        _profile(profile_digest="a" * 63)


def test_profile_rejects_a_non_canonical_app_slug() -> None:
    with pytest.raises(ValueError, match="canonical app slug"):
        _profile(app_slug="Provider App")


# --- ProviderProfile: operational_urls() ---------------------------------


def test_operational_urls_are_deduplicated_in_declaration_order() -> None:
    profile = _profile(
        developer_portal_url="https://developers.provider.com/",
        signup_url="https://provider.com/signup",
        login_url="https://app.provider.com/login",
        developer_docs_url="https://developers.provider.com/",
        api_key_flow=_flow(
            "api_key",
            supported=True,
            entry_url="https://app.provider.com/settings/api",
        ),
        oauth_flow=_flow(
            "oauth",
            supported=True,
            entry_url="https://app.provider.com/login",
        ),
    )

    assert profile.operational_urls() == (
        "https://developers.provider.com/",
        "https://provider.com/signup",
        "https://app.provider.com/login",
        "https://app.provider.com/settings/api",
    )


def test_operational_urls_omit_undeclared_fields() -> None:
    profile = _profile(
        developer_portal_url=None,
        signup_url=None,
        developer_docs_url=None,
        api_key_flow=_flow("api_key"),
    )

    assert profile.operational_urls() == ("https://app.provider.com/login",)


def test_profile_is_frozen() -> None:
    profile = _profile()

    with pytest.raises(AttributeError):
        profile.registrable_domain = "evil.io"  # type: ignore[misc]


# --- compute_profile_digest() --------------------------------------------


def test_profile_digest_is_a_sha256_hex_digest() -> None:
    digest = compute_profile_digest(_profile())

    assert len(digest) == SOURCE_DIGEST_LENGTH
    assert set(digest) <= set("0123456789abcdef")


def test_profile_digest_is_stable_across_equal_bodies() -> None:
    assert compute_profile_digest(_profile()) == compute_profile_digest(_profile())


def test_profile_digest_does_not_depend_on_its_own_stored_value() -> None:
    # The store's precondition is profile.profile_digest == compute_profile_digest(profile),
    # which is only satisfiable if stamping the digest onto the profile leaves it unchanged.
    profile = _profile()
    digest = compute_profile_digest(profile)

    assert compute_profile_digest(replace(profile, profile_digest=digest)) == digest


# --- ProviderProfile.allowed_hosts() -------------------------------------
#
# The projection's whole value is that it can only NARROW. Each test below pins
# one direction of that: the wildcard set never grows past the single primary
# domain, an auxiliary host never becomes a domain, every URL the profile
# declares is reachable, and nothing else is.


def test_allowed_hosts_wildcards_exactly_the_single_registrable_domain() -> None:
    allowed = _profile().allowed_hosts()

    assert allowed.vendor_wildcard_domains == ("provider.com",)
    assert allowed.exact_hosts == ("provider.com",)
    assert allowed.app_slug == "provider"


def test_allowed_hosts_admits_every_url_the_profile_declares() -> None:
    profile = _profile(
        login_url="https://APP.Provider.com./login",
        api_key_flow=_flow(
            "api_key",
            supported=True,
            entry_url="https://app.provider.com:8443/settings/api?tab=keys",
        ),
    )

    allowed = profile.allowed_hosts()

    for url in profile.operational_urls():
        assert evaluate_navigation(url, allowed).allowed is True, url
    # The apex is admitted alongside subdomains, because an apex login page is
    # ordinary and the wildcard alone matches only strict subdomains.
    assert evaluate_navigation("https://provider.com/login", allowed).allowed is True


@pytest.mark.parametrize(
    ("url", "reason_code"),
    [
        ("https://provider.com.evil.io/signup", "browser_host_not_in_app_policy"),
        ("https://xn--prvider-4za.com/signup", "browser_host_not_in_app_policy"),
        ("https://evil.io/provider.com", "browser_host_not_in_app_policy"),
        ("http://provider.com/signup", "browser_url_not_https_or_malformed"),
        (USERINFO_URL, "browser_url_not_https_or_malformed"),
    ],
)
def test_allowed_hosts_refuse_look_alike_and_downgraded_targets(url: str, reason_code: str) -> None:
    decision = evaluate_navigation(url, _profile().allowed_hosts())

    assert decision.allowed is False
    assert decision.reason_code == reason_code


def test_allowed_hosts_append_auxiliary_hosts_to_exact_hosts_only() -> None:
    profile = _profile(
        auxiliary_hosts=(
            AuxiliaryHost(host="login.okta.com", kind="identity_provider", source_digest=DIGEST),
            AuxiliaryHost(host="cdn.provider.net", kind="static_assets", source_digest=DIGEST),
            AuxiliaryHost(
                host="links.mailer.example", kind="email_link_host", source_digest=DIGEST
            ),
        )
    )

    allowed = profile.allowed_hosts()

    # Three auxiliary hosts, and the wildcard set is the same single domain it is
    # for a profile with none: an auxiliary host can never become a second primary.
    assert allowed.vendor_wildcard_domains == ("provider.com",)
    assert allowed.exact_hosts == (
        "provider.com",
        "login.okta.com",
        "cdn.provider.net",
        "links.mailer.example",
    )
    assert allowed.patterns() == (*allowed.exact_hosts, "*.provider.com")


def test_allowed_hosts_do_not_extend_an_auxiliary_host_to_its_subdomains() -> None:
    profile = _profile(
        auxiliary_hosts=(
            AuxiliaryHost(host="login.okta.com", kind="identity_provider", source_digest=DIGEST),
        )
    )

    allowed = profile.allowed_hosts()

    assert evaluate_navigation("https://login.okta.com/authorize", allowed).allowed is True
    assert evaluate_navigation("https://evil.login.okta.com/authorize", allowed).allowed is False
    assert evaluate_navigation("https://okta.com/authorize", allowed).allowed is False


def test_allowed_hosts_fold_auxiliary_host_case_and_a_trailing_dot() -> None:
    profile = _profile(
        auxiliary_hosts=(
            AuxiliaryHost(
                host="  Login.Okta.COM.  ", kind="identity_provider", source_digest=DIGEST
            ),
        )
    )

    allowed = profile.allowed_hosts()

    assert allowed.exact_hosts == ("provider.com", "login.okta.com")
    assert evaluate_navigation("https://LOGIN.Okta.com./authorize", allowed).allowed is True


def test_allowed_hosts_derive_the_domain_for_a_profile_declaring_no_urls() -> None:
    # A profile whose research corroborated the domain but no operational URL is
    # still confined to that domain rather than left without an allow-list.
    profile = _profile(
        developer_portal_url=None,
        signup_url=None,
        login_url=None,
        developer_docs_url=None,
        api_key_flow=_flow("api_key"),
    )
    assert profile.operational_urls() == ()

    allowed = profile.allowed_hosts()

    assert allowed.vendor_wildcard_domains == ("provider.com",)
    assert allowed.exact_hosts == ("provider.com",)


def test_allowed_hosts_wildcard_a_multi_label_public_suffix_domain() -> None:
    profile = _profile(
        registrable_domain="provider.co.uk",
        developer_portal_url="https://developers.provider.co.uk/",
        signup_url="https://provider.co.uk/signup",
        login_url="https://app.provider.co.uk/login",
        developer_docs_url="https://developers.provider.co.uk/docs",
        api_key_flow=_flow(
            "api_key",
            supported=True,
            entry_url="https://app.provider.co.uk/settings/api",
        ),
    )

    allowed = profile.allowed_hosts()

    assert allowed.vendor_wildcard_domains == ("provider.co.uk",)
    # The conservative suffix handling must not hand out a whole public zone.
    assert evaluate_navigation("https://someone-else.co.uk/", allowed).allowed is False


def test_allowed_hosts_are_deterministic_so_a_resume_reproduces_them() -> None:
    profile = _profile(
        auxiliary_hosts=(
            AuxiliaryHost(host="login.okta.com", kind="identity_provider", source_digest=DIGEST),
        )
    )

    assert profile.allowed_hosts().patterns() == profile.allowed_hosts().patterns()


def test_allowed_hosts_refuse_to_substitute_a_reviewed_recipes_authority() -> None:
    # ``pipedrive`` has a reviewed playwright recipe, so the deployment resolves a
    # DIFFERENT authority for that slug. Serving its hosts would make "this
    # allow-list is attributable to the profile" false, so the projection refuses
    # rather than mixing the two.
    profile = _profile(app_slug="pipedrive")

    with pytest.raises(BrowserPolicyInactiveError) as raised:
        profile.allowed_hosts()

    assert raised.value.reason_code == "reviewed_browser_policy_supersedes_profile"
