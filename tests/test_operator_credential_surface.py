"""An operator may declare the credential surface a login wall hides from research.

The page where an API key is created sits behind authentication, so an
unauthenticated fetch of it returns the login page. Research therefore never sees
the credential path and cannot cite it, every ``FlowSpec`` stays
``supported=False``, and ``developer_app_flows`` returns ``None`` — the run pauses
``flow_unsupported`` before any credential can be minted.

This is the narrow escape hatch: the operator names a PAGE, and it is recorded as a
declaration rather than dressed up as evidence. These tests pin the four properties
that keep it narrow:

* it is attributable — ``adapters=("operator",)``, never a discovery adapter name
* it cannot widen the browser boundary — off-domain declarations are dropped
* it cannot outrank research — a corroborated slot is left alone
* it fills BOTH flow slots, because the selector needs a supported PAIR

Nothing here lowers a corroboration bar: flow fields are absent from
``_REQUIRED_FIELDS`` and already need one citation, while
``registrable_domain``/``signup_url``/``login_url`` still need two from distinct
documents.
"""

from __future__ import annotations

from dataclasses import replace

import pytest

from ops.core.models import CompanyProfile, OperationsRequest
from ops.onboarding.driver import developer_app_flows
from ops.providers.profile import FieldEvidence, FlowSpec, ProviderProfile
from ops.providers.profile_builder import (
    _FactLog,
    _operator_declared_evidence,
    _with_operator_credential_surface,
)

_DOMAIN = "resend.com"
_SURFACE = "https://resend.com/api-keys"


def _log() -> _FactLog:
    return _FactLog(run_id="run_" + "a" * 32, recorder=None)


def _profile() -> ProviderProfile:
    """A profile shaped like the real committed one: two URLs, no flows."""

    return ProviderProfile(
        run_id="run_" + "a" * 32,
        provider_name="Resend",
        app_slug="resend",
        registrable_domain=_DOMAIN,
        auxiliary_hosts=(),
        # Both absent on the real profile: research corroborated neither, which is
        # why every flow below is unsupported.
        developer_portal_url=None,
        developer_docs_url=None,
        signup_url="https://resend.com/signup",
        login_url="https://resend.com/login",
        developer_app_flow=FlowSpec(kind="developer_app", supported=False, entry_url=None),
        oauth_flow=FlowSpec(kind="oauth", supported=False, entry_url=None),
        api_key_flow=FlowSpec(kind="api_key", supported=False, entry_url=None),
        pat_flow=FlowSpec(kind="pat", supported=False, entry_url=None),
        approval_requirement="unknown",
        billing_requirement="unknown",
        evidence=(),
        adapters_engaged=(),
        built_at="2026-08-02T00:00:00Z",
        confidence=0.95,
    )


class TestOperatorDeclaredEvidence:
    def test_an_on_domain_page_is_admitted_and_attributed_to_the_operator(self) -> None:
        evidence = _operator_declared_evidence("api_key_flow", _SURFACE, domain=_DOMAIN)

        assert evidence is not None
        assert evidence.value == _SURFACE
        # Attribution is the whole point: a reader of the profile can tell this
        # apart from a corroborated excerpt without consulting anything else.
        assert evidence.adapters == ("operator",)
        assert evidence.corroborations == 1
        # It cites itself, because there is no fetched document behind it.
        assert evidence.source_url == _SURFACE
        assert len(evidence.source_digest) == 64

    def test_a_subdomain_of_the_profile_domain_is_admitted(self) -> None:
        """The vendor's own app host is still the vendor."""

        evidence = _operator_declared_evidence(
            "api_key_flow", "https://app.resend.com/api-keys", domain=_DOMAIN
        )

        assert evidence is not None

    @pytest.mark.parametrize(
        "url",
        [
            pytest.param("https://evil.com/api-keys", id="other_domain"),
            # The classic suffix-confusion attempt.
            pytest.param("https://resend.com.evil.io/api-keys", id="suffix_confusion"),
            pytest.param("http://resend.com/api-keys", id="not_https"),
            pytest.param("not-a-url", id="malformed"),
        ],
    )
    def test_anything_off_domain_is_refused(self, url: str) -> None:
        """An operator names a page on the provider's domain, never a new host."""

        assert _operator_declared_evidence("api_key_flow", url, domain=_DOMAIN) is None


class TestFoldingIntoAdmittedEvidence:
    def test_one_declaration_fills_three_slots(self) -> None:
        """Three slots, each for a reason the walk would otherwise stall on.

        * ``developer_app_flow`` + ``api_key_flow`` — ``developer_app_flows``
          selects a PAIR and returns ``None`` unless BOTH are supported, so filling
          only the credential slot would leave ``developer_app`` pausing
          ``flow_unsupported`` and change nothing.
        * ``developer_portal_url`` — feeds both ``_reviewed_urls("authenticated")``
          (the phase's only element-independent candidate source) and
          ``expectations_for(...).console_urls`` (which is what lets the post-action
          page classify as ``developer_console_ready``). Without it ``authenticated``
          generates no candidate and ends
          ``loop_no_progress_budget_exhausted``.
        """

        chosen = _with_operator_credential_surface({}, _SURFACE, domain=_DOMAIN, log=_log())

        assert sorted(chosen) == ["api_key_flow", "developer_app_flow", "developer_portal_url"]
        for field in ("api_key_flow", "developer_app_flow", "developer_portal_url"):
            assert chosen[field].value == _SURFACE
            # Every one is attributable to the operator, not to research.
            assert chosen[field].adapters == ("operator",)

    def test_corroborated_research_is_never_overridden(self) -> None:
        """A declaration fills a gap; it does not outrank evidence."""

        researched = FieldEvidence(
            field="api_key_flow",
            value="https://resend.com/researched-surface",
            source_url="https://resend.com/docs",
            source_digest="b" * 64,
            adapters=("perplexity_search",),
            corroborations=2,
            confidence=0.9,
            extracted_at="2026-08-02T00:00:00Z",
        )

        chosen = _with_operator_credential_surface(
            {"api_key_flow": researched}, _SURFACE, domain=_DOMAIN, log=_log()
        )

        assert chosen["api_key_flow"].value == "https://resend.com/researched-surface"
        assert chosen["api_key_flow"].adapters == ("perplexity_search",)
        # The uncorroborated slot is still filled, so the pair becomes selectable.
        assert chosen["developer_app_flow"].adapters == ("operator",)

    def test_an_off_domain_declaration_changes_nothing(self) -> None:
        chosen = _with_operator_credential_surface(
            {}, "https://evil.com/api-keys", domain=_DOMAIN, log=_log()
        )

        assert chosen == {}

    def test_no_declaration_leaves_evidence_untouched(self) -> None:
        chosen = _with_operator_credential_surface({}, None, domain=_DOMAIN, log=_log())

        assert chosen == {}


def test_the_declaration_is_what_makes_a_flow_pair_selectable() -> None:
    """End to end on the selector: the regression this whole item exists for."""

    profile = _profile()
    # Before: exactly the real committed profile's situation.
    assert developer_app_flows(profile, credential_kind="api_key") is None

    declared = FlowSpec(
        kind="developer_app",
        supported=True,
        entry_url=_SURFACE,
        produces=("oauth_client_id", "oauth_client_secret"),
    )
    credential = FlowSpec(kind="api_key", supported=True, entry_url=_SURFACE, produces=("api_key",))
    after = replace(profile, developer_app_flow=declared, api_key_flow=credential)

    selected = developer_app_flows(after, credential_kind="api_key")
    assert selected is not None
    assert selected.creation.kind == "developer_app"
    assert selected.credential.kind == "api_key"


class TestRequestPlumbing:
    def _company(self) -> CompanyProfile:
        return CompanyProfile(
            legal_name="Example Labs, Inc.",
            website="https://example.com",
            work_email_ref="vault://company/work_email/resend",
            use_case="Evaluate transactional email API access.",
        )

    def test_the_request_carries_the_declared_surface(self) -> None:
        request = OperationsRequest(
            app_name="Resend",
            company=self._company(),
            account_mode="create_account",
            onboarding=True,
            provider_hint_url="https://resend.com/signup",
            credential_surface_url=_SURFACE,
        )

        assert request.credential_surface_url == _SURFACE

    def test_it_is_optional(self) -> None:
        """Every existing caller keeps its meaning."""

        request = OperationsRequest(
            app_name="Resend",
            company=self._company(),
            account_mode="create_account",
            onboarding=True,
            provider_hint_url="https://resend.com/signup",
        )

        assert request.credential_surface_url is None

    @pytest.mark.parametrize(
        "url",
        [
            pytest.param("http://resend.com/api-keys", id="not_https"),
            pytest.param("https://resend.com/x?access_token=abc", id="session_artifact"),
            pytest.param("https://resend.com/x#frag", id="fragment"),
        ],
    )
    def test_a_non_operational_url_is_refused_at_the_model_boundary(self, url: str) -> None:
        """Same validator as ``provider_hint_url``: no secrets, no fragments."""

        with pytest.raises(ValueError):
            OperationsRequest(
                app_name="Resend",
                company=self._company(),
                account_mode="create_account",
                onboarding=True,
                credential_surface_url=url,
            )
