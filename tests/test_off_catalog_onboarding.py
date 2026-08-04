"""Onboarding an app that has no reviewed recipe.

Forty-nine of the hundred researched apps have no Composio toolkit, so browser
onboarding is their only route — and none of them has a reviewed recipe. Four
coupled boundaries had to admit a recipe-less run for that to be reachable:

* ``ops/runs/service.py`` decided whether the canonical runtime was entered at all
* ``CanonicalRuntime.create_run`` required a recipe before anything was persisted
* ``api/service.py`` raised ``AppNotFoundError`` on an unknown display name
* ``MountedOnboardingRuntime.advance`` blocked when no recipe snapshot existed

Each test here fails if any one of them regresses. Nothing in this module reaches
the network: runs are created but never advanced, which is the same boundary
``test_mounted_dispatch_boundary.py`` uses.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from ops.browser.host_policy import onboarding_hint_domain
from ops.core.config import Settings
from ops.core.models import CompanyProfile, OperationsRequest
from ops.onboarding.runtime import _is_mounted_request
from ops.runs.service import CredentialSubmissionError, RunService

_OFF_CATALOG_APP = "Resend"
_OFF_CATALOG_HINT = "https://resend.com/signup"


class _NeverStartedPlaywright:
    """Any call proves a session was opened before research ran."""

    provider_name = "playwright"

    async def start(self, profile_id: str | None, **_kwargs: object) -> object:
        raise AssertionError("an off-catalog onboarding run must not start a browser session")

    async def stop(self, context: object) -> None:
        del context


def _company() -> CompanyProfile:
    return CompanyProfile(
        legal_name="Example Labs, Inc.",
        website="https://example.com",
        work_email_ref="vault://company/work_email/profile_1",
        use_case="Connect the authorized integration.",
    )


def _service(tmp_path: Path) -> RunService:
    service = RunService.from_paths(
        db_path=tmp_path / "private" / "ops.db",
        settings=Settings(),
    )
    browser = _NeverStartedPlaywright()
    service._browser_workers = {"playwright": browser}  # type: ignore[assignment]
    service._browser_worker = browser  # type: ignore[assignment]
    return service


def _request(app_name: str, hint_url: str | None) -> OperationsRequest:
    return OperationsRequest(
        app_name=app_name,
        company=_company(),
        account_mode="create_account",
        account_creation_requested=True,
        onboarding=True,
        browser_provider="playwright",
        provider_hint_url=hint_url,
    )


def test_an_off_catalog_app_with_a_hint_creates_a_mounted_run(tmp_path: Path) -> None:
    """The whole point: an app absent from the 50-slug catalog can be onboarded."""

    service = _service(tmp_path)
    run = service.create_run(
        _request(_OFF_CATALOG_APP, _OFF_CATALOG_HINT),
        execution_mode="execute_when_configured",
    )
    for thread in service._browser_threads:
        thread.join(timeout=5)

    stored = service.storage.get_run(str(run["run_id"]))
    assert stored is not None
    assert stored["app_slug"] == "resend"
    assert stored["execution_path"] == "profile_mounted"
    assert stored["status"] == "researching"
    assert stored["phase"] == "research"
    # The mounted seam must claim it, and the sweep must be able to find it again
    # after a crash — a run only this request could advance would be lost.
    assert _is_mounted_request(stored) is True
    assert str(run["run_id"]) in service.storage.stranded_mounted_run_ids(limit=100)


def test_a_recipe_less_run_persists_no_recipe_identity(tmp_path: Path) -> None:
    """NULL recipe columns are what keep the legacy static dispatcher away.

    ``_continue_pristine_playwright_run`` and both reconciliation guards key on
    ``route_kind == "playwright"``. A non-NULL value here would let them claim a
    run that has no reviewed recipe to execute.
    """

    service = _service(tmp_path)
    run = service.create_run(
        _request(_OFF_CATALOG_APP, _OFF_CATALOG_HINT),
        execution_mode="execute_when_configured",
    )
    for thread in service._browser_threads:
        thread.join(timeout=5)

    stored = service.storage.get_run(str(run["run_id"]))
    assert stored is not None
    assert stored["route_kind"] is None
    assert stored["readiness_tier"] is None
    assert stored["recipe_version"] is None
    assert stored["recipe_snapshot"] is None


def test_the_hint_is_the_only_research_seed_and_is_not_a_navigation_target(
    tmp_path: Path,
) -> None:
    """The hint is evidence at creation, not yet a place the browser may go.

    ``signup_url``/``login_url`` are ``NAVIGATION_TARGET_FIELDS``. Writing an
    uncorroborated hint into one would make it a browser destination a full
    corroboration step before the profile builder has agreed it is real.
    """

    service = _service(tmp_path)
    run = service.create_run(
        _request(_OFF_CATALOG_APP, _OFF_CATALOG_HINT),
        execution_mode="execute_when_configured",
    )
    for thread in service._browser_threads:
        thread.join(timeout=5)

    stored = service.storage.get_run(str(run["run_id"]))
    assert stored is not None
    research = stored["operational_research"]
    assert research["evidence_urls"] == [_OFF_CATALOG_HINT]
    assert research["confidence"] == 0.0
    for field in (
        "signup_url",
        "login_url",
        "credential_management_url",
        "developer_portal_url",
    ):
        assert research[field] is None


@pytest.mark.parametrize(
    "hint_url",
    [
        pytest.param(None, id="no_hint"),
        pytest.param("https://127.0.0.1/signup", id="ip_literal"),
        pytest.param("https://localhost/signup", id="localhost"),
        pytest.param("https://example.com/signup", id="non_vendor_domain"),
    ],
)
def test_an_unusable_hint_is_refused_before_a_run_exists(
    tmp_path: Path,
    hint_url: str | None,
) -> None:
    """Fail closed rather than seed a host policy from an unattributable hint.

    With no recipe the hint becomes the run's ENTIRE host policy, so falling back
    to the app name would widen the allow-list from a display string.
    """

    service = _service(tmp_path)
    with pytest.raises(CredentialSubmissionError):
        service.create_run(
            _request(_OFF_CATALOG_APP, hint_url),
            execution_mode="execute_when_configured",
        )
    assert service.storage.count_runs() == 0


def test_a_reviewed_recipe_still_wins_over_a_hint(tmp_path: Path) -> None:
    """An on-catalog onboarding run is unchanged: the recipe remains authority.

    Telegram is a reviewed Playwright recipe with no static signup URL, so it
    belongs to the mounted seam too — but with its recipe identity intact. If a
    hint could displace that, the reviewed-recipe guard would be bypassable by
    passing a URL.
    """

    service = _service(tmp_path)
    run = service.create_run(
        _request("Telegram", "https://not-telegram.example.org/signup"),
        execution_mode="execute_when_configured",
    )
    for thread in service._browser_threads:
        thread.join(timeout=5)

    stored = service.storage.get_run(str(run["run_id"]))
    assert stored is not None
    assert stored["app_slug"] == "telegram"
    assert stored["execution_path"] == "profile_mounted"
    assert stored["route_kind"] == "playwright"
    assert stored["readiness_tier"] == "owner_submit_ready"
    assert stored["recipe_snapshot"] is not None


def test_a_non_onboarding_off_catalog_request_is_still_refused(tmp_path: Path) -> None:
    """This widens onboarding only. An ordinary run keeps its catalog binding."""

    service = _service(tmp_path)
    with pytest.raises(CredentialSubmissionError):
        service.create_run(
            OperationsRequest(
                app_name=_OFF_CATALOG_APP,
                company=_company(),
                account_mode="existing_account",
                browser_provider="playwright",
            ),
            execution_mode="execute_when_configured",
        )
    assert service.storage.count_runs() == 0


class TestOnboardingHintDomain:
    """The gate every one of the four boundaries defers to."""

    @pytest.mark.parametrize(
        ("hint_url", "expected"),
        [
            ("https://resend.com/signup", "resend.com"),
            ("https://www.linear.app/signup", "linear.app"),
            # A multi-label suffix must not collapse to the public zone.
            ("https://app.vendor.co.uk/login", "vendor.co.uk"),
        ],
    )
    def test_a_vendor_url_yields_its_registrable_domain(self, hint_url: str, expected: str) -> None:
        assert onboarding_hint_domain(hint_url) == expected

    @pytest.mark.parametrize(
        "hint_url",
        [
            pytest.param(None, id="absent"),
            pytest.param("http://vendor.com/signup", id="not_https"),
            pytest.param("https://127.0.0.1/signup", id="ip_literal"),
            pytest.param("https://localhost/signup", id="localhost"),
            pytest.param("https://example.com/signup", id="reserved_example"),
            pytest.param("https://evil.github.io/vendor", id="shared_code_host"),
            pytest.param("https://user:pw@vendor.com/", id="embedded_credentials"),
            pytest.param("https://vendor.com/x?access_token=abc", id="session_artifact"),
            pytest.param("https://vendor.com/x#fragment", id="fragment"),
            pytest.param("not-a-url", id="not_a_url"),
        ],
    )
    def test_anything_unattributable_is_refused(self, hint_url: str | None) -> None:
        assert onboarding_hint_domain(hint_url) is None
