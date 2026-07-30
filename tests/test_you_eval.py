"""Offline evaluator: scores hand-built, sanitized fixture candidates against
the reviewed dataset in tests/fixtures/you_eval_dataset.json.

No network call is made anywhere in this file. These fixtures represent
what a "good" discovery result AND an occasionally noisy one would look
like, using real, verified URL shapes for each vendor rather than invented
ones. This measures the ranking/policy/classification logic deterministically
— it is not a substitute for the opt-in live evaluator in tests/live/, which
measures real provider quality.
"""

from __future__ import annotations

from ops.you.eval import EvalReport, load_dataset, score_candidates
from ops.you.research import EvidenceCandidate, classify_category

DATASET = load_dataset()


def _fixture(url: str, **overrides: object) -> EvidenceCandidate:
    fields: dict[str, object] = {
        "source_url": url,
        "provider": "you_search",
        "query_type": "access",
        "rank": 0,
        "category": classify_category(url),
    }
    fields.update(overrides)
    return EvidenceCandidate.model_validate(fields)


# Sanitized, hand-built fixture candidate sets. Real URL shapes for each
# vendor, verified during offline recipe authoring (see docs/APP_RECIPES.md),
# not live search output.
_FIXTURES: dict[str, tuple[EvidenceCandidate, ...]] = {
    "pipedrive": (
        _fixture("https://app.pipedrive.com/login"),
        _fixture("https://developers.pipedrive.com/"),
        _fixture("https://app.pipedrive.com/settings/api/token"),
    ),
    "hubspot": (
        _fixture("https://app.hubspot.com/login"),
        _fixture("https://developers.hubspot.com/docs/api/private-apps"),
    ),
    "twilio": (
        _fixture("https://www.twilio.com/login"),
        _fixture("https://www.twilio.com/docs/iam/api-keys/keys-in-console"),
        # console.twilio.com is a REAL, on-policy, verified host — included so
        # precision reflects it too — but its bare root has no path keyword,
        # so it classifies "unknown" (a documented classifier limitation).
        _fixture("https://console.twilio.com/"),
    ),
    "slack": (
        _fixture("https://slack.com/signin"),
        _fixture("https://docs.slack.dev/authentication/installing-with-oauth"),
        _fixture("https://api.slack.com/apps"),  # verified, on-policy, classifies "unknown"
    ),
    "zoho": (
        _fixture("https://www.zoho.com/accounts/protocol/oauth-setup.html"),
        _fixture("https://accounts.zoho.com/"),
        # One deliberately OFF-POLICY candidate, proving precision scoring
        # actually penalizes it rather than trusting every result.
        _fixture("https://zoho-community-forum.example/thread/123", category="unknown"),
    ),
    "attio": (
        _fixture("https://app.attio.com/login"),
        _fixture("https://docs.attio.com/rest-api/overview"),
    ),
    "twenty": (
        _fixture("https://docs.twenty.com/"),
        # api.twenty.com's bare root is a real, on-policy, verified host that
        # still classifies "unknown" — see the classifier-limitation note.
        _fixture("https://app.twenty.com/"),
    ),
    "unknown-nonexistent-vendor": (),  # nothing exists to find; must stay empty
}


def test_dataset_loads_with_expected_apps() -> None:
    slugs = {app.app_slug for app in DATASET}
    assert slugs == set(_FIXTURES)
    assert len(DATASET) == 8


def test_reviewed_apps_score_full_precision_and_recall() -> None:
    report = EvalReport(
        results=tuple(
            score_candidates(app, _FIXTURES[app.app_slug])
            for app in DATASET
            if app.app_slug not in {"zoho", "unknown-nonexistent-vendor"}
        )
    )
    for result in report.results:
        assert result.official_host_precision == 1.0, result.app_slug
        assert result.category_recall == 1.0, result.app_slug


def test_noisy_candidate_is_penalized_in_precision_not_hidden() -> None:
    zoho = next(app for app in DATASET if app.app_slug == "zoho")
    result = score_candidates(zoho, _FIXTURES["zoho"])
    assert 0.0 < result.official_host_precision < 1.0
    assert result.candidate_count == 3


def test_unknown_app_degrades_to_a_truthful_empty_result() -> None:
    unknown = next(app for app in DATASET if app.app_slug == "unknown-nonexistent-vendor")
    result = score_candidates(unknown, _FIXTURES["unknown-nonexistent-vendor"])
    assert result.candidate_count == 0
    assert result.official_host_precision == 1.0  # nothing invented
    assert result.category_recall == 1.0  # nothing expected, nothing found


def test_a_candidate_for_an_app_with_no_reviewed_hosts_scores_zero_precision() -> None:
    unknown = next(app for app in DATASET if app.app_slug == "unknown-nonexistent-vendor")
    hallucinated = (_fixture("https://totally-made-up-vendor-site.example/login"),)
    result = score_candidates(unknown, hallucinated)
    assert result.official_host_precision == 0.0


def test_report_aggregates_sanitized_summary_only() -> None:
    report = EvalReport(
        results=tuple(score_candidates(app, _FIXTURES[app.app_slug]) for app in DATASET)
    )
    payload = report.as_dict()
    assert "average_official_host_precision" in payload
    assert "average_category_recall" in payload
    assert len(payload["apps"]) == 8  # type: ignore[arg-type]
    # Never a query, a URL's full text, or provider payload — just slug/scores.
    dumped = str(payload)
    assert "http://" not in dumped and "https://" not in dumped
