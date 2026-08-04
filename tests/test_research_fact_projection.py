"""What a research fact may say on the wire, and what it may never say.

``research_fact_groups`` is the ONE place an audit payload is read
(``ops/runs/projections.py``). That makes these tests the boundary check: ``kind``
is a closed vocabulary and safe, but ``subject`` and ``detail`` are free-form
strings truncated to 200 chars, and for three kinds ``subject`` holds a URL or a
host the run observed on the network.

So ``kind`` selects the validator, and a value that does not fit is DROPPED rather
than projected — the same discipline the module applies to durable columns it cannot
project. These tests fail if that inverts.
"""

from __future__ import annotations

from typing import Any

from ops.runs.projections import research_fact_groups


def _fact(
    kind: str,
    subject: str,
    detail: str,
    *,
    created_at: str = "2026-08-02T05:03:50.501456Z",
    event_id: int = 1,
) -> dict[str, Any]:
    return {
        "id": event_id,
        "run_id": "run_test",
        "event_type": "onboarding_research_fact",
        "payload": {"kind": kind, "subject": subject, "detail": detail},
        "created_at": created_at,
    }


def test_an_observed_url_never_leaves_the_projection() -> None:
    """`url_excluded` carries a raw URL in `subject`; only its kind may travel."""

    secret_url = "https://evil.example/callback?token=abc123#fragment"
    groups = research_fact_groups([_fact("url_excluded", secret_url, "scheme_not_https")])

    assert len(groups) == 1
    group = groups[0]
    assert group["kind"] == "url_excluded"
    assert "field" not in group
    assert "adapter" not in group
    # The strongest form of the assertion: the URL appears nowhere in the output.
    assert "evil.example" not in repr(group)
    assert "token" not in repr(group)


def test_a_host_bearing_subject_projects_nothing_beyond_its_kind() -> None:
    """`domain_disagreement` holds comma-joined observed hosts."""

    groups = research_fact_groups(
        [_fact("domain_disagreement", "a.example,b.example", "registrable_domain_mismatch")]
    )

    assert groups[0]["kind"] == "domain_disagreement"
    assert "a.example" not in repr(groups[0])


def test_a_document_url_subject_projects_nothing_beyond_its_kind() -> None:
    groups = research_fact_groups(
        [_fact("document_not_requested", "https://docs.example/page", "fetch_budget")]
    )

    assert groups[0]["kind"] == "document_not_requested"
    assert "docs.example" not in repr(groups[0])


def test_a_profile_field_subject_is_projected() -> None:
    """`field_uncorroborated` names a `ProfileField`, which is a closed vocabulary."""

    groups = research_fact_groups(
        [_fact("field_uncorroborated", "signup_url", "corroborations=1/2")]
    )

    assert groups[0]["field"] == "signup_url"
    assert groups[0]["corroborations"] == 1
    assert groups[0]["corroborations_required"] == 2


def test_an_off_vocabulary_field_is_dropped_but_the_group_survives() -> None:
    """The `field_outside_vocabulary` case: count the refusal, name no field.

    Dropping the whole group would hide that research refused something at all,
    which is the opposite of the point.
    """

    groups = research_fact_groups(
        [_fact("field_uncorroborated", "not_a_real_field", "corroborations=1/2")]
    )

    assert len(groups) == 1
    assert "field" not in groups[0]
    assert groups[0]["occurrences"] == 1


def test_an_unparseable_detail_drops_both_corroboration_counts() -> None:
    groups = research_fact_groups(
        [_fact("field_uncorroborated", "login_url", "corroborations=x/y")]
    )

    assert groups[0]["field"] == "login_url"
    assert "corroborations" not in groups[0]
    assert "corroborations_required" not in groups[0]


def test_a_free_form_detail_is_never_projected() -> None:
    """`adapter_failed` interpolates a third-party exception class name."""

    groups = research_fact_groups(
        [_fact("adapter_failed", "perplexity", "HTTPStatusError/attempt=2")]
    )

    assert groups[0]["adapter"] == "perplexity"
    assert "HTTPStatusError" not in repr(groups[0])


def test_a_capped_count_is_parsed_and_bounded() -> None:
    assert research_fact_groups([_fact("candidate_urls_capped", "9", "fetch_budget")])[0][
        "count"
    ] == 9
    # Beyond the bound the count is dropped rather than clamped, so the number on
    # the wire is always one the durable row actually held.
    assert "count" not in research_fact_groups(
        [_fact("candidate_urls_capped", "99999", "fetch_budget")]
    )[0]


def test_repeated_identical_facts_collapse_to_one_group_with_a_count() -> None:
    """The live shape: 45 repetitions of one claim is one fact, not 45 trace lines."""

    rows = [
        _fact(
            "field_uncorroborated",
            "signup_url",
            "corroborations=1/2",
            created_at=f"2026-08-02T05:03:50.{index:06d}Z",
            event_id=index,
        )
        for index in range(45)
    ]

    groups = research_fact_groups(rows)

    assert len(groups) == 1
    assert groups[0]["occurrences"] == 45
    assert groups[0]["first_at"] == "2026-08-02T05:03:50.000000Z"
    assert groups[0]["last_at"] == "2026-08-02T05:03:50.000044Z"


def test_facts_differing_in_subject_stay_separate_groups() -> None:
    groups = research_fact_groups(
        [
            _fact("field_uncorroborated", "signup_url", "corroborations=1/2"),
            _fact("field_uncorroborated", "login_url", "corroborations=1/2", event_id=2),
        ]
    )

    assert {group["field"] for group in groups} == {"signup_url", "login_url"}


def test_an_unknown_kind_is_ignored_entirely() -> None:
    """A payload naming a kind outside the vocabulary is not a fact we can explain."""

    assert research_fact_groups([_fact("invented_kind", "signup_url", "whatever")]) == []


def test_non_research_events_are_ignored() -> None:
    rows = [
        {
            "id": 1,
            "run_id": "run_test",
            "event_type": "credential_stored",
            "payload": {"kind": "field_uncorroborated", "subject": "signup_url"},
            "created_at": "2026-08-02T05:03:50.501456Z",
        }
    ]

    assert research_fact_groups(rows) == []
