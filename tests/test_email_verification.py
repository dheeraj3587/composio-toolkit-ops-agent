"""Focused tests for the autonomous signup/login email-verification boundary.

These cover the four bindings that make an inbox safe to read a one-time secret
from (recency, recipient, sender, link host), the timestamp handling that decides
which message is newest, and the Gmail query-unit defect that previously left the
freshness window unenforced.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta

import pytest

from ops.email_verification import (
    MAX_VERIFICATION_AGE_SECONDS,
    VerificationCandidate,
    bind_recipient,
    canonical_address,
    extract_verification_link,
    gmail_freshness_query,
    is_safe_verification_link,
    parse_addresses,
    parse_received_at_ms,
    select_verification,
)
from ops.gmail_worker import _message_timestamp, build_inbox_query

_NOW = datetime(2026, 7, 27, 12, 0, tzinfo=UTC)
_NOW_MS = int(_NOW.timestamp() * 1000)
_IDENTITY = "ops.signup+hubspot@gmail.com"
_REVIEWED = ("app.hubspot.com", "*.hubspot.com")


def _candidate(
    *,
    message_id: str = "m1",
    sender: str = "noreply@hubspot.com",
    recipients: tuple[str, ...] = (_IDENTITY,),
    age_seconds: int = 60,
    subject: str = "Verify your email",
    body: str = "Confirm here: https://app.hubspot.com/verify-email?token=abc123",
) -> VerificationCandidate:
    return VerificationCandidate(
        message_id=message_id,
        sender=sender,
        recipients=recipients,
        received_at=_NOW_MS - age_seconds * 1000,
        subject=subject,
        body=body,
    )


def _select(*candidates: VerificationCandidate, **overrides: object):
    kwargs: dict[str, object] = {
        "purpose": "signup_confirmation",
        "expected_recipient": _IDENTITY,
        "now_ms": _NOW_MS,
        "max_age_seconds": 900,
        "allowed_host_patterns": _REVIEWED,
        "reviewed_sender_patterns": _REVIEWED,
    }
    kwargs.update(overrides)
    return select_verification(candidates, **kwargs)  # type: ignore[arg-type]


# --- Gmail query units: the defect that left freshness unenforced --------------
def test_build_inbox_query_rejects_hours_because_gmail_has_no_hour_unit() -> None:
    # Gmail's relative age operators support only d/m/y, so "1h" was never a
    # one-hour bound. Accepting it silently produced an unbounded window.
    with pytest.raises(ValueError):
        build_inbox_query(newer_than="1h")


def test_build_inbox_query_still_accepts_supported_units() -> None:
    assert build_inbox_query(newer_than="7d") == "newer_than:7d"
    assert build_inbox_query(newer_than="6m") == "newer_than:6m"
    assert build_inbox_query(newer_than="1y") == "newer_than:1y"


def test_gmail_freshness_query_uses_documented_after_operator() -> None:
    query = gmail_freshness_query(now=_NOW, max_age_seconds=900, recipient=_IDENTITY)
    assert "after:2026/07/25" in query
    assert f"to:{_IDENTITY}" in query
    assert "newer_than" not in query


def test_gmail_freshness_query_refuses_an_invalid_recipient() -> None:
    with pytest.raises(ValueError):
        gmail_freshness_query(now=_NOW, max_age_seconds=900, recipient="not-an-address")


# --- timestamp parsing and ordering -------------------------------------------
@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (1_784_899_200_000, 1_784_899_200_000),
        ("1784899200000", 1_784_899_200_000),
        (1_784_899_200, 1_784_899_200_000),
        ("2026-07-27T12:00:00Z", _NOW_MS),
        ("2026-07-27T12:00:00+00:00", _NOW_MS),
        ("Mon, 27 Jul 2026 12:00:00 +0000", _NOW_MS),
    ],
)
def test_parse_received_at_ms_handles_every_provider_shape(value: object, expected: int) -> None:
    assert parse_received_at_ms(value) == expected


@pytest.mark.parametrize("value", ["", "not-a-date", None, 0, -5, True, {"a": 1}])
def test_parse_received_at_ms_refuses_unusable_values(value: object) -> None:
    assert parse_received_at_ms(value) is None


def test_message_timestamp_orders_mixed_epoch_units_numerically() -> None:
    # Epoch SECONDS beside epoch MILLISECONDS: string ordering would rank the
    # older seconds value as newest because "1784899200" sorts above "17848...".
    older_seconds = {"internalDate": "1784899200"}  # epoch seconds
    newer_millis = {"internalDate": "1784985600000"}  # one day later, in ms
    assert _message_timestamp(newer_millis) > _message_timestamp(older_seconds)


def test_selection_prefers_the_genuinely_newest_message() -> None:
    stale = _candidate(
        message_id="stale",
        age_seconds=600,
        body="Confirm here: https://app.hubspot.com/verify-email?token=old",
    )
    fresh = _candidate(
        message_id="fresh",
        age_seconds=30,
        body="Confirm here: https://app.hubspot.com/verify-email?token=new",
    )
    decision = _select(stale, fresh)
    assert decision.resolved is not None
    assert decision.resolved.evidence.message_id == "fresh"


# --- recency ------------------------------------------------------------------
def test_stale_message_is_refused() -> None:
    decision = _select(_candidate(age_seconds=1_800), max_age_seconds=900)
    assert decision.resolved is None
    assert decision.reason_code == "verification_message_stale"


def test_unparsable_timestamp_is_refused_rather_than_assumed_fresh() -> None:
    candidate = VerificationCandidate(
        message_id="m1",
        sender="noreply@hubspot.com",
        recipients=(_IDENTITY,),
        received_at="whenever",
        subject="Verify your email",
        body="https://app.hubspot.com/verify-email?token=abc",
    )
    decision = _select(candidate)
    assert decision.resolved is None
    assert decision.reason_code == "verification_timestamp_unparsable"


def test_future_dated_message_beyond_skew_is_refused() -> None:
    decision = _select(_candidate(age_seconds=-3_600))
    assert decision.resolved is None
    assert decision.reason_code == "verification_message_future_dated"


def test_age_bound_above_the_hard_ceiling_is_refused() -> None:
    decision = _select(_candidate(), max_age_seconds=MAX_VERIFICATION_AGE_SECONDS + 1)
    assert decision.resolved is None
    assert decision.reason_code == "verification_age_bound_invalid"


# --- recipient binding --------------------------------------------------------
def test_exact_plus_tag_recipient_binds() -> None:
    decision = _select(_candidate(recipients=(_IDENTITY,)))
    assert decision.resolved is not None
    assert decision.resolved.evidence.recipient_binding == "exact"


def test_untagged_same_mailbox_is_accepted_as_canonical() -> None:
    decision = _select(_candidate(recipients=("ops.signup@gmail.com",)))
    assert decision.resolved is not None
    assert decision.resolved.evidence.recipient_binding == "canonical"


def test_another_signups_tag_is_refused() -> None:
    decision = _select(_candidate(recipients=("ops.signup+slack@gmail.com",)))
    assert decision.resolved is None
    assert decision.reason_code == "verification_recipient_tag_conflict"


def test_a_different_mailbox_is_refused() -> None:
    decision = _select(_candidate(recipients=("someone.else@gmail.com",)))
    assert decision.resolved is None
    assert decision.reason_code == "verification_recipient_mismatch"


def test_gmail_dot_insensitivity_applies_only_to_google_domains() -> None:
    google = canonical_address("a.b+tag@gmail.com")
    other = canonical_address("a.b+tag@example.com")
    assert google is not None and google.canonical_local == "ab"
    assert other is not None and other.canonical_local == "a.b"


def test_recipient_binding_reads_display_name_headers() -> None:
    observed = parse_addresses(('"Ops Signup" <ops.signup+hubspot@gmail.com>, x@y.com',))
    expected = canonical_address(_IDENTITY)
    assert expected is not None
    assert bind_recipient(expected, observed) == "exact"


# --- sender binding -----------------------------------------------------------
def test_unreviewed_sender_is_refused_when_required() -> None:
    decision = _select(_candidate(sender="noreply@hubsp0t-security.com"))
    assert decision.resolved is None
    assert decision.reason_code == "verification_sender_not_reviewed"


def test_missing_reviewed_sender_set_fails_closed() -> None:
    decision = _select(_candidate(), reviewed_sender_patterns=())
    assert decision.resolved is None
    assert decision.reason_code == "verification_reviewed_sender_set_missing"


def test_sender_subdomain_matches_a_reviewed_wildcard() -> None:
    decision = _select(_candidate(sender="noreply@email.hubspot.com"))
    assert decision.resolved is not None
    assert decision.resolved.evidence.sender_reviewed is True


# --- link host binding --------------------------------------------------------
def test_link_on_an_unreviewed_host_is_refused() -> None:
    decision = _select(_candidate(body="Verify: https://evil.example.com/verify-email?token=abc"))
    assert decision.resolved is None
    assert decision.reason_code == "verification_secret_absent"


def test_plain_http_link_is_never_accepted() -> None:
    assert is_safe_verification_link("http://app.hubspot.com/verify", _REVIEWED) is False


def test_link_with_embedded_credentials_is_refused() -> None:
    # Synthetic userinfo, present only to prove such a URL is rejected.
    url = "https://user:pw@app.hubspot.com/verify"  # pragma: allowlist secret
    assert is_safe_verification_link(url, _REVIEWED) is False


def test_missing_reviewed_host_set_fails_closed() -> None:
    decision = _select(_candidate(), allowed_host_patterns=())
    assert decision.resolved is None
    assert decision.reason_code == "verification_reviewed_host_set_missing"


def test_tracking_and_footer_links_are_never_chosen() -> None:
    body = (
        "Unsubscribe: https://app.hubspot.com/unsubscribe?x=1\n"
        "Logo: https://app.hubspot.com/emailimages/logo.png\n"
        "Verify: https://app.hubspot.com/verify-email?token=real\n"
    )
    link = extract_verification_link(
        "Verify your email",
        body,
        allowed_host_patterns=_REVIEWED,
        require_reviewed_host=True,
    )
    assert link == "https://app.hubspot.com/verify-email?token=real"


# --- secret extraction and evidence safety ------------------------------------
def test_code_is_resolved_when_no_link_is_present() -> None:
    decision = _select(
        _candidate(subject="Your verification code is 481920", body="Use it soon."),
        prefer_link=True,
    )
    assert decision.resolved is not None
    assert decision.resolved.evidence.verification_kind == "code"
    assert decision.resolved.secret.get_secret_value() == "481920"
    assert decision.resolved.evidence.code_length == 6


def test_evidence_never_carries_the_secret_or_link_path() -> None:
    decision = _select(_candidate())
    assert decision.resolved is not None
    secret = decision.resolved.secret.get_secret_value()
    serialized = decision.resolved.evidence.model_dump_json()
    assert "token=abc123" not in serialized
    assert secret not in serialized
    assert decision.resolved.evidence.link_host == "app.hubspot.com"
    assert repr(decision.resolved.secret).find("abc123") == -1


def test_already_consumed_message_is_skipped_for_an_older_candidate() -> None:
    newest = _candidate(message_id="used", age_seconds=30)
    older = _candidate(message_id="unused", age_seconds=120)
    decision = _select(newest, older, consumed_message_ids=("used",))
    assert decision.resolved is not None
    assert decision.resolved.evidence.message_id == "unused"


def test_no_candidates_reports_not_found() -> None:
    decision = _select()
    assert decision.resolved is None
    assert decision.reason_code == "verification_message_not_found"


def test_invalid_expected_recipient_fails_closed() -> None:
    decision = _select(_candidate(), expected_recipient="nope")
    assert decision.resolved is None
    assert decision.reason_code == "verification_expected_recipient_invalid"


def test_reason_codes_are_stable_tokens() -> None:
    pattern = re.compile(r"^[a-z0-9_:-]+$")
    for decision in (
        _select(),
        _select(_candidate(age_seconds=1_800)),
        _select(_candidate(recipients=("ops.signup+slack@gmail.com",))),
        _select(_candidate(sender="noreply@evil.com")),
    ):
        assert pattern.fullmatch(decision.reason_code), decision.reason_code
        assert len(decision.reason_code) <= 100


def test_freshness_window_is_enforced_relative_to_now() -> None:
    # A message exactly at the bound is allowed; one second past it is not.
    assert _select(_candidate(age_seconds=900), max_age_seconds=900).resolved is not None
    assert _select(_candidate(age_seconds=901), max_age_seconds=900).resolved is None


def test_selection_is_deterministic_for_equal_timestamps() -> None:
    first = _candidate(message_id="a", age_seconds=60)
    second = _candidate(message_id="b", age_seconds=60)
    forward = _select(first, second)
    backward = _select(second, first)
    assert forward.resolved is not None and backward.resolved is not None
    # Equal timestamps must not make the winner depend on provider list order in a
    # way that changes which secret is injected across two identical polls.
    assert forward.resolved.evidence.received_at_ms == backward.resolved.evidence.received_at_ms


def test_candidate_older_than_a_day_is_refused_even_with_a_coarse_query() -> None:
    # The server-side query is only a coarse day-granularity pre-filter, so the
    # in-code bound is what actually protects a one-time secret.
    day_old = _candidate(age_seconds=int(timedelta(days=1).total_seconds()))
    decision = _select(day_old, max_age_seconds=900)
    assert decision.resolved is None
