"""Sanitized observability for the browser harness.

The hard constraint: a decision record must be useful for debugging a failed run
WITHOUT becoming a secondary leak of the very material the harness protects. So a
``BrowserDecisionEvent`` carries structure and outcomes — checkpoint order, which
candidate IDs existed, which was chosen, why, and how it ended — and never carries
content.

Specifically never recorded: page text, element values, prompts, model reasoning,
cookies, credentials, query strings, raw URLs (a URL can carry a magic-link token
in its path, so only a coarse fingerprint of the page is kept), or HTML.

The page fingerprint is a truncated SHA-256 over host plus a NORMALIZED path, with
numeric and hex-like segments collapsed. That makes "the same logical page" stable
across accounts and IDs while being non-reversible and free of identifiers.
"""

from __future__ import annotations

import hashlib
import re
from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field, fields
from datetime import datetime
from statistics import median
from typing import Any, Final, Literal
from urllib.parse import urlsplit

from ops.browser.link_log import log_event
from ops.core.redaction import is_vault_reference, redact_text
from ops.onboarding.phase import (
    ONBOARDING_PHASES,
    ONBOARDING_REASON_CODES,
    REASON_CODE_PATTERN,
    TERMINAL_PHASES,
)

SelectionSource = Literal["deterministic", "llm", "hitl"]

# Path segments that are identifiers rather than structure. Collapsed so two runs
# against different accounts fingerprint to the same logical page.
_NUMERIC_SEGMENT = re.compile(r"^\d+$")
_HEXISH_SEGMENT = re.compile(r"^[0-9a-fA-F]{8,}$")
_UUID_SEGMENT = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
_MIXED_ID_SEGMENT = re.compile(r"^(?=.*\d)[A-Za-z0-9_-]{16,}$")

_FINGERPRINT_LENGTH = 16


def normalize_path(path: str) -> str:
    """Collapse identifier-looking segments so a path describes structure only."""

    parts = [segment for segment in (path or "/").split("/") if segment]
    if not parts:
        return "/"
    normalized: list[str] = []
    for segment in parts:
        if (
            _NUMERIC_SEGMENT.match(segment)
            or _UUID_SEGMENT.match(segment)
            or _HEXISH_SEGMENT.match(segment)
            or _MIXED_ID_SEGMENT.match(segment)
        ):
            normalized.append(":id")
        else:
            normalized.append(segment.casefold())
    return "/" + "/".join(normalized)


def page_fingerprint(url: str) -> str:
    """A stable, non-reversible id for a page.

    Built from host + normalized path ONLY. The query string and fragment are
    dropped before hashing because they can carry tokens, and the digest is
    truncated so it is an opaque grouping key rather than a recoverable URL.
    """

    try:
        parsed = urlsplit(url or "")
    except ValueError:
        return "unparseable"
    host = (parsed.hostname or "").casefold()
    if not host:
        return "unknown"
    material = f"{host}{normalize_path(parsed.path)}"
    return hashlib.sha256(material.encode()).hexdigest()[:_FINGERPRINT_LENGTH]


@dataclass(frozen=True, slots=True)
class BrowserDecisionEvent:
    """One decision in the action loop, sanitized for durable storage.

    ``candidate_ids`` are opaque policy-generated IDs, which is exactly why they are
    safe to record: they are derived from the reviewed candidate policy, not from
    page content, and they are what the model was allowed to choose between.
    """

    session_id: str
    checkpoint_order: int
    page_fingerprint: str
    candidate_ids: tuple[str, ...]
    selected_candidate_id: str | None
    selection_source: SelectionSource
    inference_provider: str | None
    action_type: str | None
    result_code: str
    latency_ms: float

    def as_log_fields(self) -> dict[str, object]:
        """Project to structured log fields (all non-secret by construction)."""

        return {
            "session_id": self.session_id,
            "checkpoint_order": self.checkpoint_order,
            "page_fingerprint": self.page_fingerprint,
            # Count plus IDs: the count is the useful aggregate, the IDs allow replay.
            "candidate_count": len(self.candidate_ids),
            "candidate_ids": list(self.candidate_ids),
            "selected_candidate_id": self.selected_candidate_id,
            "selection_source": self.selection_source,
            "inference_provider": self.inference_provider,
            "action_type": self.action_type,
            "result_code": self.result_code,
            "latency_ms": round(self.latency_ms, 2),
        }

    def emit(self) -> None:
        """Write one sanitized structured line through the redacting logger."""

        # Cast keeps mypy honest: log_event takes object-valued kwargs alongside a
        # keyword-only `level`, and `as_log_fields` never produces a `level` key.
        fields: dict[str, Any] = dict(self.as_log_fields())
        log_event("browser.decision", **fields)


# Result codes that mean "this action did not do what the policy expected".
_STALE_TARGET_CODES = frozenset({"stale_target", "target_not_found", "element_detached"})
_POSTCONDITION_CODES = frozenset({"postcondition_failed", "postcondition_timeout"})
_BLOCKED_CODES = frozenset({"navigation_blocked", "off_domain_blocked", "egress_blocked"})


@dataclass(slots=True)
class BrowserRunMetrics:
    """Aggregates sanitized decision events into the Phase 4 metric set.

    Deliberately computed from events rather than incremented ad hoc: the numbers
    can then be recomputed from persisted events, so a metric can never silently
    disagree with the record it came from.
    """

    events: list[BrowserDecisionEvent] = field(default_factory=list)
    runs_started: int = 0
    runs_completed: int = 0
    runs_requiring_hitl: int = 0
    browser_crashes: int = 0
    capacity_rejections: int = 0
    session_durations_seconds: list[float] = field(default_factory=list)
    provider_latencies_ms: dict[str, list[float]] = field(default_factory=dict)

    # --- ingestion ------------------------------------------------------------
    def record(self, event: BrowserDecisionEvent) -> None:
        self.events.append(event)
        if event.inference_provider and event.selection_source == "llm":
            self.provider_latencies_ms.setdefault(event.inference_provider, []).append(
                event.latency_ms
            )

    def record_run_started(self) -> None:
        self.runs_started += 1

    def record_run_completed(self, *, required_hitl: bool) -> None:
        self.runs_completed += 1
        if required_hitl:
            self.runs_requiring_hitl += 1

    def record_browser_crash(self) -> None:
        self.browser_crashes += 1

    def record_capacity_rejection(self) -> None:
        self.capacity_rejections += 1

    def record_session_duration(self, seconds: float) -> None:
        self.session_durations_seconds.append(max(0.0, seconds))

    # --- derived rates --------------------------------------------------------
    @staticmethod
    def _rate(numerator: int, denominator: int) -> float:
        # An undefined rate is 0.0 rather than a division error or a misleading 1.0.
        return round(numerator / denominator, 4) if denominator else 0.0

    @property
    def completion_rate(self) -> float:
        return self._rate(self.runs_completed, self.runs_started)

    @property
    def hitl_rate(self) -> float:
        return self._rate(self.runs_requiring_hitl, self.runs_started)

    @property
    def model_calls(self) -> int:
        return sum(1 for event in self.events if event.selection_source == "llm")

    @property
    def model_calls_per_run(self) -> float:
        return self._rate(self.model_calls, self.runs_started)

    @property
    def deterministic_action_rate(self) -> float:
        """Share of decisions made WITHOUT the model. Higher is better."""

        decisions = len(self.events)
        deterministic = sum(1 for e in self.events if e.selection_source == "deterministic")
        return self._rate(deterministic, decisions)

    @property
    def checkpoint_retry_rate(self) -> float:
        """Share of decisions spent re-attempting a checkpoint already visited."""

        if not self.events:
            return 0.0
        seen: set[tuple[str, int]] = set()
        retries = 0
        for event in self.events:
            key = (event.session_id, event.checkpoint_order)
            if key in seen:
                retries += 1
            else:
                seen.add(key)
        return self._rate(retries, len(self.events))

    def _code_rate(self, codes: frozenset[str]) -> float:
        return self._rate(sum(1 for e in self.events if e.result_code in codes), len(self.events))

    @property
    def stale_target_rate(self) -> float:
        return self._code_rate(_STALE_TARGET_CODES)

    @property
    def postcondition_failure_rate(self) -> float:
        return self._code_rate(_POSTCONDITION_CODES)

    @property
    def blocked_navigation_rate(self) -> float:
        return self._code_rate(_BLOCKED_CODES)

    @property
    def median_session_duration_seconds(self) -> float:
        if not self.session_durations_seconds:
            return 0.0
        return round(median(self.session_durations_seconds), 2)

    def provider_latency_summary(self) -> dict[str, dict[str, float]]:
        """Median and worst latency per inference provider."""

        summary: dict[str, dict[str, float]] = {}
        for provider, samples in sorted(self.provider_latencies_ms.items()):
            if not samples:
                continue
            summary[provider] = {
                "count": float(len(samples)),
                "median_ms": round(median(samples), 2),
                "max_ms": round(max(samples), 2),
            }
        return summary

    def snapshot(self) -> dict[str, object]:
        """The full sanitized metric set, safe to log or expose internally."""

        return {
            "completion_rate": self.completion_rate,
            "hitl_rate": self.hitl_rate,
            "model_calls_per_run": self.model_calls_per_run,
            "deterministic_action_rate": self.deterministic_action_rate,
            "checkpoint_retry_rate": self.checkpoint_retry_rate,
            "stale_target_rate": self.stale_target_rate,
            "postcondition_failure_rate": self.postcondition_failure_rate,
            "blocked_navigation_rate": self.blocked_navigation_rate,
            "median_session_duration_seconds": self.median_session_duration_seconds,
            "browser_crashes": self.browser_crashes,
            "capacity_rejections": self.capacity_rejections,
            "inference_provider_latency": self.provider_latency_summary(),
            "decisions": len(self.events),
            "runs_started": self.runs_started,
        }

    def emit_snapshot(self) -> None:
        fields: dict[str, Any] = dict(self.snapshot())
        log_event("browser.metrics", **fields)


# Field names that must never appear in a decision event or metric payload. Used by
# the Phase 4 DLP test to assert the shape rather than trusting review alone.
FORBIDDEN_EVENT_FIELDS: frozenset[str] = frozenset(
    {
        "cookies",
        "credential",
        "credentials",
        "element_values",
        "html",
        "page_text",
        "password",
        "prompt",
        "prompts",
        "query",
        "query_string",
        "reasoning",
        "storage_state",
        "token",
        "url",
    }
)


def assert_sanitized(fields: Iterable[str]) -> tuple[str, ...]:
    """Return any forbidden field names present (empty tuple means clean)."""

    return tuple(sorted(name for name in fields if name.casefold() in FORBIDDEN_EVENT_FIELDS))


def build_decision_event(
    *,
    session_id: str,
    checkpoint_order: int,
    url: str,
    candidate_ids: Sequence[str],
    selected_candidate_id: str | None,
    selection_source: SelectionSource,
    result_code: str,
    latency_ms: float,
    inference_provider: str | None = None,
    action_type: str | None = None,
) -> BrowserDecisionEvent:
    """Build an event, fingerprinting the URL so no raw URL is ever stored."""

    return BrowserDecisionEvent(
        session_id=session_id,
        checkpoint_order=checkpoint_order,
        page_fingerprint=page_fingerprint(url),
        candidate_ids=tuple(candidate_ids),
        selected_candidate_id=selected_candidate_id,
        selection_source=selection_source,
        inference_provider=inference_provider,
        action_type=action_type,
        result_code=result_code,
        latency_ms=latency_ms,
    )


# --- onboarding autonomy: correlation and metrics ----------------------------
#
# Two things live below, and they answer the two halves of design "Observability".
#
# ``OnboardingCorrelation`` is the nine identifiers Requirement 20.1 puts on every
# structured log record, every metric, and every timeline event. It is a value
# object rather than a logging convention because the requirement is checkable
# only if there is one place that produces the nine fields: a log line assembled
# by hand can quietly omit the attempt, and nothing would notice.
#
# ``OnboardingAutonomyMetrics`` is the Requirement 20.3 metric set, and every
# number in it is a projection of a DURABLE record — the
# ``onboarding_autonomy_outcomes`` rows first, and committed phase boundaries only
# for the two metrics that are per-phase and therefore cannot come from a per-run
# outcome. Nothing here parses a log line (Requirement 20.6); the metrics module
# never opens a database either, so the records are handed in by the caller that
# owns the reads.
#
# Nothing below can carry a secret: every field is a bounded identifier, a closed
# vocabulary member, a content digest, or a count, and a vault reference is
# admitted only in its ``vault://app/kind/id`` reference form.

MAX_OBSERVABILITY_IDENTIFIER_LENGTH: Final = 64

# The nine fields of Requirement 20.1, in the order the design lists them, and the
# single source the three projections below are built from. ``browser_session_id``
# is the design's ``Browser_Session_ID`` — the browser service's own session handle
# — carried under snake_case like every other field so one schema covers all nine.
CORRELATION_FIELDS: Final[tuple[str, ...]] = (
    "run_id",
    "session_id",
    "correlation_id",
    "vault_reference_id",
    "browser_session_id",
    "phase",
    "profile_digest",
    "attempt",
    "reason_code",
)

_PROFILE_DIGEST_PATTERN = re.compile(r"^[0-9a-f]{64}$")

# The phase a completed run stops at, and the verdict that names full autonomy.
_COMPLETED_PHASE: Final = "completed"
_FULLY_AUTONOMOUS: Final = "fully_autonomous"

# The reason code a run carries when the mailbox never yielded its verification.
_VERIFICATION_UNRESOLVED: Final = "verification_unresolved"
# The phase whose duration IS the time to verification.
_VERIFICATION_PHASE: Final = "email_verification"

# The three outcomes of a session reattach after a worker or API restart. A
# recreated session is a failed reattach that recovered, which is why it counts in
# the denominator rather than being ignored.
_REATTACH_SUCCESS: Final = "session_reattached"
_REATTACH_FAILURES: Final = frozenset({"session_recreated", "session_unreattachable"})


def _observability_identifier(value: object, *, field_name: str) -> str:
    """One bounded identifier for a log record, a metric label, or a timeline event.

    A value redaction would rewrite is refused rather than stored in its redacted
    form: an identifier that looks like a secret is a defect at the caller, and
    ``[REDACTED]`` in a correlation field would be a record that survives while
    its meaning does not.
    """

    if not isinstance(value, str):
        raise ValueError(f"an onboarding {field_name} must be text")
    stripped = value.strip()
    if not stripped or len(stripped) > MAX_OBSERVABILITY_IDENTIFIER_LENGTH:
        raise ValueError(f"an onboarding {field_name} must be a bounded, non-empty identifier")
    if redact_text(stripped) != stripped:
        raise ValueError(f"an onboarding {field_name} cannot carry secret-shaped material")
    return stripped


def _observability_count(value: object, *, field_name: str) -> int:
    """One non-negative counter, and never a bool."""

    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"an onboarding {field_name} must be a non-negative count")
    return value


def _moment_seconds(value: object, *, field_name: str) -> datetime:
    """Parse one ISO-8601 UTC timestamp, refusing anything else."""

    if not isinstance(value, str) or not value:
        raise ValueError(f"an onboarding {field_name} must be an ISO-8601 timestamp")
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError(f"an onboarding {field_name} must be an ISO-8601 timestamp") from error


@dataclass(frozen=True, slots=True)
class OnboardingCorrelation:
    """The nine identifiers every onboarding record carries (Requirement 20.1).

    Assembled once and projected three ways — a structured log record, a metric
    label set, and a timeline event — so the three cannot disagree about which run,
    phase, and attempt they describe.

    ``vault_reference_id`` is admitted only as a ``vault://app/kind/id``
    reference: the requirement asks for the reference identifier, and a value
    that is not a reference is refused here rather than logged.
    """

    run_id: str
    phase: str
    profile_digest: str
    reason_code: str
    attempt: int = 0
    session_id: str | None = None
    correlation_id: str | None = None
    vault_reference_id: str | None = None
    browser_session_id: str | None = None

    def __post_init__(self) -> None:
        _observability_identifier(self.run_id, field_name="run id")
        if self.phase not in ONBOARDING_PHASES:
            raise ValueError("an onboarding correlation carries an onboarding phase")
        if self.reason_code not in ONBOARDING_REASON_CODES:
            raise ValueError("an onboarding correlation carries an onboarding reason code")
        # Requirement 20.2, checked where the code is emitted rather than only
        # where it is stored: a code that fails the API's character class would
        # need a translation layer on the way out, and there is none.
        if REASON_CODE_PATTERN.fullmatch(self.reason_code) is None:
            raise ValueError("an onboarding reason code must project to the API untranslated")
        # Empty for a run that stopped before it built a profile; anything else is
        # a content address.
        if self.profile_digest and _PROFILE_DIGEST_PATTERN.fullmatch(self.profile_digest) is None:
            raise ValueError("an onboarding profile digest must be a sha256 hex digest or empty")
        _observability_count(self.attempt, field_name="attempt")
        for name in ("session_id", "correlation_id", "browser_session_id"):
            value = getattr(self, name)
            if value is not None:
                _observability_identifier(value, field_name=name.replace("_", " "))
        if self.vault_reference_id is not None and not is_vault_reference(self.vault_reference_id):
            raise ValueError("a vault reference id must be an exact vault:// reference")

    @classmethod
    def for_outcome(
        cls,
        record: Mapping[str, object],
        *,
        attempt: int = 0,
        session_id: str | None = None,
        correlation_id: str | None = None,
        vault_reference_id: str | None = None,
        browser_session_id: str | None = None,
    ) -> OnboardingCorrelation:
        """The correlation for one autonomy outcome record.

        Reads the run, the terminal phase, the digest, and the reason code off the
        durable record, so a log line about an outcome cannot describe a different
        run than the row it reports.
        """

        return cls(
            run_id=str(record["run_id"]),
            phase=str(record["terminal_phase"]),
            profile_digest=str(record["profile_digest"]),
            reason_code=str(record["reason_code"]),
            attempt=attempt,
            session_id=session_id,
            correlation_id=correlation_id,
            vault_reference_id=vault_reference_id,
            browser_session_id=browser_session_id,
        )

    def as_log_fields(self) -> dict[str, object]:
        """The nine fields as structured log fields, absent ones dropped.

        Projected from :data:`CORRELATION_FIELDS` rather than listed again, so a
        field cannot be carried by the dataclass and missed by the log record.
        """

        fields_out: dict[str, object] = {}
        for name in CORRELATION_FIELDS:
            value = getattr(self, name)
            if value is not None:
                fields_out[name] = value
        return fields_out

    def as_metric_labels(self) -> dict[str, str]:
        """The same nine fields as metric labels: every value a bounded string."""

        return {key: str(value) for key, value in self.as_log_fields().items()}

    def as_timeline_fields(self) -> dict[str, object]:
        """The same nine fields for a timeline event detail object."""

        return self.as_log_fields()

    def emit(self, event: str, **extra: object) -> None:
        """Log one structured line carrying the nine fields plus ``extra``.

        ``extra`` is checked against :data:`FORBIDDEN_EVENT_FIELDS` before it is
        emitted, so a caller cannot widen an onboarding log record into a leak by
        attaching page content or a prompt to it.
        """

        forbidden = assert_sanitized(extra)
        if forbidden:
            raise ValueError(f"onboarding log fields are forbidden: {', '.join(forbidden)}")
        payload: dict[str, Any] = dict(self.as_log_fields())
        payload.update(extra)
        log_event(event, **payload)


@dataclass(frozen=True, slots=True)
class AutonomyOutcomeRecord:
    """One ``onboarding_autonomy_outcomes`` row, read back for metrics.

    The 19 fields of Requirement 20.5, in the table's own column order. It is a
    read model: nothing here writes, and every value is re-checked on the way in,
    so a row that somehow got past the table's CHECKs cannot become a metric.
    """

    run_id: str
    profile_digest: str
    verdict: str
    terminal_phase: str
    reason_code: str
    started_at: str
    ended_at: str
    admission_prompts: int
    captcha_prompts: int
    other_operator_prompts: int
    model_calls: int
    actions_executed: int
    navigation_denials: int
    phases_replayed: int
    effects_skipped_as_duplicate: int
    outcome_unknown_effects: int
    verification_attempts: int
    validation_attempts: int
    duration_seconds: int

    def __post_init__(self) -> None:
        # The correlation's own checks cover the run id, the phase, the digest, and
        # the reason code, so they are not restated here.
        self.correlation()
        _moment_seconds(self.started_at, field_name="outcome start time")
        _moment_seconds(self.ended_at, field_name="outcome end time")
        for name in AUTONOMY_COUNT_FIELDS:
            _observability_count(getattr(self, name), field_name=name)
        if self.other_operator_prompts != 0:
            raise ValueError(
                "an onboarding run emits no operator prompt beyond admission and captcha"
            )
        if self.verdict == _FULLY_AUTONOMOUS and self.captcha_prompts != 0:
            raise ValueError("a fully autonomous run emitted no captcha prompt")

    @classmethod
    def from_row(cls, row: Mapping[str, object]) -> AutonomyOutcomeRecord:
        """Build the read model from one stored row.

        The row must carry exactly the 19 declared fields, which is the same
        refusal the writer makes: a column renamed on one side stops matching here
        rather than becoming a metric computed over a missing count.
        """

        if frozenset(row) != frozenset(AUTONOMY_OUTCOME_FIELDS):
            raise ValueError("an autonomy outcome row carries exactly the 19 declared fields")

        def count(name: str) -> int:
            return _observability_count(row[name], field_name=name)

        return cls(
            run_id=str(row["run_id"]),
            profile_digest=str(row["profile_digest"]),
            verdict=str(row["verdict"]),
            terminal_phase=str(row["terminal_phase"]),
            reason_code=str(row["reason_code"]),
            started_at=str(row["started_at"]),
            ended_at=str(row["ended_at"]),
            admission_prompts=count("admission_prompts"),
            captcha_prompts=count("captcha_prompts"),
            other_operator_prompts=count("other_operator_prompts"),
            model_calls=count("model_calls"),
            actions_executed=count("actions_executed"),
            navigation_denials=count("navigation_denials"),
            phases_replayed=count("phases_replayed"),
            effects_skipped_as_duplicate=count("effects_skipped_as_duplicate"),
            outcome_unknown_effects=count("outcome_unknown_effects"),
            verification_attempts=count("verification_attempts"),
            validation_attempts=count("validation_attempts"),
            duration_seconds=count("duration_seconds"),
        )

    def correlation(
        self,
        *,
        attempt: int = 0,
        session_id: str | None = None,
        correlation_id: str | None = None,
        vault_reference_id: str | None = None,
        browser_session_id: str | None = None,
    ) -> OnboardingCorrelation:
        """The Requirement 20.1 correlation for this record."""

        return OnboardingCorrelation.for_outcome(
            self.as_row(),
            attempt=attempt,
            session_id=session_id,
            correlation_id=correlation_id,
            vault_reference_id=vault_reference_id,
            browser_session_id=browser_session_id,
        )

    def as_row(self) -> dict[str, object]:
        """The 19 fields keyed by name, in the stored column order."""

        return {name: getattr(self, name) for name in AUTONOMY_OUTCOME_FIELDS}

    @property
    def completed(self) -> bool:
        """Whether the run reached ``completed`` rather than another terminal phase."""

        return self.terminal_phase == _COMPLETED_PHASE

    @property
    def operator_prompts(self) -> int:
        """Every human touch point the run needed, admission included."""

        return self.admission_prompts + self.captcha_prompts + self.other_operator_prompts

    def as_view(self) -> dict[str, object]:
        """The ``AutonomyOutcomeView`` field set (design LL-6.2, Requirement 20.8).

        Returned as a mapping rather than an API model so this module stays free of
        ``api/``: the API constructs its own response model from these six keys,
        and the projection cannot drift into carrying a nineteenth field the view
        never declared.
        """

        return {
            "verdict": self.verdict,
            "terminal_phase": self.terminal_phase,
            "reason_code": self.reason_code,
            "admission_prompts": self.admission_prompts,
            "captcha_prompts": self.captcha_prompts,
            "duration_seconds": self.duration_seconds,
        }


# The field split the read model is built from, derived from the dataclass so a
# field added above cannot be missed by :meth:`AutonomyOutcomeRecord.from_row`.
AUTONOMY_OUTCOME_FIELDS: Final[tuple[str, ...]] = tuple(
    declared.name for declared in fields(AutonomyOutcomeRecord)
)
AUTONOMY_TEXT_FIELDS: Final[tuple[str, ...]] = (
    "run_id",
    "profile_digest",
    "verdict",
    "terminal_phase",
    "reason_code",
    "started_at",
    "ended_at",
)
AUTONOMY_COUNT_FIELDS: Final[tuple[str, ...]] = tuple(
    name for name in AUTONOMY_OUTCOME_FIELDS if name not in AUTONOMY_TEXT_FIELDS
)

assert len(AUTONOMY_OUTCOME_FIELDS) == 19, (
    "an autonomy outcome carries the 19 fields Requirement 20.5 enumerates"
)


def autonomy_outcome_view(row: Mapping[str, object]) -> dict[str, object]:
    """Project one stored outcome row onto the run detail view (Requirement 20.8).

    The reader the API wires: a run has a stored outcome only once it is terminal
    (the driver writes at the terminal phase and nowhere else), so the presence of
    a row IS the terminal condition. The terminal phase is re-checked here anyway,
    because a projection that claimed a non-terminal run had finished would be a
    lie told in the response body.
    """

    record = AutonomyOutcomeRecord.from_row(row)
    if record.terminal_phase not in TERMINAL_PHASES:
        raise ValueError("an autonomy outcome projects only for a terminal run")
    return record.as_view()


@dataclass(frozen=True, slots=True)
class Distribution:
    """A bounded summary of one sample set. Never the samples themselves."""

    count: int = 0
    median_seconds: float = 0.0
    p95_seconds: float = 0.0
    max_seconds: float = 0.0

    @classmethod
    def of(cls, samples: Sequence[float]) -> Distribution:
        """Summarize ``samples``; an empty set is zeros rather than an error."""

        if not samples:
            return cls()
        ordered = sorted(max(0.0, sample) for sample in samples)
        # Nearest-rank p95: with few samples it is the worst one, which is the
        # honest answer for a distribution that small.
        index = min(len(ordered) - 1, int(round(0.95 * (len(ordered) - 1))))
        return cls(
            count=len(ordered),
            median_seconds=round(median(ordered), 2),
            p95_seconds=round(ordered[index], 2),
            max_seconds=round(ordered[-1], 2),
        )

    def as_fields(self) -> dict[str, float]:
        return {
            "count": float(self.count),
            "median_seconds": self.median_seconds,
            "p95_seconds": self.p95_seconds,
            "max_seconds": self.max_seconds,
        }


@dataclass(frozen=True, slots=True)
class PhaseSpan:
    """How long one run stood in one phase, derived from two committed boundaries."""

    run_id: str
    phase: str
    exit_reason_code: str
    attempt: int
    seconds: float


def phase_spans(boundaries: Iterable[Mapping[str, object]]) -> tuple[PhaseSpan, ...]:
    """Measure each phase a run stood in, from its committed boundaries.

    A run occupies ``to_phase`` from the moment that boundary was committed until
    the moment the next boundary for the same run was committed, so a span is a
    subtraction over two durable timestamps. The last boundary of a run opens a
    span nothing has closed yet and is therefore not measured — reporting it would
    make a still-running phase look like a fast one.

    Boundaries may arrive for several runs at once; they are grouped by run and
    ordered by the ledger's own sequence, so an interleaved read is fine.
    """

    per_run: dict[str, list[Mapping[str, object]]] = {}
    for boundary in boundaries:
        per_run.setdefault(str(boundary["run_id"]), []).append(boundary)
    spans: list[PhaseSpan] = []
    for run_id, rows in per_run.items():
        ordered = sorted(rows, key=lambda row: int(str(row["sequence"])))
        for entered, left in zip(ordered, ordered[1:], strict=False):
            start = _moment_seconds(entered["committed_at"], field_name="boundary time")
            end = _moment_seconds(left["committed_at"], field_name="boundary time")
            spans.append(
                PhaseSpan(
                    run_id=run_id,
                    phase=str(entered["to_phase"]),
                    exit_reason_code=str(left["reason_code"]),
                    attempt=int(str(left["attempt"])),
                    seconds=max(0.0, (end - start).total_seconds()),
                )
            )
    return tuple(spans)


@dataclass(frozen=True, slots=True)
class OnboardingAutonomyMetrics:
    """The Requirement 20.3 metric set, computed from durable records.

    Constructed through :meth:`from_records` from the rows a caller read: the
    autonomy outcomes for every per-run number, and committed phase boundaries for
    the two per-phase ones (the phase duration distribution and time to
    verification) that a per-run outcome cannot express. No log line is parsed and
    no counter is incremented on the side, which is Requirement 20.6 as a property
    of where the numbers come from rather than a claim about discipline.
    """

    outcomes: tuple[AutonomyOutcomeRecord, ...] = ()
    spans: tuple[PhaseSpan, ...] = ()
    reattach_successes: int = 0
    reattach_attempts: int = 0
    denials_by_phase: Mapping[str, int] = field(default_factory=dict)

    @classmethod
    def from_records(
        cls,
        *,
        outcomes: Iterable[Mapping[str, object]],
        boundaries: Iterable[Mapping[str, object]] = (),
        denials: Iterable[Mapping[str, object]] = (),
    ) -> OnboardingAutonomyMetrics:
        """Build the metric set from stored rows.

        ``denials`` is the ``onboarding_navigation_denials`` read, and it supplies
        only the per-phase BREAKDOWN of denials. The denial COUNT itself comes from
        the outcomes, so the headline number has exactly one source and the two can
        never contradict each other.
        """

        committed = tuple(boundaries)
        reason_codes = [str(row["reason_code"]) for row in committed]
        return cls(
            outcomes=tuple(AutonomyOutcomeRecord.from_row(row) for row in outcomes),
            spans=phase_spans(committed),
            reattach_successes=sum(1 for code in reason_codes if code == _REATTACH_SUCCESS),
            reattach_attempts=sum(
                1
                for code in reason_codes
                if code == _REATTACH_SUCCESS or code in _REATTACH_FAILURES
            ),
            denials_by_phase=dict(Counter(str(row["phase"]) for row in denials)),
        )

    # --- denominators ---------------------------------------------------------
    @staticmethod
    def _rate(numerator: int, denominator: int) -> float:
        # An undefined rate is 0.0, the same choice BrowserRunMetrics makes: a
        # division error and a misleading 1.0 are both worse than a zero.
        return round(numerator / denominator, 4) if denominator else 0.0

    @property
    def runs_measured(self) -> int:
        return len(self.outcomes)

    @property
    def runs_completed(self) -> int:
        return sum(1 for outcome in self.outcomes if outcome.completed)

    # --- the metric set -------------------------------------------------------
    @property
    def fully_autonomous_completion_rate(self) -> float:
        """Runs finished with no human touch point but admission, over all runs."""

        autonomous = sum(1 for outcome in self.outcomes if outcome.verdict == _FULLY_AUTONOMOUS)
        return self._rate(autonomous, self.runs_measured)

    @property
    def operator_prompts_per_completed_run(self) -> float:
        """Human touch points per completed run (target: 1 admission + N CAPTCHA)."""

        prompts = sum(outcome.operator_prompts for outcome in self.outcomes if outcome.completed)
        return self._rate(prompts, self.runs_completed)

    def phase_duration_distribution(self) -> dict[str, dict[str, float]]:
        """Per phase, the summary of how long runs stood in it."""

        samples: dict[str, list[float]] = {}
        for span in self.spans:
            samples.setdefault(span.phase, []).append(span.seconds)
        return {
            phase: Distribution.of(values).as_fields() for phase, values in sorted(samples.items())
        }

    def phase_failure_counts_by_reason(self) -> dict[str, int]:
        """Runs that stopped short of ``completed``, keyed by ``phase:reason_code``.

        Both halves of the key are closed vocabularies, so the label set is bounded
        and no attacker-influenced text can reach a metric name.
        """

        return dict(
            Counter(
                f"{outcome.terminal_phase}:{outcome.reason_code}"
                for outcome in self.outcomes
                if not outcome.completed
            )
        )

    @property
    def verification_resolution_rate(self) -> float:
        """Of the runs that read a mailbox, the share whose verification resolved.

        Unresolved is the run's own recorded reason code, so a run that resolved
        verification and later stopped for some other reason counts as resolved —
        which is what the metric is asking about.
        """

        attempted = [outcome for outcome in self.outcomes if outcome.verification_attempts > 0]
        resolved = sum(
            1 for outcome in attempted if outcome.reason_code != _VERIFICATION_UNRESOLVED
        )
        return self._rate(resolved, len(attempted))

    def time_to_verification(self) -> Distribution:
        """How long the email-verification phase took, over the measured runs."""

        return Distribution.of(
            [span.seconds for span in self.spans if span.phase == _VERIFICATION_PHASE]
        )

    @property
    def first_attempt_validation_pass_rate(self) -> float:
        """Of the runs that validated a credential, the share that passed first try."""

        attempted = [outcome for outcome in self.outcomes if outcome.validation_attempts > 0]
        first_try = sum(
            1 for outcome in attempted if outcome.completed and outcome.validation_attempts == 1
        )
        return self._rate(first_try, len(attempted))

    @property
    def off_domain_denial_count(self) -> int:
        """Navigations refused for leaving the run's allow-list (expected non-zero)."""

        return sum(outcome.navigation_denials for outcome in self.outcomes)

    @property
    def reattach_success_rate(self) -> float:
        """Sessions reattached after a restart, over every reattach attempted."""

        return self._rate(self.reattach_successes, self.reattach_attempts)

    @property
    def duplicate_prevention_hits(self) -> int:
        """Effects the ledger refused to repeat because a receipt already existed."""

        return sum(outcome.effects_skipped_as_duplicate for outcome in self.outcomes)

    @property
    def outcome_unknown_count(self) -> int:
        """Effects whose provider outcome stayed ambiguous (should be near zero)."""

        return sum(outcome.outcome_unknown_effects for outcome in self.outcomes)

    def snapshot(self) -> dict[str, object]:
        """The whole metric set, safe to log or expose internally."""

        return {
            "runs_measured": self.runs_measured,
            "runs_completed": self.runs_completed,
            "fully_autonomous_completion_rate": self.fully_autonomous_completion_rate,
            "operator_prompts_per_completed_run": self.operator_prompts_per_completed_run,
            "phase_duration_seconds": self.phase_duration_distribution(),
            "phase_failure_counts_by_reason": self.phase_failure_counts_by_reason(),
            "verification_resolution_rate": self.verification_resolution_rate,
            "time_to_verification_seconds": self.time_to_verification().as_fields(),
            "first_attempt_validation_pass_rate": self.first_attempt_validation_pass_rate,
            "off_domain_denial_count": self.off_domain_denial_count,
            "off_domain_denials_by_phase": dict(sorted(self.denials_by_phase.items())),
            "reattach_success_rate": self.reattach_success_rate,
            "duplicate_prevention_hits": self.duplicate_prevention_hits,
            "outcome_unknown_count": self.outcome_unknown_count,
        }

    def emit_snapshot(self) -> None:
        """Log the metric set as one structured line."""

        fields_out: dict[str, Any] = dict(self.snapshot())
        log_event("onboarding.autonomy_metrics", **fields_out)


__all__ = [
    "AUTONOMY_COUNT_FIELDS",
    "AUTONOMY_OUTCOME_FIELDS",
    "AUTONOMY_TEXT_FIELDS",
    "CORRELATION_FIELDS",
    "FORBIDDEN_EVENT_FIELDS",
    "MAX_OBSERVABILITY_IDENTIFIER_LENGTH",
    "AutonomyOutcomeRecord",
    "BrowserDecisionEvent",
    "BrowserRunMetrics",
    "Distribution",
    "OnboardingAutonomyMetrics",
    "OnboardingCorrelation",
    "PhaseSpan",
    "SelectionSource",
    "assert_sanitized",
    "autonomy_outcome_view",
    "build_decision_event",
    "normalize_path",
    "page_fingerprint",
    "phase_spans",
]
