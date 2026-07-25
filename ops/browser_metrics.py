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
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from statistics import median
from typing import Any, Literal
from urllib.parse import urlsplit

from ops.browser_link_log import log_event

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


__all__ = [
    "FORBIDDEN_EVENT_FIELDS",
    "BrowserDecisionEvent",
    "BrowserRunMetrics",
    "SelectionSource",
    "assert_sanitized",
    "build_decision_event",
    "normalize_path",
    "page_fingerprint",
]
