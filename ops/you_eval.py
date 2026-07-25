"""Deterministic evaluation harness for the You.com discovery layer.

Two modes:

* Offline (default, always safe, no network): score a set of candidates —
  either hand-built sanitized fixtures or a recorded live result — against
  the reviewed dataset in ``tests/fixtures/you_eval_dataset.json``. This
  measures the RANKING/POLICY/CLASSIFICATION logic deterministically.
* Live (opt-in only): ``tests/live/test_you_discovery_live.py`` calls the
  real configured discovery providers for each app in the dataset and feeds
  their output through the SAME :func:`score_candidates` used here, under a
  strict call budget, gated by ``RUN_LIVE_YOU_TESTS=1``.

Neither mode ever prints a full provider response or launches Browser Use.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from ops.you_research import EvidenceCandidate, ResearchHostPolicy

DATASET_PATH = Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "you_eval_dataset.json"


@dataclass(frozen=True, slots=True)
class EvalApp:
    app_slug: str
    app_name: str
    expected_categories: tuple[str, ...]
    approved_hosts: tuple[str, ...]


def load_dataset(path: Path = DATASET_PATH) -> tuple[EvalApp, ...]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    return tuple(
        EvalApp(
            app_slug=entry["app_slug"],
            app_name=entry["app_name"],
            expected_categories=tuple(entry["expected_categories"]),
            approved_hosts=tuple(entry["approved_hosts"]),
        )
        for entry in payload["apps"]
    )


@dataclass(frozen=True, slots=True)
class AppEvalResult:
    app_slug: str
    official_host_precision: float
    category_recall: float
    candidate_count: int
    latency_ms: float | None = None


def score_candidates(
    app: EvalApp, candidates: Sequence[EvidenceCandidate], *, latency_ms: float | None = None
) -> AppEvalResult:
    """Score discovered candidates (fixture or live) against a reviewed app entry.

    * ``official_host_precision`` — fraction of candidates whose host passes
      the app's reviewed :class:`ResearchHostPolicy`. An app with NO reviewed
      hosts and NO candidates scores 1.0 (truthfully found nothing, invented
      nothing); any candidate at all in that case scores 0.0 precision.
    * ``category_recall`` — fraction of the app's ``expected_categories``
      actually present among the candidates. An app expecting no categories
      scores 1.0 recall only when nothing was found either.
    """

    if not candidates:
        return AppEvalResult(
            app_slug=app.app_slug,
            official_host_precision=1.0,
            category_recall=1.0 if not app.expected_categories else 0.0,
            candidate_count=0,
            latency_ms=latency_ms,
        )

    if not app.approved_hosts:
        # Nothing is reviewed for this app; any candidate at all is a false
        # positive by definition (there is no basis to trust it).
        precision = 0.0
    else:
        policy = ResearchHostPolicy(app.approved_hosts)
        on_policy = 0
        for candidate in candidates:
            try:
                policy.validate_candidate_url(candidate.source_url)
                on_policy += 1
            except ValueError:
                continue
        precision = on_policy / len(candidates)

    found_categories = {candidate.category for candidate in candidates}
    if app.expected_categories:
        recall = len(found_categories & set(app.expected_categories)) / len(app.expected_categories)
    else:
        recall = 0.0  # nothing was expected, yet something was found

    return AppEvalResult(
        app_slug=app.app_slug,
        official_host_precision=precision,
        category_recall=recall,
        candidate_count=len(candidates),
        latency_ms=latency_ms,
    )


@dataclass(frozen=True, slots=True)
class EvalReport:
    results: tuple[AppEvalResult, ...]

    @property
    def average_official_host_precision(self) -> float:
        if not self.results:
            return 0.0
        return sum(r.official_host_precision for r in self.results) / len(self.results)

    @property
    def average_category_recall(self) -> float:
        if not self.results:
            return 0.0
        return sum(r.category_recall for r in self.results) / len(self.results)

    def as_dict(self) -> dict[str, object]:
        """Sanitized report: app slugs, scores, counts, latency — never a query or payload."""

        return {
            "average_official_host_precision": round(self.average_official_host_precision, 3),
            "average_category_recall": round(self.average_category_recall, 3),
            "apps": [
                {
                    "app_slug": result.app_slug,
                    "official_host_precision": round(result.official_host_precision, 3),
                    "category_recall": round(result.category_recall, 3),
                    "candidate_count": result.candidate_count,
                    "latency_ms": result.latency_ms,
                }
                for result in self.results
            ],
        }


__all__ = [
    "DATASET_PATH",
    "AppEvalResult",
    "EvalApp",
    "EvalReport",
    "load_dataset",
    "score_candidates",
]
