"""Strict, secret-free browser guidance for the P1 snapshot's first 25 apps.

The catalog narrows agent behavior; it never grants navigation permission.
``BrowserHostPolicy`` remains the sole authority for allowed browser hosts.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from types import MappingProxyType
from typing import Literal, cast
from urllib.parse import urlsplit

from ops.browser.setup_values import APPROVED_BROWSER_VALUE_REFS

AccessModel = Literal["self_serve", "gated"]

_CATALOG_PATH = Path(__file__).with_name("api_traces.json")
_TOP_LEVEL_KEYS = frozenset(
    {
        "schema_version",
        "catalog_id",
        "selection_source",
        "selection_basis",
        "navigation_mode",
        "divergence_action",
        "global_hard_stops",
        "apps",
    }
)
_APP_KEYS = frozenset(
    {
        "position",
        "app_slug",
        "app_name",
        "access_model",
        "start_url",
        "evidence_url",
        "credential_goal",
        "checkpoints",
        "success_signals",
        "success",
    }
)
_STEP_KEYS = frozenset(
    {
        "order",
        "instruction",
        "expected_signals",
        "completion",
        "allowed_value_refs",
        "credential_creation_controls",
        "requires_hitl",
    }
)
_PREDICATE_KEYS = frozenset(
    {
        "url_path_contains",
        "title_contains",
        "visible_text_contains",
        "required_accessible_names",
        "forbidden_text",
    }
)
# Shared non-secret value-reference vocabulary.
_ALLOWED_VALUE_REFS = APPROVED_BROWSER_VALUE_REFS


@dataclass(frozen=True, slots=True)
class CheckpointPredicate:
    """A structured, evidence-based completion/success condition.

    A predicate is SATISFIED (see ``predicate_satisfied`` in
    ``ops.playwright.worker``) only when every positive condition is present on
    the inspected page and no ``forbidden_text`` appears. Natural-language
    ``expected_signals`` are hints for the model; only these structured
    predicates advance the state machine or declare success.
    """

    url_path_contains: tuple[str, ...] = ()
    title_contains: tuple[str, ...] = ()
    visible_text_contains: tuple[str, ...] = ()
    required_accessible_names: tuple[str, ...] = ()
    forbidden_text: tuple[str, ...] = ()

    def has_positive_condition(self) -> bool:
        """True when the predicate asserts at least one thing that must be present.

        A predicate with only ``forbidden_text`` (or nothing) can never be used
        to PROVE progress, so the state machine treats it as unprovable.
        """

        return bool(
            self.url_path_contains
            or self.title_contains
            or self.visible_text_contains
            or self.required_accessible_names
        )


@dataclass(frozen=True, slots=True)
class BrowserApiTraceStep:
    """One ordered, observable navigation checkpoint.

    ``completion`` is the structured predicate that must be proven before the
    state machine advances past this checkpoint. ``allowed_value_refs`` lists
    the reviewed NON-SECRET values the agent may type here. ``requires_hitl``
    marks a checkpoint whose completion cannot be reliably auto-verified — the
    loop escalates to a human rather than inventing evidence.
    """

    order: int
    instruction: str
    expected_signals: tuple[str, ...]
    completion: CheckpointPredicate = CheckpointPredicate()
    allowed_value_refs: tuple[str, ...] = ()
    credential_creation_controls: tuple[str, ...] = ()
    requires_hitl: bool = False


@dataclass(frozen=True, slots=True)
class BrowserApiTrace:
    """Non-secret browser guidance for one app.

    ``success`` is the structured final predicate for the credential page. It
    must require at least an approved URL/path indicator AND a specific
    structural heading/credential-field label (never generic body text).
    """

    position: int
    app_slug: str
    app_name: str
    access_model: AccessModel
    start_url: str
    evidence_url: str
    credential_goal: str
    checkpoints: tuple[BrowserApiTraceStep, ...]
    success_signals: tuple[str, ...]
    success: CheckpointPredicate = CheckpointPredicate()


@dataclass(frozen=True, slots=True)
class BrowserApiTraceCatalog:
    """Validated versioned catalog and its global fail-closed behavior."""

    schema_version: str
    catalog_id: str
    selection_source: str
    selection_basis: str
    navigation_mode: str
    divergence_action: str
    global_hard_stops: tuple[str, ...]
    apps: tuple[BrowserApiTrace, ...]


def _mapping(value: object, label: str) -> dict[str, object]:
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        raise ValueError(f"{label} must be an object")
    return cast(dict[str, object], value)


def _exact_keys(value: dict[str, object], expected: frozenset[str], label: str) -> None:
    actual = frozenset(value)
    if actual != expected:
        raise ValueError(f"{label} fields do not match the catalog schema")


def _string(value: object, label: str, *, maximum: int = 1_000) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{label} must be a string")
    normalized = value.strip()
    if not normalized or len(normalized) > maximum or "\x00" in normalized:
        raise ValueError(f"{label} is invalid")
    return normalized


def _positive_integer(value: object, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise ValueError(f"{label} must be a positive integer")
    return value


def _strings(
    value: object,
    label: str,
    *,
    minimum: int = 1,
    maximum: int = 20,
) -> tuple[str, ...]:
    if not isinstance(value, list) or not minimum <= len(value) <= maximum:
        raise ValueError(f"{label} has an invalid item count")
    items = tuple(_string(item, f"{label} item") for item in value)
    if len(set(items)) != len(items):
        raise ValueError(f"{label} must not contain duplicates")
    return items


def _https_url(value: object, label: str) -> str:
    url = _string(value, label, maximum=2_048)
    parsed = urlsplit(url)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError(f"{label} must be a query-free, fragment-free HTTPS URL")
    return url


def _predicate_strings(value: object, label: str) -> tuple[str, ...]:
    """Parse an OPTIONAL predicate string list (0..20 items, no duplicates)."""

    if not isinstance(value, list) or len(value) > 20:
        raise ValueError(f"{label} must be a list of at most 20 strings")
    items = tuple(_string(item, f"{label} item", maximum=300) for item in value)
    if len(set(items)) != len(items):
        raise ValueError(f"{label} must not contain duplicates")
    return items


def _parse_predicate(value: object, label: str) -> CheckpointPredicate:
    data = _mapping(value, label)
    extra = frozenset(data) - _PREDICATE_KEYS
    if extra:
        raise ValueError(f"{label} has unknown predicate fields")
    return CheckpointPredicate(
        url_path_contains=_predicate_strings(
            data.get("url_path_contains", []), f"{label} url_path"
        ),
        title_contains=_predicate_strings(data.get("title_contains", []), f"{label} title"),
        visible_text_contains=_predicate_strings(
            data.get("visible_text_contains", []), f"{label} visible_text"
        ),
        required_accessible_names=_predicate_strings(
            data.get("required_accessible_names", []), f"{label} accessible_names"
        ),
        forbidden_text=_predicate_strings(
            data.get("forbidden_text", []), f"{label} forbidden_text"
        ),
    )


def _parse_value_refs(value: object, label: str) -> tuple[str, ...]:
    if not isinstance(value, list) or len(value) > 20:
        raise ValueError(f"{label} must be a list of at most 20 value references")
    refs = tuple(_string(item, f"{label} item", maximum=60) for item in value)
    unknown = set(refs) - _ALLOWED_VALUE_REFS
    if unknown:
        raise ValueError(f"{label} references unapproved values: {sorted(unknown)}")
    return refs


def _parse_creation_controls(value: object, label: str) -> tuple[str, ...]:
    if not isinstance(value, list) or len(value) > 20:
        raise ValueError(f"{label} must be a list of at most 20 controls")
    controls = tuple(_string(item, f"{label} item", maximum=160) for item in value)
    if len(controls) != len(set(controls)):
        raise ValueError(f"{label} must not contain duplicates")
    return controls


def _parse_step(value: object, app_slug: str) -> BrowserApiTraceStep:
    data = _mapping(value, f"{app_slug} checkpoint")
    extra = frozenset(data) - _STEP_KEYS
    if extra:
        raise ValueError(f"{app_slug} checkpoint has unknown fields")
    requires_hitl = bool(data.get("requires_hitl", False))
    completion = (
        _parse_predicate(data["completion"], f"{app_slug} checkpoint completion")
        if "completion" in data
        else CheckpointPredicate()
    )
    # A non-HITL checkpoint MUST carry a provable completion predicate, so the
    # state machine can never advance on an empty/unprovable condition.
    if not requires_hitl and not completion.has_positive_condition():
        raise ValueError(
            f"{app_slug} checkpoint {data.get('order')} needs a completion predicate "
            "or requires_hitl=true"
        )
    return BrowserApiTraceStep(
        order=_positive_integer(data["order"], f"{app_slug} checkpoint order"),
        instruction=_string(data["instruction"], f"{app_slug} checkpoint instruction"),
        expected_signals=_strings(
            data["expected_signals"], f"{app_slug} checkpoint expected signals"
        ),
        completion=completion,
        allowed_value_refs=_parse_value_refs(
            data.get("allowed_value_refs", []), f"{app_slug} checkpoint allowed_value_refs"
        ),
        credential_creation_controls=_parse_creation_controls(
            data.get("credential_creation_controls", []),
            f"{app_slug} checkpoint credential_creation_controls",
        ),
        requires_hitl=requires_hitl,
    )


def _parse_app(value: object) -> BrowserApiTrace:
    data = _mapping(value, "app trace")
    _exact_keys(data, _APP_KEYS, "app trace")
    slug = _string(data["app_slug"], "app slug", maximum=120)
    access_model = _string(data["access_model"], f"{slug} access model", maximum=20)
    if access_model not in {"self_serve", "gated"}:
        raise ValueError(f"{slug} access model is invalid")
    raw_steps = data["checkpoints"]
    if not isinstance(raw_steps, list) or not 2 <= len(raw_steps) <= 10:
        raise ValueError(f"{slug} must have two to ten checkpoints")
    checkpoints = tuple(_parse_step(step, slug) for step in raw_steps)
    if tuple(step.order for step in checkpoints) != tuple(range(1, len(checkpoints) + 1)):
        raise ValueError(f"{slug} checkpoint order must be contiguous")
    success = _parse_predicate(data["success"], f"{slug} success predicate")
    # An EMPTY success predicate is allowed and means "final credential-page
    # readiness must be confirmed by a human" (HITL-only) — the conservative
    # migration for apps without a reviewed, reliable auto-success predicate.
    # A NON-EMPTY success predicate must require an approved URL/path indicator
    # AND a specific structural heading/label — never generic body text alone.
    if success.has_positive_condition() and (
        not success.url_path_contains
        or not (
            success.required_accessible_names
            or success.visible_text_contains
            or success.title_contains
        )
    ):
        raise ValueError(
            f"{slug} success predicate must require a URL/path indicator AND a specific label"
        )
    return BrowserApiTrace(
        position=_positive_integer(data["position"], f"{slug} position"),
        app_slug=slug,
        app_name=_string(data["app_name"], f"{slug} app name", maximum=200),
        access_model=cast(AccessModel, access_model),
        start_url=_https_url(data["start_url"], f"{slug} start URL"),
        evidence_url=_https_url(data["evidence_url"], f"{slug} evidence URL"),
        credential_goal=_string(data["credential_goal"], f"{slug} credential goal"),
        checkpoints=checkpoints,
        success_signals=_strings(data["success_signals"], f"{slug} success signals"),
        success=success,
    )


@lru_cache(maxsize=1)
def load_browser_api_trace_catalog() -> BrowserApiTraceCatalog:
    """Load and strictly validate the repository-owned trace catalog once."""

    try:
        raw: object = json.loads(_CATALOG_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError("browser API trace catalog is unavailable") from exc
    data = _mapping(raw, "browser API trace catalog")
    _exact_keys(data, _TOP_LEVEL_KEYS, "browser API trace catalog")
    raw_apps = data["apps"]
    if not isinstance(raw_apps, list) or len(raw_apps) != 25:
        raise ValueError("browser API trace catalog must contain exactly 25 apps")
    apps = tuple(_parse_app(app) for app in raw_apps)
    if tuple(app.position for app in apps) != tuple(range(1, 26)):
        raise ValueError("browser API trace positions must be contiguous from 1 through 25")
    if len({app.app_slug for app in apps}) != len(apps):
        raise ValueError("browser API trace app slugs must be unique")
    catalog = BrowserApiTraceCatalog(
        schema_version=_string(data["schema_version"], "schema version", maximum=20),
        catalog_id=_string(data["catalog_id"], "catalog ID", maximum=200),
        selection_source=_string(data["selection_source"], "selection source", maximum=200),
        selection_basis=_string(data["selection_basis"], "selection basis"),
        navigation_mode=_string(data["navigation_mode"], "navigation mode", maximum=100),
        divergence_action=_string(data["divergence_action"], "divergence action"),
        global_hard_stops=_strings(
            data["global_hard_stops"], "global hard stops", minimum=3, maximum=10
        ),
        apps=apps,
    )
    if catalog.schema_version != "2.0":
        raise ValueError("unsupported browser API trace catalog schema version")
    if catalog.selection_source != "data/p1/results.json":
        raise ValueError("browser API trace catalog has an unexpected selection source")
    return catalog


@lru_cache(maxsize=1)
def _traces_by_slug() -> Mapping[str, BrowserApiTrace]:
    catalog = load_browser_api_trace_catalog()
    return MappingProxyType({trace.app_slug: trace for trace in catalog.apps})


def get_browser_api_trace(app_slug: str) -> BrowserApiTrace | None:
    """Resolve guidance by canonical app slug without changing host policy."""

    return _traces_by_slug().get(app_slug)


def render_browser_api_trace(trace: BrowserApiTrace) -> str:
    """Render deterministic, bounded checkpoint guidance for the agent prompt."""

    catalog = load_browser_api_trace_catalog()
    lines = [
        f"STRICT APP TRACE: {trace.app_name} ({trace.app_slug}), catalog "
        f"{catalog.catalog_id} schema {catalog.schema_version}.",
        f"CREDENTIAL-PAGE GOAL: {trace.credential_goal}.",
        "Follow these checkpoints in order. Do not skip ahead or substitute another route:",
    ]
    for checkpoint in trace.checkpoints:
        signals = "; ".join(checkpoint.expected_signals)
        lines.append(f"{checkpoint.order}. {checkpoint.instruction}")
        lines.append(f"   Expected checkpoint signals: {signals}.")
    lines.extend(
        (
            "SUCCESS SIGNALS: " + "; ".join(trace.success_signals) + ".",
            "DIVERGENCE: " + catalog.divergence_action,
        )
    )
    return "\n".join(lines)


__all__ = [
    "BrowserApiTrace",
    "BrowserApiTraceCatalog",
    "BrowserApiTraceStep",
    "CheckpointPredicate",
    "get_browser_api_trace",
    "load_browser_api_trace_catalog",
    "render_browser_api_trace",
]
