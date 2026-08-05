"""A signup-route research agent that works from the app's own site, live.

The reviewed catalog declares a signup policy for exactly one app, so every other
browser-ready app paused at ``signup_policy_absent`` no matter how complete the
rest of its recipe was. This module researches the missing piece instead of
waiting for a human to author it: it reads the app's own official pages, finds
the route they link to, reads the form that route serves, and reports what it
found as structured data.

It is deliberately NOT bound to the P1 snapshot. P1 carries documentation URLs
and nothing about registration, so it is used here as one more page to scan when
it happens to exist — never as the gate on whether research may run at all.

The one boundary that does NOT move: **the researched route must live on a host
the app's reviewed recipe already navigates to.** Research fills in a path inside
an origin a reviewer already approved; it can never introduce a new origin. That
keeps the browser allow-list exactly as wide as it was before this existed, which
is what makes accepting a machine-found URL safe at all.

Every step reports through ``on_progress`` so an operator watching a run sees the
research happen rather than a spinner.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from html import unescape as html_unescape
from typing import Final, Protocol
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit

from ops.recipes.app_recipes import AppRecipe
from ops.research.operational_research import OfficialURLPolicy

# Read once and discarded. A marketing page dwarfs the documentation page the
# evidence fetcher's default is sized for, and nothing here becomes durable
# evidence, so this is a transfer budget rather than a safety boundary.
PAGE_MAX_BYTES: Final = 4 * 1024 * 1024

# Subdomain labels that front documentation or an app console. Dropping one
# reaches the marketing site, which is where a signup link usually lives.
_SITE_LABELS: Final = (
    "docs",
    "developers",
    "developer",
    "api",
    "help",
    "support",
    "app",
    "console",
    "dash",
    "dashboard",
    "my",
    "www",
)

# A link is a signup route because its PATH says so. Link text alone is far too
# loose — "Get started" points at a tutorial as often as a registration form.
_SIGNUP_PATH_PATTERN: Final = re.compile(
    r"(?:^|[/?&=._-])(?:sign[-_]?up|signup|register|registration|create-account|join)(?:$|[/?&=._-])",
    re.IGNORECASE,
)
_ANCHOR_PATTERN: Final = re.compile(r"<a\b[^>]*?\bhref\s*=\s*[\"']([^\"'#][^\"']*)[\"']", re.I)
_BUTTON_PATTERN: Final = re.compile(r"<button\b[^>]*>(.*?)</button>", re.I | re.S)
_SUBMIT_INPUT_PATTERN: Final = re.compile(
    r"<input\b[^>]*\btype\s*=\s*[\"']submit[\"'][^>]*\bvalue\s*=\s*[\"']([^\"']+)[\"']", re.I
)
_TAG_PATTERN: Final = re.compile(r"<[^>]+>")
# The submit control on a registration form. Matched against the button's own
# visible text, which is why it can be this permissive without being loose.
_SUBMIT_LABEL_PATTERN: Final = re.compile(
    r"sign\s*up|create\s+(?:a\s+)?(?:free\s+)?account|get\s+started|register|continue|join",
    re.IGNORECASE,
)
# Federated-identity buttons sit on nearly every registration form. They are
# not the email-first submit control the reviewed flow authorizes, and clicking
# one would hand the run to a third-party identity provider, so they are dropped
# rather than ranked below the real control.
_FEDERATED_LABEL_PATTERN: Final = re.compile(
    r"\b(?:continue|sign\s*(?:up|in)|log\s*in)\s+with\b|\bsso\b|\bsaml\b", re.IGNORECASE
)
_MAX_SUBMIT_LABELS: Final = 10
_MAX_LABEL_CHARS: Final = 120

# The progress steps this agent reports, in the order it performs them. Static
# strings: an operator reads these, and a researched page must never be able to
# author the text shown to them.
ProgressStep = str
PROGRESS_SUMMARIES: Final[dict[str, str]] = {
    "signup_research_started": "Researching where this app registers new accounts.",
    "signup_page_scanned": "Read an official page looking for a registration link.",
    "signup_route_found": "Found the registration route the app's own site links to.",
    "signup_form_read": "Read the registration form and its submit control.",
    "signup_research_exhausted": "No registration route was found on the app's official pages.",
}


class ProgressReporter(Protocol):
    """Reports one research step. ``detail`` is a URL or a slug, never page text."""

    def __call__(self, step: ProgressStep, *, detail: str | None = None) -> None: ...


class SourceFetcherLike(Protocol):
    """The raw-markup half of ``OfficialEvidenceFetcher``."""

    async def fetch_source(
        self, url: str, *, max_bytes: int | None = None
    ) -> tuple[str, str, str]: ...


# Built per policy because the allow-list is derived per app.
FetcherFactory = Callable[[OfficialURLPolicy], SourceFetcherLike]


@dataclass(frozen=True, slots=True)
class SignupRouteFinding:
    """A registration route researched from the app's own site."""

    app_slug: str
    signup_url: str
    #: The absolute path prefix a plan may enter under, derived from the URL.
    entry_path_prefix: str
    #: Visible submit labels read off the registration form itself.
    submit_labels: tuple[str, ...]
    #: The official page that linked to the route.
    evidence_url: str
    #: Every page read, in order, so the operator can retrace the research.
    scanned_pages: tuple[str, ...] = field(default=())


def _noop_progress(step: ProgressStep, *, detail: str | None = None) -> None:
    del step, detail


def candidate_pages(recipe: AppRecipe, *, extra: Sequence[str] = ()) -> tuple[str, ...]:
    """Official pages worth scanning for a registration link, best first.

    The app's own login page comes first: it is the one page every reviewed
    browser recipe has, and a login form almost always links to registration
    right beside it. Then the reviewed developer portal, then the marketing
    origins implied by those hosts.
    """

    seeds = [
        recipe.urls.login,
        *extra,
        recipe.urls.developer_portal,
        recipe.urls.credential_management,
    ]
    pages: list[str] = []
    origins: list[str] = []
    for seed in seeds:
        if not isinstance(seed, str) or not seed:
            continue
        pages.append(seed)
        host = urlsplit(seed).hostname
        if not host:
            continue
        origins.append(f"https://{host}/")
        head, _, tail = host.partition(".")
        # Only ever shortens, and only past a label that fronts docs or a
        # console, so a bare two-label host is never reduced to a public suffix.
        if head.casefold() in _SITE_LABELS and tail.count(".") >= 1:
            origins.append(f"https://{tail}/")
            origins.append(f"https://www.{tail}/")
    ordered: list[str] = []
    for page in (*pages, *origins):
        if page not in ordered:
            ordered.append(page)
    return tuple(ordered)


def signup_anchor(html: str, page_url: str, policy: OfficialURLPolicy) -> str | None:
    """The first anchor on ``page_url`` whose resolved target is a signup route.

    This is a LINK check, not a text check: the URL has to be something the
    official page actually points at. ``urljoin`` against the fetched page's own
    URL is what makes a relative ``href="/signup"`` usable, and the resolved host
    must still pass the policy, so an ad or a third-party widget cannot supply
    one.
    """

    for href in _ANCHOR_PATTERN.findall(html):
        resolved = urljoin(page_url, html_unescape(href))
        split = urlsplit(resolved)
        if split.scheme != "https" or not split.hostname:
            continue
        # Analytics parameters are dropped before matching: a "sign_up" campaign
        # tag rides on links to pages that are not registration routes, while a
        # real one (``/signin?view=signup``) lives in a functional parameter.
        meaningful = urlencode(
            [
                (name, value)
                for name, value in parse_qsl(split.query, keep_blank_values=True)
                if not name.casefold().startswith(("utm_", "ref_"))
            ]
        )
        if not _SIGNUP_PATH_PATTERN.search(f"{split.path}?{meaningful}"):
            continue
        try:
            return policy.sanitize_candidate(resolved)
        except ValueError:
            continue
    return None


def submit_labels(html: str) -> tuple[str, ...]:
    """Visible submit-control labels on a registration form.

    The reviewed recipes carry an exact label ("Sign up in two minutes") because
    the browser policy authorizes one specific control rather than any clickable
    thing. Reading them off the live form keeps that narrowness while removing
    the requirement that a human transcribe it first.
    """

    found: list[str] = []
    for raw in (
        *(_TAG_PATTERN.sub(" ", body) for body in _BUTTON_PATTERN.findall(html)),
        *_SUBMIT_INPUT_PATTERN.findall(html),
    ):
        label = " ".join(html_unescape(raw).split())
        if not label or len(label) > _MAX_LABEL_CHARS:
            continue
        if not _SUBMIT_LABEL_PATTERN.search(label):
            continue
        if _FEDERATED_LABEL_PATTERN.search(label):
            continue
        if label not in found:
            found.append(label)
        if len(found) == _MAX_SUBMIT_LABELS:
            break
    return tuple(found)


def entry_path_prefix(signup_url: str) -> str:
    """The absolute path a plan may enter the signup flow under.

    The query string is dropped: ``entry_path_prefixes`` is a path vocabulary,
    and an app that routes registration through ``/signin?view=signup`` is still
    entering at ``/signin``.
    """

    path = urlsplit(signup_url).path or "/"
    return path if path.startswith("/") else f"/{path}"


async def research_signup_route(
    *,
    recipe: AppRecipe,
    fetcher_factory: FetcherFactory,
    extra_pages: Sequence[str] = (),
    on_progress: ProgressReporter = _noop_progress,
) -> SignupRouteFinding | None:
    """Find where ``recipe``'s app registers new accounts, from its own site.

    Returns ``None`` when no official page links to a registration route, which
    is a truthful "not found" rather than a guess. The caller keeps whatever
    behavior it had before research ran.

    The policy is built from ``recipe.browser.exact_hosts`` and nothing else, so
    a researched route is always inside an origin a reviewer already approved.
    """

    browser = recipe.browser
    if browser is None:
        return None

    on_progress("signup_research_started", detail=recipe.app_slug)
    # Two policies, because reading a page and trusting a URL are different acts.
    #
    # ``scan_policy`` covers the public pages the agent may READ: the reviewed
    # hosts plus the marketing origins they imply. Reading a company's own
    # homepage grants nothing — the fetcher's DNS and private-address checks
    # still run — and it is where registration links actually live.
    #
    # ``accept_policy`` is the reviewed hosts and nothing else. It decides which
    # URL may be handed to the browser, and it is the boundary that must not
    # move: a researched route is always a path inside an approved origin.
    pages = candidate_pages(recipe, extra=extra_pages)
    scan_hosts = [host for host in (urlsplit(page).hostname for page in pages) if host]
    scan_policy = OfficialURLPolicy(exact_hosts=(*browser.exact_hosts, *scan_hosts))
    accept_policy = OfficialURLPolicy(exact_hosts=browser.exact_hosts)
    fetcher = fetcher_factory(scan_policy)
    scanned: list[str] = []

    for page in pages:
        try:
            source_url, _content_type, body = await fetcher.fetch_source(
                page, max_bytes=PAGE_MAX_BYTES
            )
        except Exception:
            # An unreadable page is not an error: bot walls, redirects and
            # rate limits are ordinary on marketing sites. Try the next one.
            continue
        scanned.append(source_url)
        on_progress("signup_page_scanned", detail=source_url)
        found = signup_anchor(body, source_url, accept_policy)
        if found is None:
            continue
        on_progress("signup_route_found", detail=found)

        labels: tuple[str, ...] = ()
        try:
            _url, _type, form_body = await fetcher.fetch_source(found, max_bytes=PAGE_MAX_BYTES)
        except Exception:
            form_body = ""
        if form_body:
            scanned.append(found)
            labels = submit_labels(form_body)
        if not labels:
            # The form is client-rendered, so its control is not in the served
            # markup. The reviewed default is the label every registration form
            # in the catalog uses, and the browser policy still requires the
            # control to actually be present before it is clicked.
            labels = ("Sign up",)
        on_progress("signup_form_read", detail=found)

        return SignupRouteFinding(
            app_slug=recipe.app_slug,
            signup_url=found,
            entry_path_prefix=entry_path_prefix(found),
            submit_labels=labels,
            evidence_url=source_url,
            scanned_pages=tuple(scanned),
        )

    on_progress("signup_research_exhausted", detail=recipe.app_slug)
    return None


__all__ = [
    "PAGE_MAX_BYTES",
    "PROGRESS_SUMMARIES",
    "FetcherFactory",
    "ProgressReporter",
    "SignupRouteFinding",
    "candidate_pages",
    "entry_path_prefix",
    "research_signup_route",
    "signup_anchor",
    "submit_labels",
]
