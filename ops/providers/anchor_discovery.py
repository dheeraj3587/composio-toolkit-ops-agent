"""Homepage-anchor discovery: the provider profile's primary evidence source.

Profile research corroborates a field only when two distinct documents say the
same thing, and it can only read documents that some discovery adapter proposed.
Today the only registered adapter is a search vendor that is off by default and
needs a key, so corroboration is arithmetically impossible on a stock deployment
and every managed-auth app in the catalog carries an empty ``urls`` object.

This module closes that gap without a vendor. Every SaaS homepage links "Log in",
"Sign up", "Get started" and "API keys" in its own header or footer, and those
anchors are both cheaper and more accurate than a search result: they are the
provider stating, on its own site, where its own gates are. Harvesting them needs
no API key, no quota and no third party.

Three properties keep that safe, and none of them live here alone:

* **Nothing returned is believed.** ``discover`` implements
  :class:`ops.providers.profile_builder.ProfileDiscovery`, whose contract is that
  a candidate is only a suggestion. The builder still fetches it, extracts claims
  from it, requires a second document to agree, and confines the survivors to one
  registrable domain.
* **Reading a page grants nothing.** The fetch goes through
  ``OfficialEvidenceFetcher``, which keeps its host allowlist, DNS/SSRF checks,
  redirect limit, size limit and content-type limit. A page the operator's policy
  does not admit is never requested, so this adapter is inert until an operator
  binds a fetcher for the provider.
* **An anchor cannot move the domain.** Every harvested href is resolved against
  the page it was read from and dropped unless its registrable domain matches
  that page's. A third-party widget, an ad, or a federated-login button on the
  provider's homepage therefore cannot introduce a new origin.

Failure is a value, never an exception: a bot wall, a redirect loop, a rate limit
or a policy rejection all yield ``()``, because discovery is advisory and the run
must degrade to the remaining adapters rather than fail.
"""

from __future__ import annotations

import logging
from collections.abc import Sequence
from html.parser import HTMLParser
from typing import TYPE_CHECKING, Final, Protocol
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

import httpx

from ops.browser.host_policy import registrable_domain as resolve_registrable_domain
from ops.research.operational_research import OfficialEvidenceFetcher, OfficialURLPolicy

LOGGER = logging.getLogger("composio_ops.provider_anchor_discovery")

#: Read once and discarded. A marketing homepage dwarfs the documentation page
#: the evidence fetcher's 256 KiB default is sized for, and nothing read here
#: becomes durable evidence, so this is a transfer budget, not a safety boundary.
PAGE_MAX_BYTES: Final = 4 * 1024 * 1024

#: Wall clock for one page read. Discovery is advisory and runs before anything
#: can be spent, so a marketing site that hangs must cost the run a bounded pause
#: and nothing more; the timeout expiring is just another unreadable page.
PAGE_TIMEOUT_SECONDS: Final = 15.0

#: How many pages one ``discover`` call may read. The homepage and its login page
#: carry essentially every gate link a provider has; a third fetch buys little and
#: costs a run's latency on sites that hang.
MAX_PAGES: Final = 3

#: Anchors parsed per page. A large marketing site can serve thousands of links
#: (an "all integrations" grid is the usual culprit); ranking is unaffected by the
#: tail, and the bound keeps a hostile page from turning into unbounded work.
MAX_ANCHORS_PER_PAGE: Final = 2_000

#: Candidates returned. Matches ``operational_research.MAX_EVIDENCE_DOCUMENTS``,
#: which is where the builder truncates anyway — returning more would only push
#: the other adapters' candidates out of the fetch window.
MAX_RESULTS: Final = 8

#: Query parameters stripped before a candidate is returned. Campaign tags make
#: one destination look like several distinct URLs, which would spend the fetch
#: budget re-reading the same page and inflate the corroboration count with
#: duplicates of a single document.
_TRACKING_PARAM_PREFIXES: Final = ("utm_", "ref_", "mkt_", "gclid", "fbclid")


class SourceFetcherLike(Protocol):
    """The raw-markup half of ``ops.research.operational_research.OfficialEvidenceFetcher``.

    Restated here rather than imported so this module depends on a two-line shape
    instead of a research-stack class, and so a test double is one object with one
    method. ``_reused_port_is_verbatim`` below is the static proof it did not
    drift from the class it describes.
    """

    async def fetch_source(self, url: str, *, max_bytes: int | None = None) -> tuple[str, str, str]:
        """Return ``(final_url, content_type, body)`` for a policy-admitted page.

        PRE:  ``url`` is absolute.
        POST: the body is the served markup, bounded by ``max_bytes``, fetched
              under the implementation's host allowlist and redirect controls.
              A URL the policy refuses, a transport error, an oversized body or a
              non-text content type raises.
        """


if TYPE_CHECKING:

    def _reused_port_is_verbatim(fetcher: OfficialEvidenceFetcher) -> SourceFetcherLike:
        """Type checked, never executed: the real fetcher satisfies the local port.

        Any drift — a renamed keyword, a changed tuple shape — fails type checking
        here instead of at runtime inside a research run.
        """

        return fetcher


# --- intent ranking -------------------------------------------------------

# Ranked by what the profile is FOR, not by how common the phrase is. The login
# gate is the field every later phase needs first (it is what the browser is
# pointed at), registration is the field that unblocks autonomous onboarding, and
# the credential console is where an API key is actually minted. Documentation
# ranks last because a docs page corroborates a domain but names no gate.
#
# Matched against the anchor's own visible text, lowercased and whitespace
# collapsed. Text-only matching is loose on its own — "Get started" points at a
# tutorial as often as a signup form — which is exactly why nothing here is
# authoritative: this orders candidates, it does not classify them.
_INTENT_TIERS: Final[tuple[tuple[str, ...], ...]] = (
    # Tier 0 — the login gate.
    ("log in", "login", "sign in", "signin", "log-in", "sign-in", "member login"),
    # Tier 1 — registration.
    (
        "sign up",
        "signup",
        "sign-up",
        "get started",
        "register",
        "create account",
        "create an account",
        "create a free account",
        "start free",
        "try free",
        "free trial",
        "join",
    ),
    # Tier 2 — the credential console and developer surface.
    (
        "api key",
        "api keys",
        "api token",
        "access token",
        "personal access token",
        "developer portal",
        "developers",
        "developer",
        "console",
        "dashboard",
    ),
    # Tier 3 — documentation.
    ("api reference", "api docs", "documentation", "docs", "developer docs", "reference"),
)


def _intent_rank(text: str) -> int | None:
    """The tier ``text`` expresses, or ``None`` when it expresses no intent.

    PRE:  ``text`` is already lowercased with whitespace collapsed.
    POST: the result indexes ``_INTENT_TIERS``; a lower number ranks earlier.

    Substring rather than equality: real headers wrap the phrase in a call to
    action ("Log in to your account"). The bound on looseness is the length
    check — a whole paragraph that happens to contain "docs" is not a gate link,
    and admitting it would let body copy outrank a header button.
    """

    if not text or len(text) > 60:
        return None
    for rank, phrases in enumerate(_INTENT_TIERS):
        if any(phrase in text for phrase in phrases):
            return rank
    return None


# --- anchor harvesting ----------------------------------------------------


class _AnchorParser(HTMLParser):
    """Collect ``(href, visible text)`` pairs, bounded, in document order.

    A regex over ``<a href=...>`` finds the target but not the text, and the text
    is what carries the intent. A parser also survives the markup real homepages
    ship: nested ``<span>``/``<svg>`` inside the anchor, attributes in any order,
    and unclosed tags.
    """

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.anchors: list[tuple[str, str]] = []
        self._href: str | None = None
        self._label: str = ""
        self._parts: list[str] = []
        self._depth: int = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag != "a":
            return
        if self._href is not None:
            # An unclosed anchor nested inside another. Emit what we have rather
            # than merging two links into one mislabelled candidate.
            self._emit()
        attributes = dict(attrs)
        href = attributes.get("href")
        if not href:
            return
        if len(self.anchors) >= MAX_ANCHORS_PER_PAGE:
            return
        self._href = href
        self._parts = []
        self._depth = 1
        # Icon-only links — a key glyph for "API keys", an avatar for "Log in" —
        # have no text node at all. The accessible name is the same intent stated
        # for a screen reader, so it is used when there is no visible text.
        self._label = (attributes.get("aria-label") or attributes.get("title") or "").strip()

    def handle_endtag(self, tag: str) -> None:
        if tag != "a" or self._href is None:
            return
        self._depth -= 1
        if self._depth <= 0:
            self._emit()

    def handle_data(self, data: str) -> None:
        if self._href is not None:
            self._parts.append(data)

    def _emit(self) -> None:
        href, self._href = self._href, None
        if href is None:
            return
        text = " ".join("".join(self._parts).split()) or self._label
        self.anchors.append((href, " ".join(text.split()).casefold()))
        self._parts = []
        self._label = ""
        self._depth = 0

    def close(self) -> None:
        super().close()
        # A truncated body (the fetcher stops at ``max_bytes``) leaves the last
        # anchor unterminated. Its href is still a real link, so it is kept.
        self._emit()


def _normalized_candidate(href: str, *, page_url: str, page_domain: str) -> str | None:
    """Resolve one href against its page, or ``None`` if it may not be proposed.

    PRE:  ``page_domain`` is the registrable domain of ``page_url``.
    POST: the result is an absolute https URL with no userinfo, no fragment, no
          tracking parameters, and the same registrable domain as ``page_url``.

    Each rejection is a distinct hazard, not a style preference:

    * a non-https scheme covers ``mailto:``, ``javascript:`` and plain http —
      none is a fetchable evidence document, and http would be a downgrade;
    * userinfo (the ``user:pw@`` prefix before a host) is how a URL is made to READ as one
      host and RESOLVE to another, which is the whole point of confining
      research to one domain;
    * a different registrable domain is a third-party link — a status page, a
      federated identity provider, a social profile — and admitting one would let
      a page the provider merely links to vote on the provider's own domain.

    A malformed href is a rejection, not an error. ``urljoin``, ``urlsplit`` and
    the ``username``/``password``/``hostname``/``port`` properties all parse the
    netloc lazily and all raise ``ValueError`` on input the standard library
    cannot make sense of — ``https://x.com:99999/`` and ``https://x.com:abc/``
    (port out of range / not a number) and ``https://[::1/`` (unterminated IPv6
    literal) are the reachable cases. Every one of those arrives from page HTML
    nobody in this process wrote, so the whole parse is guarded as one unit:
    ``discover`` promises never to raise, and a single hostile anchor must cost
    itself and nothing else.
    """

    try:
        resolved = urljoin(page_url, href.strip())
        split = urlsplit(resolved)
        if split.scheme != "https" or split.username or split.password:
            return None
        host = split.hostname
        if not host:
            return None
        port = f":{split.port}" if split.port else ""
    except ValueError:
        LOGGER.debug("anchor discovery dropped an unparseable href on %s", page_url)
        return None
    if resolve_registrable_domain(host) != page_domain:
        return None
    query = urlencode(
        [
            (name, value)
            for name, value in parse_qsl(split.query, keep_blank_values=True)
            if not name.casefold().startswith(_TRACKING_PARAM_PREFIXES)
        ]
    )
    # Rebuilt from the parsed parts, and the fragment is dropped: a fragment
    # names a position inside a document the fetcher would return in full, so
    # keeping it only manufactures duplicate candidates for one page.
    return urlunsplit(("https", f"{host.casefold()}{port}", split.path or "/", query, ""))


class HomepageAnchorDiscovery:
    """Propose a provider's gate URLs by reading the anchors on its own pages.

    Implements :class:`ops.providers.profile_builder.ProfileDiscovery`. It is
    registered at the composition boundary like any other adapter; it is NOT
    self-registering, because the fetcher it needs is built per provider from
    that provider's admitted hosts.

    ``hint_url`` is the same operator hint ``build_profile`` takes — one URL
    somewhere on the provider's site. It is the seed, not the answer: the site
    root implied by it is read too, since an operator usually pastes a docs or
    console URL and the gate links live on the marketing page above it.
    """

    #: Recorded on the evidence as the adapter that proposed the URL, satisfying
    #: ``NamedProfileDiscovery`` so registration needs no wrapper.
    name: Final[str] = "homepage_anchors"

    def __init__(
        self,
        fetcher: SourceFetcherLike,
        *,
        hint_url: str | None = None,
        extra_pages: Sequence[str] = (),
        max_results: int = MAX_RESULTS,
    ) -> None:
        if max_results < 1:
            raise ValueError("anchor discovery must be allowed to return at least one candidate")
        self._fetcher = fetcher
        self._hint_url = (hint_url or "").strip() or None
        self._extra_pages = tuple(page.strip() for page in extra_pages if page.strip())
        self._max_results = max_results

    async def discover(self, *, app_name: str) -> tuple[str, ...]:
        """Return candidate https URLs harvested from the provider's own anchors.

        PRE:  ``app_name`` is non-empty.
        POST: every value is an absolute https URL carrying no userinfo, sharing
              a registrable domain with the page it was read from, deduplicated,
              ordered by anchor-text intent (login, then registration, then
              credential console, then documentation), and no longer than
              ``max_results``. Returns ``()`` — never raises — when no page could
              be read or no anchor expressed an intent.
        """

        if not app_name.strip():
            # Refused rather than degraded: an unnamed provider means the caller
            # lost track of what it is researching, and returning () here would
            # hide that as "the site linked nothing".
            raise ValueError("anchor discovery requires the provider being researched")

        pages = self._pages()
        if not pages:
            # Says so rather than looking like a site that links nothing. An
            # unseeded harvester is an operator-visible condition — the run
            # carried no hint URL — and the durable
            # ``adapter_returned_nothing`` fact the builder records for it names
            # the adapter but not the reason.
            LOGGER.info("anchor discovery has no seed page for %s: no hint url", app_name)
            return ()

        ranked: dict[str, int] = {}
        for page in pages:
            for url, rank in self._harvest(await self._read(page)):
                # First occurrence wins on ties, and the strongest intent wins
                # overall: one destination is often linked twice ("Log in" in the
                # header, "Sign in" in the footer), and the better label is the
                # one that should decide where it sits in the fetch order.
                if rank < ranked.get(url, len(_INTENT_TIERS)):
                    ranked[url] = rank

        # ``sorted`` is stable, so within one tier the document order of the page
        # survives — a header button outranks the same intent repeated in a footer.
        ordered = sorted(ranked, key=lambda url: ranked[url])
        return tuple(ordered[: self._max_results])

    def _pages(self) -> tuple[str, ...]:
        """The pages worth reading, best-first and bounded.

        The hint comes first because it is the one URL a human vouched for. Its
        site root follows: gate links live in a marketing header, and a hint that
        points at ``docs.provider.com/guide`` would otherwise never reach one.
        """

        seeds = [self._hint_url, *self._extra_pages]
        pages: list[str] = []
        for seed in seeds:
            if not seed:
                continue
            pages.append(seed)
            root = _site_root(seed)
            if root is not None:
                pages.append(root)
        # ``dict.fromkeys`` rather than a set: order is the ranking's tiebreak.
        return tuple(dict.fromkeys(pages))[:MAX_PAGES]

    async def _read(self, page: str) -> tuple[str, str] | None:
        """Fetch one page as ``(final_url, body)``, or ``None`` if unreadable.

        Every failure is swallowed at this boundary. Bot walls, rate limits,
        redirect loops and hosts the fetcher's policy refuses are all ORDINARY on
        marketing sites, and none of them is a reason to fail a research run that
        still has other adapters and other pages to try.
        """

        try:
            source_url, content_type, body = await self._fetcher.fetch_source(
                page, max_bytes=PAGE_MAX_BYTES
            )
        except Exception:
            LOGGER.debug("anchor discovery could not read %s", page, exc_info=True)
            return None
        if "html" not in content_type.casefold():
            # JSON and plain text carry no anchors. Returning early keeps the
            # parser from inventing links out of text that merely looks like markup.
            return None
        return source_url, body

    def _harvest(self, fetched: tuple[str, str] | None) -> tuple[tuple[str, int], ...]:
        """Turn one fetched page into ranked, domain-confined candidate URLs.

        Resolution is against the page's FINAL url, not the URL requested: a
        provider that redirects ``provider.com`` to ``www.provider.com`` would
        otherwise have every relative href resolved against the wrong host and
        then dropped by the domain check.
        """

        if fetched is None:
            return ()
        page_url, body = fetched
        try:
            page_host = urlsplit(page_url).hostname
        except ValueError:
            # The fetcher sanitizes the final URL it reports, so this is not the
            # expected path; it is guarded anyway because a page whose own URL
            # cannot be parsed must cost this page, not the run.
            LOGGER.debug("anchor discovery could not parse the final url of a fetched page")
            return ()
        page_domain = resolve_registrable_domain(page_host) if page_host else None
        if page_domain is None:
            return ()
        parser = _AnchorParser()
        try:
            parser.feed(body)
            parser.close()
        except Exception:
            # ``HTMLParser`` is tolerant, but the page is attacker-shaped input;
            # a parse that dies keeps whatever anchors it already collected.
            LOGGER.debug("anchor discovery could not parse %s", page_url, exc_info=True)
        found: list[tuple[str, int]] = []
        for href, text in parser.anchors:
            rank = _intent_rank(text)
            if rank is None:
                continue
            try:
                url = _normalized_candidate(href, page_url=page_url, page_domain=page_domain)
            except Exception:  # noqa: BLE001 - one bad anchor drops itself, never the batch
                # ``_normalized_candidate`` already turns every parse failure it
                # knows about into ``None``. This is the outer bound on the ones it
                # does not: the hrefs are attacker-shaped, the domain resolver is
                # someone else's code, and ``discover`` promises a value.
                LOGGER.debug("anchor discovery dropped an anchor on %s", page_url, exc_info=True)
                continue
            if url is None or url == page_url:
                continue
            found.append((url, rank))
        return tuple(found)


def _site_root(url: str) -> str | None:
    """The scheme-and-host root of ``url``, or ``None`` when it has no https host.

    Deliberately NOT the registrable domain: dropping ``docs.`` from a host would
    invent an origin the provider may not serve, and inventing origins is how
    research reaches somewhere nobody approved. The root of the host we were
    given is a page that host demonstrably has.

    Guarded for the same reason ``_normalized_candidate`` is: this runs on the
    operator hint, and a hint carrying a bad port or an unterminated IPv6 literal
    would otherwise raise out of ``_pages`` and through ``discover``.
    """

    try:
        split = urlsplit(url.strip())
        if split.scheme != "https" or split.username or split.password or not split.hostname:
            return None
        port = f":{split.port}" if split.port else ""
        host = split.hostname.casefold()
    except ValueError:
        LOGGER.debug("anchor discovery could not derive a site root from a seed url")
        return None
    return urlunsplit(("https", f"{host}{port}", "/", "", ""))


# --- self-scoped fetching -------------------------------------------------


class SelfScopedSourceFetcher:
    """A :class:`SourceFetcherLike` confined to the site of the page it is given.

    ``OfficialEvidenceFetcher`` needs an ``OfficialURLPolicy``, and a policy needs
    a host allowlist. Profile research has none to give: the phase exists because
    the provider's hosts are unknown, which is why the evidence fetcher one layer
    later (``DomainElectedEvidenceFetcher``) builds its policy only AFTER electing
    a domain from candidates. Anchor harvesting runs before there are candidates,
    so each read is scoped to the registrable domain of the seed URL it was handed
    — a page someone already vouched for — and to nothing else.

    That grant is narrow on purpose:

    * one seed admits one registrable domain, so a redirect or an anchor cannot
      walk the fetch onto a host the seed did not already imply;
    * every transport bound stays where it was reviewed. The DNS/SSRF rejection,
      the redirect ceiling, the size cap, the content-type check and the query
      sanitisation are all ``OfficialEvidenceFetcher``/``OfficialURLPolicy``
      behaviour, reached verbatim. Nothing is reimplemented here, so there is no
      place for one of them to be forgotten;
    * nothing opens a socket until ``fetch_source`` is awaited. Constructing this
      object — which is what adapter registration does — performs no I/O, so
      importing the module and composing the run root stay inert.

    The client lives for one call. A ``discover`` pass reads at most ``MAX_PAGES``
    pages, so pooling would buy two connection reuses at the price of a
    process-lifetime socket owned by a module with no lifecycle to close it on.
    """

    def __init__(self, *, timeout_seconds: float = PAGE_TIMEOUT_SECONDS) -> None:
        if timeout_seconds <= 0:
            raise ValueError("anchor discovery needs a positive page timeout")
        self._timeout_seconds = timeout_seconds

    async def fetch_source(self, url: str, *, max_bytes: int | None = None) -> tuple[str, str, str]:
        """Return ``(final_url, content_type, body)`` for ``url``, scoped to its own site.

        PRE:  ``url`` is an absolute https URL.
        POST: the response was served by ``url``'s own registrable domain under
              every bound ``OfficialEvidenceFetcher`` enforces, and its body is
              capped by ``max_bytes``.

        Raises on anything else — an unparseable URL, a host the policy refuses,
        a redirect off the seed's domain, an oversized or non-text body, or a
        transport error. ``HomepageAnchorDiscovery._read`` turns every one of
        those into "this page was unreadable", which is the contract that keeps
        ``discover`` returning a value.
        """

        host = urlsplit(url).hostname
        if not host:
            raise ValueError("anchor discovery cannot read a url with no host")
        # Fall back to the host itself when the suffix list does not recognise the
        # TLD: an unrecognised suffix must narrow the grant to exactly that host,
        # never widen it to a guessed parent.
        scope = resolve_registrable_domain(host) or host
        policy = OfficialURLPolicy((scope,))
        async with httpx.AsyncClient(timeout=self._timeout_seconds) as client:
            return await OfficialEvidenceFetcher(client, policy).fetch_source(
                url, max_bytes=max_bytes
            )


__all__ = [
    "MAX_PAGES",
    "MAX_RESULTS",
    "PAGE_MAX_BYTES",
    "PAGE_TIMEOUT_SECONDS",
    "HomepageAnchorDiscovery",
    "SelfScopedSourceFetcher",
    "SourceFetcherLike",
]
