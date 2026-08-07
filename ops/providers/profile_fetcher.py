"""Batch evidence fetching for provider profile research, without a known host.

THE BOOTSTRAP DEADLOCK this module exists to break: ``OfficialEvidenceFetcher``
needs an ``OfficialURLPolicy``; ``OfficialURLPolicy`` refuses to be built without
at least one verified official host; and the official host is precisely the fact
research is trying to discover. Every existing caller sidesteps this by reading a
host out of an already-reviewed P1 catalog row, which a brand-new provider does
not have. That is why no concrete profile fetcher existed outside ``tests/``.

The way out is that discovery adapters return candidate URLs from a search API
*without fetching them*. A URL is only a string until someone dereferences it, so
the registrable domain of every candidate can be read, counted, and voted on
before a single byte leaves the process. The election picks ONE registrable
domain, and that winner — not an operator's assumption — is what the policy is
built from.

Single-registrable-domain confinement is a SAFETY property, not a convenience.
Downstream, the browser types vaulted credentials into whatever host this profile
authorizes; a batch that fetched ``provider.com`` and ``provider-login.com``
together would let one look-alike page in the evidence set justify sending a
password to it. So there is deliberately no cross-domain mode, and an ambiguous
vote fails closed with no documents rather than guessing.
"""

from __future__ import annotations

import asyncio
import logging
from collections import Counter
from collections.abc import Sequence
from urllib.parse import urlsplit

import httpx

from ops.browser.host_policy import registrable_domain as resolve_registrable_domain
from ops.core.models import validate_https_url
from ops.research.operational_research import (
    MAX_EVIDENCE_DOCUMENTS,
    EvidenceDocument,
    HostResolver,
    OfficialEvidenceFetcher,
    OfficialURLPolicy,
)
from ops.you.candidates import canonicalize

LOGGER = logging.getLogger(__name__)

# A domain named by exactly one candidate is an assertion, not corroboration: a
# single search result can be an SEO squat, a mirror, or a typo-domain. Two
# independent candidates agreeing is the weakest evidence of ownership worth
# acting on, so this is the floor rather than a tunable default.
MINIMUM_DOMAIN_VOTES = 2

# Small on purpose. The cap bounds how many sockets one provider's research can
# hold open at once, and its real job is that a single slow host cannot stall the
# whole batch behind it.
MAX_CONCURRENT_FETCHES = 4

# Registrable domains that are SHARED BY UNRELATED TENANTS. Electing one of these
# would hand ``OfficialURLPolicy(exact_hosts=[d], wildcard_domains=[d])`` an entire
# hosting platform, so every other tenant on it — including one an attacker signed
# up for ten minutes ago — becomes a "verified official host" for this vendor. That
# is precisely the look-alike-host case single-registrable-domain confinement exists
# to prevent, so these can never win an election.
#
# Entries are matched against the value ``registrable_domain`` returns, which is two
# labels (or three under a known ccTLD suffix). A platform whose tenancy lives
# BELOW a registrable domain it shares with its owner — ``sites.google.com``,
# ``<tenant>.blob.core.windows.net`` — cannot be expressed at this granularity, so
# the nearest expressible parent is listed where denying it is acceptable and the
# rest are simply out of reach of this mechanism.
#
# The list is deliberately over-inclusive: a false positive costs one human review,
# a false negative silently widens credential-entry confinement to a whole platform.
MULTI_TENANT_SUFFIXES: frozenset[str] = frozenset(
    {
        # Static-site / docs hosting, one site per user or repository.
        "github.io",
        "githubusercontent.com",
        "gitlab.io",
        "bitbucket.io",
        "pages.dev",
        "r2.dev",
        "workers.dev",
        "trycloudflare.com",
        "vercel.app",
        "netlify.app",
        "netlify.com",
        "onrender.com",
        "fly.dev",
        "herokuapp.com",
        "railway.app",
        "koyeb.app",
        "deno.dev",
        "surge.sh",
        "glitch.me",
        "repl.co",
        "replit.app",
        "pythonanywhere.com",
        "readthedocs.io",
        "readthedocs.org",
        "rtfd.io",
        "sourceforge.net",
        # Cloud object storage / serverless app domains handed out per account.
        "amazonaws.com",
        "cloudfront.net",
        "amplifyapp.com",
        "elasticbeanstalk.com",
        "awsapps.com",
        "appspot.com",
        "web.app",
        "firebaseapp.com",
        "googleusercontent.com",
        "azurewebsites.net",
        "azureedge.net",
        "windows.net",
        "digitaloceanspaces.com",
        "ondigitalocean.app",
        # Code hosting: every account publishes pages under the same domain, so a
        # vendor's repo is not evidence that the vendor owns the domain. Denying
        # these means a vendor whose ONLY evidence is a repo needs a human — which
        # is correct, because a repo can be forked by anyone.
        "github.com",
        "gitlab.com",
        "bitbucket.org",
        # Package registries: per-publisher pages under one shared domain.
        "npmjs.com",
        "pypi.org",
        "crates.io",
        "packagist.org",
        "rubygems.org",
        # Documentation / knowledge-base / support SaaS, one tenant per subdomain.
        "gitbook.io",
        "gitbook.com",
        "readme.io",
        "readme.com",
        "mintlify.app",
        "stoplight.io",
        "apiary.io",
        "swaggerhub.com",
        "postman.co",
        "document360.io",
        "helpdocs.io",
        "helpjuice.com",
        "helpscoutdocs.com",
        "intercom.help",
        "zendesk.com",
        "freshdesk.com",
        "atlassian.net",
        "notion.site",
        "notion.so",
        "zohodesk.com",
        # Status pages.
        "statuspage.io",
        "status.io",
        "instatus.com",
        "betteruptime.com",
        # Site builders, blogging and community platforms.
        "wordpress.com",
        "blogspot.com",
        "wixsite.com",
        "squarespace.com",
        "weebly.com",
        "webflow.io",
        "carrd.co",
        "bubbleapps.io",
        "softr.app",
        "super.site",
        "framer.website",
        "hashnode.dev",
        "medium.com",
        "substack.com",
        "ghost.io",
        "tumblr.com",
        "dev.to",
        "circle.so",
        "discourse.group",
        "zulipchat.com",
        "groups.io",
        # Commerce storefronts.
        "myshopify.com",
        "mybigcommerce.com",
        "bigcartel.com",
        "hs-sites.com",
        "hubspotpagebuilder.com",
        # Identity / CRM tenancy: <tenant>.okta.com is not Okta's own front door.
        "okta.com",
        "auth0.com",
        "onelogin.com",
        "force.com",
        "myshopifypreview.com",
        # Tunnels and link shorteners: the domain says nothing about who is behind
        # it, and a shortener additionally hides the eventual destination.
        "ngrok.io",
        "ngrok.app",
        "ngrok-free.app",
        "loca.lt",
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "lnkd.in",
        "goo.gl",
        "rebrand.ly",
    }
)


def is_multi_tenant_domain(domain: str) -> bool:
    """Whether ``domain`` is a registrable domain shared by unrelated tenants.

    PRE:  ``domain`` is the output of ``registrable_domain`` (already casefolded
          and dot-stripped) or any hostname-shaped string.
    POST: ``True`` when the domain is, or sits under, a known multi-tenant suffix.

    The parent check exists because ``registrable_domain`` can return three labels
    under a ccTLD suffix (``example.co.uk``), so a listed platform operating a
    country domain still matches its own subtree rather than slipping past on
    label count.
    """

    candidate = (domain or "").strip().rstrip(".").casefold()
    if not candidate:
        return False
    if candidate in MULTI_TENANT_SUFFIXES:
        return True
    return any(candidate.endswith(f".{suffix}") for suffix in MULTI_TENANT_SUFFIXES)


def _vote_key(url: str) -> tuple[str, str]:
    """The destination identity a candidate votes for: (registrable domain, path).

    PRE:  ``url`` already passed ``validate_https_url``.
    POST: two URLs differing ONLY in query string, fragment, subdomain, host case
          or trailing slash produce the same key.

    ``ops.you.candidates.canonicalize`` cannot be used for this: it preserves the
    query string, so one destination reached through N tracking-parameter variants
    (``?utm_source=``, ``?ref=``, and any parameter no deny-list anticipated) counts
    as N independent pages and can manufacture a plurality by itself. Keying on the
    query-free destination costs a vote when a site genuinely addresses distinct
    pages by query alone; that direction is safe, because undercounting can only
    make the election fail closed.
    """

    split = urlsplit(url)
    domain = resolve_registrable_domain(split.hostname or "") or (split.hostname or "").casefold()
    path = split.path or "/"
    if len(path) > 1 and path.endswith("/"):
        path = path.rstrip("/") or "/"
    return (domain, path)


def elect_registrable_domain(
    urls: Sequence[str],
    *,
    minimum_votes: int = MINIMUM_DOMAIN_VOTES,
) -> str | None:
    """Elect the one registrable domain a candidate set agrees on, or ``None``.

    PRE:  ``urls`` are unfetched discovery candidates; ``minimum_votes >= 2``.
    POST: returns a registrable domain that (a) was named by at least
          ``minimum_votes`` distinct candidate DESTINATIONS, (b) STRICTLY outpolls
          every other domain, and (c) is not a known multi-tenant hosting suffix,
          or ``None``. A tie returns ``None``: two domains with equal support is
          exactly the look-alike case, and picking either one would be a coin flip
          that later authorizes a credential entry.

    A winner on ``MULTI_TENANT_SUFFIXES`` returns ``None`` and does NOT fall
    through to the runner-up. Promoting the runner-up would be inventing an answer:
    the candidates said the vendor lives on ``github.io``, and a vendor whose only
    evidence is on shared hosting genuinely cannot be confined by a
    registrable-domain policy — the domain it would be confined to belongs to the
    platform and to every other tenant on it. The honest outcome is no evidence and
    a human review, not the second-most-popular domain the search happened to
    return, which is typically an aggregator or a press mention.

    Votes are counted per destination — (registrable domain, path) — so ten deep
    links into one docs site each carry a vote (they are independent pages) while
    the same page reached through two adapters, two tracking-parameter variants or
    two host spellings carries one.
    """

    votes: Counter[str] = Counter()
    seen: set[tuple[str, str]] = set()
    for url in urls:
        try:
            validated = validate_https_url(url)
        except ValueError:
            continue  # a non-HTTPS or malformed candidate has no standing to vote
        key = _vote_key(validated)
        if key in seen:
            continue
        seen.add(key)
        domain = resolve_registrable_domain(urlsplit(validated).hostname or "")
        if domain is not None:
            votes[domain] += 1

    if not votes:
        return None
    ranked = votes.most_common(2)
    winner, count = ranked[0]
    if count < minimum_votes:
        LOGGER.info("profile domain election inconclusive: best %s had %d vote(s)", winner, count)
        return None
    if len(ranked) > 1 and ranked[1][1] == count:
        LOGGER.info(
            "profile domain election inconclusive: %s and %s tied at %d",
            winner,
            ranked[1][0],
            count,
        )
        return None
    if is_multi_tenant_domain(winner):
        # Logged at WARNING because this is a research run that CANNOT be completed
        # safely, not merely one that found nothing: the vendor is reachable, its
        # pages are just indistinguishable from its neighbours' at domain level.
        LOGGER.warning(
            "profile domain election refused: %s is multi-tenant hosting; needs human review",
            winner,
        )
        return None
    return winner


class DomainElectedEvidenceFetcher:
    """A ``ProfileEvidenceFetcher`` that derives its own host allowlist.

    Satisfies ``ops.providers.profile_builder.ProfileEvidenceFetcher`` — i.e. the
    verbatim ``EvidenceContentFetcherLike.fetch_many`` signature — so the profile
    builder consumes it with no wrapper, and no wrapper means no place to lose a
    redirect limit or a size cap.

    It owns none of the transport hardening. Size caps, redirect confinement,
    content-type checks, DNS-level SSRF rejection and sensitive-query stripping
    all stay inside ``OfficialEvidenceFetcher``/``OfficialURLPolicy``, which are
    already reviewed. The only thing added here is the answer to "which host is
    official?", computed before anything is dereferenced.

    Not reusable across providers concurrently: ``elected_domain`` records the
    most recent batch, so one instance serves one provider's research at a time.
    """

    def __init__(
        self,
        client: httpx.AsyncClient,
        *,
        resolver: HostResolver | None = None,
        minimum_votes: int = MINIMUM_DOMAIN_VOTES,
        max_documents: int = MAX_EVIDENCE_DOCUMENTS,
        concurrency: int = MAX_CONCURRENT_FETCHES,
    ) -> None:
        """PRE: ``minimum_votes >= MINIMUM_DOMAIN_VOTES``; ``1 <= concurrency <=
        MAX_CONCURRENT_FETCHES``; ``1 <= max_documents <= MAX_EVIDENCE_DOCUMENTS``.

        The bounds are rejected loudly instead of clamped. Silently raising a
        caller's ``minimum_votes=1`` to 2 would hide that they asked for a
        single-source domain election, and silently lowering it would hand them a
        weaker guarantee than the one they configured.
        """

        if minimum_votes < MINIMUM_DOMAIN_VOTES:
            raise ValueError("a domain election needs at least two corroborating candidates")
        if not 1 <= concurrency <= MAX_CONCURRENT_FETCHES:
            raise ValueError("evidence fetch concurrency must be between 1 and 4")
        if not 1 <= max_documents <= MAX_EVIDENCE_DOCUMENTS:
            raise ValueError("evidence document budget must be between 1 and 8")
        self._client = client
        self._resolver = resolver
        self._minimum_votes = minimum_votes
        self._max_documents = max_documents
        self._concurrency = concurrency
        # Diagnostic only: the winner of the most recent ``fetch_many``, kept so a
        # run can be explained after the fact. NOTHING outside this class reads it
        # — the profile builder never consults it, and confinement is carried by
        # the ``OfficialURLPolicy`` built below, not by this attribute. It is
        # therefore not a channel one provider's domain can leak through, but it is
        # also not a value any caller may rely on.
        self.elected_domain: str | None = None

    async def fetch_many(self, urls: Sequence[str]) -> tuple[EvidenceDocument, ...]:
        """Elect one domain, then fetch only the candidates that live on it.

        PRE:  every url is https (non-HTTPS entries are dropped, not coerced).
        POST: ``len(result) <= min(len(urls), max_documents)``; every returned
              document's ``source_url`` resolves to ``self.elected_domain``;
              every ``relevant_text`` is non-empty and within
              ``MAX_EXCERPT_CHARACTERS`` (enforced by ``EvidenceDocument``); a URL
              that could not be fetched is OMITTED rather than returned empty or
              synthesized, because a fabricated excerpt would corroborate a claim
              nothing supports. Returns ``()`` when the election is inconclusive.

        Candidate order is preserved so the budget spends on the highest-ranked
        results the discovery adapters returned, not on whichever host replied
        first.
        """

        self.elected_domain = None
        domain = elect_registrable_domain(urls, minimum_votes=self._minimum_votes)
        if domain is None:
            return ()
        self.elected_domain = domain

        # exact_hosts admits the bare root; wildcard_domains admits subdomains
        # only (the reviewed browser semantics, where a ``*.parent`` pattern does
        # NOT cover ``parent``). Together they are exactly one registrable
        # domain's tree and nothing else.
        policy = OfficialURLPolicy(
            exact_hosts=[domain],
            wildcard_domains=[domain],
            resolver=self._resolver,
        )
        fetcher = OfficialEvidenceFetcher(self._client, policy)

        confined = self._confine(urls, domain=domain)
        if not confined:
            return ()

        semaphore = asyncio.Semaphore(self._concurrency)

        async def _fetch(url: str) -> EvidenceDocument | None:
            async with semaphore:
                try:
                    return await fetcher.fetch(url)
                except (httpx.HTTPError, OSError, ValueError) as exc:
                    # One unreachable page is a smaller evidence set, never a
                    # failed research run: partial evidence is still evidence,
                    # and the builder decides whether what survived corroborates.
                    LOGGER.info(
                        "profile evidence fetch dropped a candidate: %s", type(exc).__name__
                    )
                    return None

        fetched = await asyncio.gather(*(_fetch(url) for url in confined))
        return tuple(
            document
            for document in fetched
            # An empty excerpt cannot ground a claim, so it is not evidence and
            # must not consume a slot in the corroboration count.
            if document is not None and document.relevant_text.strip()
        )

    def _confine(self, urls: Sequence[str], *, domain: str) -> tuple[str, ...]:
        """The in-order, deduplicated, budgeted candidates on the elected domain.

        POST: length <= ``self._max_documents``; every entry's registrable domain
              equals ``domain``. Candidates on any other domain are DROPPED here
              rather than handed to the policy to reject, so the losing domains
              are never even resolved — a look-alike host learns nothing about us.
        """

        confined: list[str] = []
        seen: set[str] = set()
        for url in urls:
            try:
                validated = validate_https_url(url)
            except ValueError:
                continue
            key = canonicalize(validated)
            if key in seen:
                continue
            if resolve_registrable_domain(urlsplit(validated).hostname or "") != domain:
                continue
            seen.add(key)
            confined.append(validated)
            if len(confined) == self._max_documents:
                break
        return tuple(confined)


__all__ = [
    "MAX_CONCURRENT_FETCHES",
    "MINIMUM_DOMAIN_VOTES",
    "MULTI_TENANT_SUFFIXES",
    "DomainElectedEvidenceFetcher",
    "elect_registrable_domain",
    "is_multi_tenant_domain",
]
