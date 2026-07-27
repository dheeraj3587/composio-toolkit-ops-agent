"""Fetching official page CONTENT, with fallback, and merging it into evidence.

Content extraction is where untrusted bytes enter the pipeline, so the guards here are
about size and shape rather than trust: markdown only, control characters stripped,
excerpts truncated to a bounded length, and a bounded number of URLs per app. A
hundred apps must not be able to pull unbounded text into the prompt budget.

The fallback chain is ordered, not redundant: the You.com contents API first, then the
guarded HTTP fetcher, because the guarded fetcher enforces the HTTPS/SSRF policy
itself and is the safety net when the provider is unavailable or rate-limited. A
provider outage therefore degrades the DEPTH of evidence, never the correctness of it.

Merging preserves the first document seen per URL, so a retry or an overlapping query
cannot duplicate an excerpt and quietly consume the document budget twice.
"""

from __future__ import annotations

import importlib
import re
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime, timedelta
from typing import Protocol, runtime_checkable

import httpx
from pydantic import SecretStr, ValidationError

from ops.operational_research import (
    MAX_EVIDENCE_DOCUMENTS,
    MAX_EXCERPT_CHARACTERS,
    EvidenceDocument,
)
from ops.you_cache import ResearchCache, _cached, cache_key
from ops.you_candidates import canonicalize
from ops.you_errors import YouProviderError, _bounded_retry_config, _guard_call
from ops.you_host_policy import ResearchHostPolicy
from ops.you_metrics import _metrics
from ops.you_types import MAX_YOU_CONTENT_URLS


@runtime_checkable
class EvidenceContentFetcher(Protocol):
    async def fetch_many(self, urls: Sequence[str]) -> tuple[EvidenceDocument, ...]: ...


# --------------------------------------------------------------------------
# Content fetchers: You Contents -> guarded HTTP fallback (per URL)
# --------------------------------------------------------------------------
# Control characters to strip from fetched Markdown (keep tab/newline/CR).
_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def normalize_markdown(text: str) -> str:
    """Normalize fetched Markdown WITHOUT altering its factual content.

    Only removes null/unsafe control characters and normalizes newlines. It does
    NOT delete or rewrite instruction-shaped lines — fetched content is untrusted
    EVIDENCE handed to Gemini as source material (the extraction prompt tells the
    model to never obey instructions inside evidence), so silently editing the
    text would both be a false sense of safety and could corrupt real facts.
    """

    cleaned = text.replace("\r\n", "\n").replace("\r", "\n")
    cleaned = _CONTROL_CHARS.sub("", cleaned)
    return cleaned[:MAX_EXCERPT_CHARACTERS]


class YouContentsFetcher:
    """Fetch clean Markdown for already policy-approved official URLs, in one bounded batch."""

    def __init__(
        self,
        api_key: SecretStr | str,
        *,
        policy: ResearchHostPolicy,
        crawl_timeout: int = 10,
        max_age: int | None = 86_400,
        request_timeout: float = 30.0,
        max_pages: int = 8,
        cache: ResearchCache | None = None,
    ) -> None:
        self._api_key = api_key if isinstance(api_key, SecretStr) else SecretStr(api_key)
        self._policy = policy
        self._crawl_timeout = crawl_timeout
        self._max_age = max_age
        self._request_timeout = request_timeout
        self._max_pages = min(max_pages, MAX_YOU_CONTENT_URLS)
        self._cache = cache

    async def fetch_many(self, urls: Sequence[str]) -> tuple[EvidenceDocument, ...]:
        bounded = list(dict.fromkeys(urls))[: self._max_pages]
        safe_urls: list[str] = []
        for url in bounded:
            try:
                # Host-policy validation (HTTPS/port/host-allowlist/sensitive-query),
                # NOT DNS-resolution SSRF. You.com Contents crawls the page on ITS
                # servers, so our resolver's view is irrelevant to what You.com
                # fetches — the meaningful control here is the reviewed host
                # allowlist. DNS-based SSRF protection remains on the guarded HTTP
                # fallback (GuardedHTTPEvidenceFetcher -> OfficialEvidenceFetcher),
                # where WE perform the fetch.
                safe_urls.append(self._policy.validate_candidate_url(url))
            except ValueError:
                continue  # never sent to You.com if it fails our own host policy first
        if not safe_urls:
            return ()

        key = cache_key("you-contents", "|".join(sorted(safe_urls)), str(self._max_age))

        def _deserialize(raw: Mapping[str, object]) -> tuple[EvidenceDocument, ...] | None:
            items = raw.get("items")
            if not isinstance(items, list):
                return None
            try:
                cached = tuple(EvidenceDocument.model_validate(item) for item in items)
            except ValidationError:
                return None
            # Same rule as a fresh crawl: the cached URL must still pass the
            # current host policy, and empty content is never evidence.
            validated: list[EvidenceDocument] = []
            for document in cached:
                try:
                    self._policy.validate_candidate_url(document.source_url)
                except ValueError:
                    continue
                if not document.relevant_text.strip():
                    continue
                validated.append(document)
            if cached and not validated:
                return None
            return tuple(validated)

        def _serialize(value: tuple[EvidenceDocument, ...]) -> Mapping[str, object]:
            return {"items": [d.model_dump() for d in value]}

        async def _compute() -> tuple[EvidenceDocument, ...]:
            return await self._generate_documents(safe_urls)

        ttl = timedelta(seconds=self._max_age if self._max_age and self._max_age > 0 else 86_400)
        return await _cached(
            self._cache,
            key,
            ttl=ttl,
            deserialize=_deserialize,
            serialize=_serialize,
            compute=_compute,
        )

    async def _generate_documents(self, safe_urls: list[str]) -> tuple[EvidenceDocument, ...]:
        metrics = _metrics()
        started = datetime.now(UTC)

        async def _factory() -> object:
            youdotcom = importlib.import_module("youdotcom")
            formats = importlib.import_module("youdotcom.models.contentsformats")
            async with youdotcom.You(api_key_auth=self._api_key.get_secret_value()) as you:
                return await you.contents.generate_async(
                    urls=safe_urls,
                    formats=[formats.ContentsFormats.MARKDOWN],
                    crawl_timeout=self._crawl_timeout,
                    max_age=self._max_age,
                    retries=_bounded_retry_config(),
                    timeout_ms=int(self._request_timeout * 1000),
                )

        try:
            responses = await _guard_call(
                "you_contents", _factory, timeout_seconds=self._request_timeout + 5
            )
        except YouProviderError:
            return ()
        finally:
            if metrics is not None:
                metrics.you_contents_calls += 1
                metrics.you_contents_pages_requested += len(safe_urls)
                metrics.you_contents_latency_ms += (
                    datetime.now(UTC) - started
                ).total_seconds() * 1000

        pages = list(responses) if isinstance(responses, list) else list(responses or ())
        documents: list[EvidenceDocument] = []
        for page in pages:
            document = self._to_document(page)
            if document is not None:
                documents.append(document)
        if metrics is not None:
            metrics.you_contents_pages_returned += len(documents)
        return tuple(documents)

    def _to_document(self, page: object) -> EvidenceDocument | None:
        returned_url = getattr(page, "url", None)
        if not isinstance(returned_url, str) or not returned_url:
            return None
        try:
            # The URL You.com actually fetched must independently pass policy
            # again — a redirect during crawling must not smuggle an off-policy
            # host into the evidence set.
            safe_url = self._policy.validate_candidate_url(returned_url)
        except ValueError:
            return None
        markdown = getattr(page, "markdown", None)
        if not isinstance(markdown, str) or not markdown.strip():
            return None  # empty Markdown is rejected, not passed through as evidence
        title = getattr(page, "title", None) or "Official documentation"
        return EvidenceDocument(
            source_url=safe_url,
            title=str(title)[:500],
            relevant_text=normalize_markdown(markdown),
        )


class GuardedHTTPEvidenceFetcher:
    """Adapt the existing per-URL ``OfficialEvidenceFetcher`` to the batch protocol."""

    def __init__(self, fetcher: object) -> None:
        self._fetcher = fetcher

    async def fetch_many(self, urls: Sequence[str]) -> tuple[EvidenceDocument, ...]:
        documents: list[EvidenceDocument] = []
        for url in urls:
            try:
                documents.append(await self._fetcher.fetch(url))  # type: ignore[attr-defined]
            except (httpx.HTTPError, OSError, ValueError):
                continue
        return tuple(documents)


class FallbackEvidenceContentFetcher:
    """You Contents first; the guarded HTTP fetcher fills whatever it missed (per URL)."""

    def __init__(self, primary: EvidenceContentFetcher, fallback: EvidenceContentFetcher) -> None:
        self._primary = primary
        self._fallback = fallback

    async def fetch_many(self, urls: Sequence[str]) -> tuple[EvidenceDocument, ...]:
        primary_documents = await self._primary.fetch_many(urls)
        fetched = {canonicalize(d.source_url) for d in primary_documents}
        missing = [url for url in urls if canonicalize(url) not in fetched]
        fallback_documents = await self._fallback.fetch_many(missing) if missing else ()
        return merge_documents(primary_documents, fallback_documents)


def merge_documents(
    primary: Sequence[EvidenceDocument], fallback: Sequence[EvidenceDocument]
) -> tuple[EvidenceDocument, ...]:
    seen: set[str] = set()
    merged: list[EvidenceDocument] = []
    for document in (*primary, *fallback):
        key = canonicalize(document.source_url)
        if key in seen:
            continue
        seen.add(key)
        merged.append(document)
    return tuple(merged[:MAX_EVIDENCE_DOCUMENTS])
