"""Official-evidence operational enrichment with fail-closed provider boundaries."""

from __future__ import annotations

import asyncio
import importlib
import ipaddress
import re
import socket
from collections.abc import Awaitable, Callable, Mapping, Sequence
from html.parser import HTMLParser
from typing import Any, Protocol
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

import httpx
from pydantic import Field, SecretStr

from ops.models import (
    CapabilityAvailability,
    OperationalResearch,
    StrictModel,
    validate_https_url,
)
from ops.provider_errors import PhaseUnavailableError

MAX_EVIDENCE_DOCUMENTS = 8
MAX_RESPONSE_BYTES = 256 * 1024
MAX_EXCERPT_CHARACTERS = 24_000
MAX_REDIRECTS = 3
_SENSITIVE_QUERY_NAMES = frozenset(
    {"access_token", "api_key", "code", "key", "password", "secret", "token"}
)
_TEXT_CONTENT_TYPES = ("text/html", "text/plain", "application/json", "application/xhtml+xml")


class EvidenceDocument(StrictModel):
    """A bounded excerpt fetched from an allowlisted official HTTPS URL."""

    source_url: str
    title: str = Field(max_length=500)
    relevant_text: str = Field(max_length=MAX_EXCERPT_CHARACTERS)


class ResearchEnrichmentOutcome(StrictModel):
    """Truthful result: a baseline remains usable when provider configuration is absent."""

    research: OperationalResearch
    capability: CapabilityAvailability
    missing_fields: list[str]
    documents_fetched: int = Field(ge=0, le=MAX_EVIDENCE_DOCUMENTS)


class OperationalResearchProvider(Protocol):
    async def enrich(
        self,
        *,
        app_name: str,
        p1_record: dict[str, object],
        evidence_documents: tuple[EvidenceDocument, ...],
    ) -> OperationalResearch: ...


class EvidenceDiscovery(Protocol):
    async def discover(self, *, app_name: str) -> tuple[str, ...]: ...


class EvidenceExtractor(Protocol):
    async def extract(
        self,
        *,
        app_name: str,
        p1_record: Mapping[str, object],
        documents: tuple[EvidenceDocument, ...],
    ) -> OperationalResearch: ...


class HostResolver(Protocol):
    async def resolve(self, hostname: str) -> tuple[str, ...]: ...


class SystemHostResolver:
    """Resolve every address so URL checks reject private or special networks."""

    async def resolve(self, hostname: str) -> tuple[str, ...]:
        loop = asyncio.get_running_loop()
        records = await loop.getaddrinfo(hostname, 443, type=socket.SOCK_STREAM)
        return tuple(sorted({str(record[4][0]) for record in records}))


class OfficialURLPolicy:
    """Exact-host/subdomain allowlist plus DNS-level SSRF protection."""

    def __init__(self, official_hosts: Sequence[str], resolver: HostResolver | None = None) -> None:
        normalized = {host.strip().rstrip(".").casefold() for host in official_hosts if host.strip()}
        if not normalized:
            raise ValueError("at least one verified official host is required")
        self._official_hosts = frozenset(normalized)
        self._resolver = resolver or SystemHostResolver()

    @classmethod
    def from_p1_record(
        cls,
        p1_record: Mapping[str, object],
        *,
        resolver: HostResolver | None = None,
    ) -> OfficialURLPolicy:
        urls: list[str] = []
        primary = p1_record.get("primary_docs_url")
        if isinstance(primary, str):
            urls.append(primary)
        evidence = p1_record.get("evidence_urls")
        if isinstance(evidence, list):
            urls.extend(value for value in evidence if isinstance(value, str))
        hosts = [urlsplit(value).hostname or "" for value in urls]
        return cls(hosts, resolver=resolver)

    def sanitize_candidate(self, value: str) -> str:
        validated = validate_https_url(value)
        parsed = urlsplit(validated)
        hostname = (parsed.hostname or "").rstrip(".").casefold()
        if not any(
            hostname == official or hostname.endswith(f".{official}")
            for official in self._official_hosts
        ):
            raise ValueError("URL host is outside the verified official allowlist")
        if parsed.port not in (None, 443):
            raise ValueError("official evidence URLs must use the standard HTTPS port")
        safe_query = urlencode(
            [
                (name, value)
                for name, value in parse_qsl(parsed.query, keep_blank_values=True)
                if name.casefold() not in _SENSITIVE_QUERY_NAMES
            ],
            doseq=True,
        )
        return urlunsplit(("https", hostname, parsed.path or "/", safe_query, parsed.fragment))

    async def validate_for_request(self, value: str) -> str:
        sanitized = self.sanitize_candidate(value)
        hostname = urlsplit(sanitized).hostname
        if hostname is None:  # pragma: no cover - guaranteed by sanitize_candidate
            raise ValueError("official evidence URL has no hostname")
        addresses = await self._resolver.resolve(hostname)
        if not addresses:
            raise ValueError("official evidence host did not resolve")
        for value in addresses:
            try:
                address = ipaddress.ip_address(value)
            except ValueError as exc:
                raise ValueError("official evidence host resolved unexpectedly") from exc
            if not address.is_global:
                raise ValueError("official evidence host resolved to a non-public address")
        return sanitized


class _VisibleTextParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self._ignored_depth = 0
        self.title = ""
        self._inside_title = False
        self.parts: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        del attrs
        if tag in {"script", "style", "svg", "noscript"}:
            self._ignored_depth += 1
        if tag == "title":
            self._inside_title = True

    def handle_endtag(self, tag: str) -> None:
        if tag in {"script", "style", "svg", "noscript"} and self._ignored_depth:
            self._ignored_depth -= 1
        if tag == "title":
            self._inside_title = False

    def handle_data(self, data: str) -> None:
        if self._ignored_depth:
            return
        normalized = " ".join(data.split())
        if not normalized:
            return
        if self._inside_title and not self.title:
            self.title = normalized[:500]
        self.parts.append(normalized)


class OfficialEvidenceFetcher:
    """Fetch bounded official pages without following an unvalidated redirect."""

    def __init__(self, client: httpx.AsyncClient, policy: OfficialURLPolicy) -> None:
        self._client = client
        self._policy = policy

    async def fetch(self, url: str) -> EvidenceDocument:
        current = await self._policy.validate_for_request(url)
        for redirect_count in range(MAX_REDIRECTS + 1):
            async with self._client.stream(
                "GET",
                current,
                follow_redirects=False,
                headers={"Accept": "text/html, text/plain;q=0.9, application/json;q=0.7"},
            ) as response:
                if response.status_code in {301, 302, 303, 307, 308}:
                    if redirect_count == MAX_REDIRECTS:
                        raise ValueError("official evidence exceeded the redirect limit")
                    location = response.headers.get("location")
                    if not location:
                        raise ValueError("official evidence redirect omitted its target")
                    current = await self._policy.validate_for_request(urljoin(current, location))
                    continue
                response.raise_for_status()
                content_type = response.headers.get("content-type", "").casefold()
                if not content_type.startswith(_TEXT_CONTENT_TYPES):
                    raise ValueError("official evidence returned an unsupported content type")
                declared = response.headers.get("content-length")
                if declared and declared.isdigit() and int(declared) > MAX_RESPONSE_BYTES:
                    raise ValueError("official evidence exceeded the response size limit")
                chunks: list[bytes] = []
                total = 0
                async for chunk in response.aiter_bytes():
                    total += len(chunk)
                    if total > MAX_RESPONSE_BYTES:
                        raise ValueError("official evidence exceeded the response size limit")
                    chunks.append(chunk)
                body = b"".join(chunks).decode(response.encoding or "utf-8", errors="replace")
                title, text = _extract_visible_text(body, content_type)
                return EvidenceDocument(
                    source_url=self._policy.sanitize_candidate(str(response.url)),
                    title=title,
                    relevant_text=text,
                )
        raise AssertionError("redirect loop exited unexpectedly")  # pragma: no cover


def _extract_visible_text(body: str, content_type: str) -> tuple[str, str]:
    if "html" not in content_type:
        return "Official documentation", " ".join(body.split())[:MAX_EXCERPT_CHARACTERS]
    parser = _VisibleTextParser()
    parser.feed(body)
    return parser.title or "Official documentation", "\n".join(parser.parts)[
        :MAX_EXCERPT_CHARACTERS
    ]


class PerplexitySearchDiscovery:
    """Native Perplexity Search API adapter; imported only when configured."""

    def __init__(self, api_key: SecretStr | str) -> None:
        self._api_key = api_key if isinstance(api_key, SecretStr) else SecretStr(api_key)

    async def discover(self, *, app_name: str) -> tuple[str, ...]:
        module = importlib.import_module("perplexity")
        client_type = getattr(module, "AsyncPerplexity")
        client = client_type(api_key=self._api_key.get_secret_value(), max_retries=1)
        try:
            response = await client.search.create(
                query=[
                    f"{app_name} official developer portal API authentication",
                    f"{app_name} official OAuth scopes authorization token URL",
                    f"{app_name} API partner access contact production approval",
                ],
                max_results=5,
            )
            return tuple(
                str(result.url)
                for result in response.results
                if isinstance(getattr(result, "url", None), str)
            )
        finally:
            await client.close()


class GeminiStructuredExtractor:
    """Gemini structured-output adapter validated directly by Pydantic."""

    def __init__(self, api_key: SecretStr | str, *, model: str = "gemini-3.1-pro-preview") -> None:
        self._api_key = api_key if isinstance(api_key, SecretStr) else SecretStr(api_key)
        self._model = model

    async def extract(
        self,
        *,
        app_name: str,
        p1_record: Mapping[str, object],
        documents: tuple[EvidenceDocument, ...],
    ) -> OperationalResearch:
        prompt = _render_extraction_prompt(app_name, p1_record, documents)

        def invoke() -> str:
            module = importlib.import_module("google.genai")
            client = module.Client(api_key=self._api_key.get_secret_value())
            try:
                response = client.models.generate_content(
                    model=self._model,
                    contents=prompt,
                    config={
                        "response_mime_type": "application/json",
                        "response_json_schema": OperationalResearch.model_json_schema(),
                        "temperature": 0,
                    },
                )
                text = response.text
                if not isinstance(text, str) or not text:
                    raise RuntimeError("structured extraction returned no content")
                return text
            finally:
                client.close()

        return OperationalResearch.model_validate_json(await asyncio.to_thread(invoke))


def _render_extraction_prompt(
    app_name: str,
    p1_record: Mapping[str, object],
    documents: tuple[EvidenceDocument, ...],
) -> str:
    # P1 and evidence documents are non-secret, bounded, strict inputs.  repr is
    # intentionally avoided so the model receives a deterministic plain form.
    import json

    return (
        "Extract operational API access facts using only the official evidence. "
        "Use null or unknown for unsupported facts. Never invent scopes. Every scope "
        "must cite one supplied source URL. Return only the supplied JSON schema.\n\n"
        f"APP\n{app_name}\n\n"
        f"P1 RECORD\n{json.dumps(dict(p1_record), sort_keys=True)}\n\n"
        "EVIDENCE PACK\n"
        f"{json.dumps([document.model_dump() for document in documents], sort_keys=True)}"
    )


class OperationalResearchEnricher:
    """Orchestrate discovery, guarded fetches, and structured extraction."""

    def __init__(
        self,
        *,
        discovery: EvidenceDiscovery | None,
        extractor: EvidenceExtractor | None,
        http_client: httpx.AsyncClient,
        resolver: HostResolver | None = None,
    ) -> None:
        self._discovery = discovery
        self._extractor = extractor
        self._http_client = http_client
        self._resolver = resolver

    async def enrich(
        self,
        *,
        app_name: str,
        p1_record: Mapping[str, object],
        baseline: OperationalResearch,
    ) -> ResearchEnrichmentOutcome:
        missing = _missing_fields(baseline)
        if self._discovery is None or self._extractor is None:
            return ResearchEnrichmentOutcome(
                research=baseline,
                capability=CapabilityAvailability(
                    capability="operational_research",
                    status="configuration_required",
                    reason_code="provider_credentials_missing",
                    detail=(
                        "Perplexity discovery and Gemini extraction must both be configured; "
                        "the verified P1 baseline is retained."
                    ),
                ),
                missing_fields=missing,
                documents_fetched=0,
            )

        policy = OfficialURLPolicy.from_p1_record(p1_record, resolver=self._resolver)
        fetcher = OfficialEvidenceFetcher(self._http_client, policy)
        discovered = await self._discovery.discover(app_name=app_name)
        candidates = _candidate_urls(p1_record, discovered, policy)
        documents: list[EvidenceDocument] = []
        for candidate in candidates:
            if len(documents) == MAX_EVIDENCE_DOCUMENTS:
                break
            try:
                documents.append(await fetcher.fetch(candidate))
            except (httpx.HTTPError, OSError, ValueError):
                continue
        if not documents:
            return ResearchEnrichmentOutcome(
                research=baseline,
                capability=CapabilityAvailability(
                    capability="operational_research",
                    status="failed",
                    reason_code="official_evidence_unavailable",
                    detail="No allowlisted official evidence page could be fetched safely.",
                ),
                missing_fields=missing,
                documents_fetched=0,
            )

        research = await self._extractor.extract(
            app_name=app_name,
            p1_record=p1_record,
            documents=tuple(documents),
        )
        _validate_extracted_research(research, baseline, documents, policy)
        return ResearchEnrichmentOutcome(
            research=research,
            capability=CapabilityAvailability(
                capability="operational_research",
                status="ready",
                reason_code="official_evidence_enriched",
                detail="Operational fields were extracted from fetched allowlisted evidence.",
            ),
            missing_fields=_missing_fields(research),
            documents_fetched=len(documents),
        )


def _candidate_urls(
    p1_record: Mapping[str, object],
    discovered: Sequence[str],
    policy: OfficialURLPolicy,
) -> tuple[str, ...]:
    supplied: list[str] = []
    primary = p1_record.get("primary_docs_url")
    if isinstance(primary, str):
        supplied.append(primary)
    evidence = p1_record.get("evidence_urls")
    if isinstance(evidence, list):
        supplied.extend(value for value in evidence if isinstance(value, str))
    supplied.extend(discovered)
    result: list[str] = []
    for value in supplied:
        try:
            safe = policy.sanitize_candidate(value)
        except ValueError:
            continue
        if safe not in result:
            result.append(safe)
    return tuple(result)


def _validate_extracted_research(
    research: OperationalResearch,
    baseline: OperationalResearch,
    documents: Sequence[EvidenceDocument],
    policy: OfficialURLPolicy,
) -> None:
    if research.app_slug != baseline.app_slug or research.app_name != baseline.app_name:
        raise ValueError("structured extraction changed the canonical app identity")
    source_urls = {document.source_url for document in documents}
    for value in research.evidence_urls:
        if policy.sanitize_candidate(value) not in source_urls:
            raise ValueError("structured extraction cited evidence outside the fetched pack")
    for scope in research.scopes:
        if policy.sanitize_candidate(scope.source_url) not in source_urls:
            raise ValueError("structured extraction cited an unsupported scope source")


def _missing_fields(research: OperationalResearch) -> list[str]:
    fields = (
        "api_available",
        "api_base_url",
        "authorization_url",
        "token_url",
        "developer_portal_url",
        "signup_url",
        "production_approval_required",
        "contact_email",
        "contact_url",
    )
    missing = [name for name in fields if getattr(research, name) is None]
    if not research.credential_fields:
        missing.append("credential_fields")
    if not research.scopes:
        missing.append("scopes")
    return missing


class UnavailableOperationalResearchProvider:
    """Compatibility boundary retained for callers that require hard failure."""

    async def enrich(
        self,
        *,
        app_name: str,
        p1_record: dict[str, object],
        evidence_documents: tuple[EvidenceDocument, ...],
    ) -> OperationalResearch:
        del app_name, p1_record, evidence_documents
        raise PhaseUnavailableError(phase=2, capability="operational research enrichment")
