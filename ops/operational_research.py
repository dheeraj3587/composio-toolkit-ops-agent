"""Official-evidence operational enrichment with fail-closed provider boundaries."""

from __future__ import annotations

import asyncio
import importlib
import ipaddress
import socket
from collections.abc import Mapping, Sequence
from html.parser import HTMLParser
from typing import Protocol
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


class ResearchEnricher(Protocol):
    """The injectable one-probe enrichment boundary consumed by ``RunService``."""

    async def enrich(
        self,
        *,
        app_name: str,
        p1_record: Mapping[str, object],
        baseline: OperationalResearch,
    ) -> ResearchEnrichmentOutcome: ...


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
        normalized = {
            host.strip().rstrip(".").casefold() for host in official_hosts if host.strip()
        }
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


PERPLEXITY_TIMEOUT_SECONDS = 20.0
PERPLEXITY_MAX_RESULTS = 5
GEMINI_TIMEOUT_SECONDS = 45.0


class PerplexitySearchDiscovery:
    """Perplexity Search API adapter (perplexityai>=0.42, ``AsyncPerplexity``).

    One bounded request per enrichment attempt, no retry storm, at most five
    results. Downstream, :class:`OfficialURLPolicy` discards any result outside
    the verified official allowlist, so only official evidence URLs survive.
    """

    def __init__(
        self,
        api_key: SecretStr | str,
        *,
        search_domain_filter: Sequence[str] = (),
    ) -> None:
        self._api_key = api_key if isinstance(api_key, SecretStr) else SecretStr(api_key)
        self._search_domain_filter = tuple(
            value.strip() for value in search_domain_filter if value.strip()
        )

    async def discover(self, *, app_name: str) -> tuple[str, ...]:
        module = importlib.import_module("perplexity")
        client_type = module.AsyncPerplexity
        # ``max_retries=0`` avoids a hidden retry storm; the client owns one
        # bounded HTTP request that we time out explicitly below.
        client = client_type(
            api_key=self._api_key.get_secret_value(),
            max_retries=0,
            timeout=PERPLEXITY_TIMEOUT_SECONDS,
        )
        # ``search_mode`` is intentionally omitted: it is present in the installed
        # SDK signature but rejected as unsupported by the current Search API
        # deployment. Only the documented, universally accepted fields are sent.
        request: dict[str, object] = {
            "query": (
                f"{app_name} official developer documentation API authentication "
                "OAuth scopes token URL developer portal signup"
            ),
            "max_results": PERPLEXITY_MAX_RESULTS,
            "timeout": PERPLEXITY_TIMEOUT_SECONDS,
        }
        if self._search_domain_filter:
            request["search_domain_filter"] = list(self._search_domain_filter)
        try:
            response = await client.search.create(**request)
        finally:
            await client.close()

        seen: set[str] = set()
        urls: list[str] = []
        for result in getattr(response, "results", ()) or ():
            candidate = getattr(result, "url", None)
            if not isinstance(candidate, str):
                continue
            try:
                normalized = validate_https_url(candidate)
            except ValueError:
                continue
            if normalized in seen:
                continue
            seen.add(normalized)
            urls.append(normalized)
            if len(urls) >= PERPLEXITY_MAX_RESULTS:
                break
        return tuple(urls)


class GeminiStructuredExtractor:
    """Gemini structured-output adapter (google-genai>=2.12, ``google.genai``).

    Uses the current public async client
    (``client.aio.models.generate_content``) with a strict JSON schema and a
    pinned production model. The returned JSON is validated by Pydantic, and the
    enricher separately rejects any evidence/scope URL outside the fetched pack,
    so the model cannot inject fabricated URLs, scopes, or identities.
    """

    def __init__(
        self,
        api_key: SecretStr | str,
        *,
        model: str | Sequence[str] = "gemini-3.6-flash",
    ) -> None:
        self._api_key = api_key if isinstance(api_key, SecretStr) else SecretStr(api_key)
        models = (model,) if isinstance(model, str) else tuple(model)
        self._models = tuple(dict.fromkeys(name for name in models if name))
        if not self._models:
            raise ValueError("at least one Gemini model id is required")
        # The model that actually produced the last successful response.
        self.model_used: str | None = None

    async def extract(
        self,
        *,
        app_name: str,
        p1_record: Mapping[str, object],
        documents: tuple[EvidenceDocument, ...],
    ) -> OperationalResearch:
        prompt = _render_extraction_prompt(app_name, p1_record, documents)
        genai = importlib.import_module("google.genai")
        types = importlib.import_module("google.genai.types")
        client = genai.Client(api_key=self._api_key.get_secret_value())
        config = types.GenerateContentConfig(
            response_mime_type="application/json",
            response_json_schema=OperationalResearch.model_json_schema(),
            temperature=0,
            http_options=types.HttpOptions(timeout=int(GEMINI_TIMEOUT_SECONDS * 1000)),
        )
        last_error: Exception | None = None
        for model in self._models:
            try:
                response = await client.aio.models.generate_content(
                    model=model,
                    contents=prompt,
                    config=config,
                )
            except Exception as exc:  # try the next model on unavailability/overload
                last_error = exc
                continue
            text = getattr(response, "text", None)
            if not isinstance(text, str) or not text:
                last_error = RuntimeError("structured extraction returned no content")
                continue
            self.model_used = model
            return OperationalResearch.model_validate_json(text)
        raise RuntimeError(f"all Gemini models failed ({', '.join(self._models)})") from last_error


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
        if self._extractor is None:
            # Structured extraction (Gemini) is mandatory for enrichment; without
            # it the verified P1 baseline is retained truthfully. Perplexity
            # discovery is optional: when absent, only the verified P1 official
            # URLs are fetched, so no fabricated evidence can be introduced.
            return ResearchEnrichmentOutcome(
                research=baseline,
                capability=CapabilityAvailability(
                    capability="operational_research",
                    status="configuration_required",
                    reason_code="provider_credentials_missing",
                    detail=(
                        "Gemini structured extraction must be configured to enrich; "
                        "the verified P1 baseline is retained."
                    ),
                ),
                missing_fields=missing,
                documents_fetched=0,
            )

        policy = OfficialURLPolicy.from_p1_record(p1_record, resolver=self._resolver)
        fetcher = OfficialEvidenceFetcher(self._http_client, policy)
        discovered = await self._discovery.discover(app_name=app_name) if self._discovery else ()
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
        _validate_extracted_research(research, baseline, documents, p1_record)
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


def _normalize_url(value: str) -> str | None:
    """Canonicalize an HTTPS URL for citation comparison.

    Lowercases the hostname, drops the fragment, and normalizes a redundant
    trailing slash while preserving the meaningful path and query. Non-HTTPS
    URLs return ``None`` so they can never match an allowed citation.
    """

    parsed = urlsplit(value.strip())
    if parsed.scheme != "https" or not parsed.hostname:
        return None
    hostname = parsed.hostname.rstrip(".").casefold()
    path = parsed.path or "/"
    if len(path) > 1 and path.endswith("/"):
        path = path.rstrip("/") or "/"
    return urlunsplit(("https", hostname, path, parsed.query, ""))


def _validate_extracted_research(
    research: OperationalResearch,
    baseline: OperationalResearch,
    documents: Sequence[EvidenceDocument],
    p1_record: Mapping[str, object],
) -> None:
    if research.app_slug != baseline.app_slug or research.app_name != baseline.app_name:
        raise ValueError("structured extraction changed the canonical app identity")

    # Evidence citations may reference only the normalized union of: trusted P1
    # evidence URLs, the trusted P1 primary docs URL, and the URLs we actually
    # fetched. A hostname being "official" is not sufficient; the specific page
    # must be one we trusted or fetched, so the model cannot fabricate a URL.
    fetched: set[str] = set()
    for document in documents:
        normalized = _normalize_url(document.source_url)
        if normalized is not None:
            fetched.add(normalized)
    allowed_evidence = set(fetched)
    primary = p1_record.get("primary_docs_url")
    if isinstance(primary, str):
        normalized = _normalize_url(primary)
        if normalized is not None:
            allowed_evidence.add(normalized)
    p1_evidence = p1_record.get("evidence_urls")
    if isinstance(p1_evidence, list):
        for value in p1_evidence:
            if isinstance(value, str):
                normalized = _normalize_url(value)
                if normalized is not None:
                    allowed_evidence.add(normalized)

    for value in research.evidence_urls:
        normalized = _normalize_url(value)
        if normalized is None or normalized not in allowed_evidence:
            raise ValueError("structured extraction cited evidence outside the trusted union")

    # Scope citations stay stricter: a scope is acceptable only when its source
    # URL is one we actually fetched, or when that exact scope name already
    # exists in the trusted P1 baseline. This blocks invented scopes attributed
    # to unfetched pages.
    trusted_scope_names = {scope.name for scope in baseline.scopes}
    for scope in research.scopes:
        normalized = _normalize_url(scope.source_url)
        cited_from_fetched = normalized is not None and normalized in fetched
        if not cited_from_fetched and scope.name not in trusted_scope_names:
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
