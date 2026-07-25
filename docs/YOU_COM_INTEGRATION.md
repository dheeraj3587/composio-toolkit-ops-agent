# You.com Integration

## Purpose

You.com improves **public official-document discovery and extraction** for
the operational research pipeline: finding an app's official login page,
signup page, developer portal, API settings/credentials page, and
authentication/scope documentation faster and more accurately than
Perplexity alone.

> You.com improves public official-document discovery and extraction.
> It does not control the browser. Browser Use remains the primary
> production browser harness.

## Architecture

### Pipeline (before -> after)

Before:

```
Verified P1 snapshot
    -> Perplexity discovery (optional)
    -> OfficialEvidenceFetcher (guarded HTTP)
    -> Gemini structured extraction
    -> OperationalResearch
    -> Browser Use
```

After (only when `YDC_API_KEY` is configured — otherwise byte-identical to
the pipeline above):

```
Verified P1 snapshot
    -> You.com Search (primary discovery)
    -> Perplexity Search (fallback discovery)
    -> You.com Contents (primary content extraction)
    -> Existing guarded HTTP fetcher (fallback, per-URL)
    -> Gemini strict OperationalResearch extraction (unchanged, canonical)
    -> Optional You.com Research fallback (adds MORE candidate pages, never
       authors a field directly — see "Research" below)
    -> Browser Use production browser harness (unchanged)
```

### Module layout

* `ops/you_research.py` — the whole new layer: `EvidenceCandidate`,
  `ResearchHostPolicy`, `YouSearchDiscovery`, `CompositeEvidenceDiscovery`,
  `LegacyDiscoveryAdapter`, `YouContentsFetcher`, `GuardedHTTPEvidenceFetcher`,
  `FallbackEvidenceContentFetcher`, `YouResearchFallback`, error mapping,
  bounded retry, caching, sanitized metrics.
* `ops/operational_research.py` — unchanged `EvidenceDiscovery` protocol and
  original `OperationalResearchEnricher` code path (used verbatim whenever
  You.com is not configured); ADDITIVE `rich_discovery` /
  `content_fetcher_factory` / `research_fallback` constructor parameters and
  a new `_enrich_rich` method that only runs when at least one of those is
  supplied. `extract_https_urls` (documented-URL extraction) and
  `_validate_operational_urls` (the new operational-URL-vs-evidence check)
  live here too, to avoid a circular import with `ops.you_research`.
* `ops/run_service.py` — `_build_research_enricher` wires You.com when
  `YDC_API_KEY` is configured, and builds the exact pre-existing
  Perplexity + guarded-HTTP wiring when it is not.
* `ops/cli.py` — `research-app` and `probe-you` operator diagnostics.
* `ops/you_eval.py` + `tests/fixtures/you_eval_dataset.json` +
  `tests/test_you_eval.py` + `tests/live/test_you_discovery_live.py` —
  the evaluation harness (offline fixtures + opt-in live).

### Preserved separation of concerns

Discovery, URL-policy validation, content retrieval, structured extraction,
and post-extraction validation remain five distinct steps — You.com sits
inside the first two, never collapses them into a single uncontrolled agent:

1. **Discovery** — `YouSearchDiscovery` / `LegacyDiscoveryAdapter`-wrapped
   Perplexity / `CompositeEvidenceDiscovery` return `EvidenceCandidate`s
   (URL + bounded title/snippets + classification), never full page content.
2. **URL-policy validation** — `ResearchHostPolicy` (built ONLY from the
   verified P1 record, the verified baseline, and the reviewed
   `ops/browser_host_policy.py` dataset) decides which hosts are trusted;
   `OfficialURLPolicy` remains the final HTTPS/SSRF authority for anything
   actually fetched.
3. **Content retrieval** — `YouContentsFetcher` (primary) ->
   `GuardedHTTPEvidenceFetcher` (fallback, wraps the pre-existing
   `OfficialEvidenceFetcher` unchanged) via `FallbackEvidenceContentFetcher`,
   per-URL fallback so one failed page never discards the batch.
4. **Structured extraction** — `GeminiStructuredExtractor`, completely
   unchanged code, same strict JSON schema, same pinned model chain. This is
   the ONLY place an `OperationalResearch` object is produced.
5. **Post-extraction validation** — the pre-existing `_validate_extracted_research`
   (evidence citations, scope citations, identity) PLUS the new
   `_validate_operational_urls` (an operational field like `login_url` must be
   one of the fetched evidence URLs, or literally documented inside fetched
   evidence text on an approved host, or a reaffirmation of the verified
   baseline — never an invented URL).

## Search vs. Contents vs. Research

| Capability | Purpose | Default | Cost |
|---|---|---|---|
| Search | Find candidate official pages (URL + title + snippets) | ON (needs key) | Cheap, 2 calls max per enrichment |
| Contents | Fetch clean Markdown for policy-approved URLs | ON (needs key) | Moderate, 1 batch (<=10 URLs) max |
| Research | Multi-step fallback when Search+Contents are insufficient | **OFF** | Expensive, at most 1 call, only supplies MORE candidate URLs for the same Gemini extraction |

### Verified SDK contract (important — read before touching this code)

The official Python SDK is `youdotcom` (`pip install youdotcom`), authenticated
via `YDC_API_KEY`. This integration is pinned to **`youdotcom==2.2.0`**,
verified by installing it and inspecting the real signatures rather than
trusting documentation prose (`tests/test_you_research.py::TestSdkContract`
pins these facts so a future SDK upgrade fails loudly instead of silently):

* `you.search.unified_async(query, count, safesearch, timeout_ms, ...)` and
  `you.contents.generate_async(urls, formats, crawl_timeout, timeout_ms, ...)`
  are real `async def` coroutines — no thread-pool wrapping needed.
* **The installed SDK's `search.unified` has NO `include_domains` /
  `exclude_domains` / `boost_domains` parameter at all.** This is a genuine
  gap between the public REST OpenAPI spec (which documents these) and the
  Python SDK version pinned here. Domain trust for Search is therefore
  enforced ENTIRELY downstream, by `ResearchHostPolicy`, on every candidate
  URL returned — never at the request layer. This does not weaken anything:
  every candidate would have needed that same downstream check regardless,
  per the non-negotiable "never trust a URL just because You.com returned it."
* **The installed SDK's `contents.generate` has NO `max_age` request
  parameter.** `max_age` in this integration is a LOCAL cache-freshness bound
  only (see `ResearchCache`); it is never sent to You.com.
* **There is no standalone `you.research(...)` method in this SDK version.**
  The only Research surface is a `ResearchTool` object nested inside the
  Agents API (`you.agents.runs.create`), with `search_effort:
  Literal["low","medium","high","auto"]` and no `output_schema` /
  `source_control` / cited `output.sources` — none of the guarantees this
  integration requires and the docs describe. `YouResearchFallback` therefore
  calls the documented REST endpoint (`POST https://api.you.com/v1/research`)
  directly over a guarded `httpx.AsyncClient`, the same pattern already used
  by `OfficialEvidenceFetcher`, rather than inventing a compatibility shim
  around a mismatched SDK object. If a future SDK version adds a matching
  `research()` method, migrating to it is a contained change inside
  `YouResearchFallback` only.
* `YouError` (the SDK's exception base) exposes `.status_code`; nothing else
  from a provider exception (`.message`, `.body`, `.headers`, the raw
  exception) is ever read for logging or user-facing text.
  `ops.you_research.map_you_error` reads only `.status_code`.
* The SDK applies **no retry of its own** unless a `RetryConfig` is
  explicitly supplied (verified from source: `sdk_configuration.retry_config`
  defaults to `Unset()`). This integration never supplies one, so
  `run_with_bounded_retry` is the only retry layer — no double-retry risk.

If a future `youdotcom` upgrade changes any of the above, the contract tests
in `tests/test_you_research.py::TestSdkContract` will fail first, before any
production code silently breaks.

## Provider fallback order

* **Discovery**: You.com Search first (when `you_search_configured`) ->
  Perplexity (when configured) via `CompositeEvidenceDiscovery`. Perplexity
  is only called when You.com's results do not yet cover an access page
  (login/signup) AND a portal/credential page AND a credential/oauth page —
  not merely because the configured result count wasn't fully filled.
* **Content fetch**: You.com Contents first (when `you_contents_configured`)
  -> the pre-existing guarded HTTP fetcher, per URL — one failed page never
  discards the rest of the batch.
* **Research fallback**: only when Search + Contents produced zero usable
  documents, `you_research_configured`, and official hosts exist. Called at
  most once. Its ONLY effect is adding more candidate URLs (each individually
  re-validated against `ResearchHostPolicy` and cross-checked against
  `output.sources`) to the SAME Contents fetch + Gemini extraction path —
  it never creates an `OperationalResearch` value directly.

## Feature flags

| Env var | Default | Notes |
|---|---|---|
| `YDC_API_KEY` | unset | Server-side only. Every flag below requires this. |
| `YOU_SEARCH_ENABLED` | `true` | Stage 1 |
| `YOU_CONTENTS_ENABLED` | `true` | Stage 2 |
| `YOU_RESEARCH_ENABLED` | `false` | Stage 3 — stays off until Search+Contents are evaluated |
| `YOU_SEARCH_COUNT` | `5` | 1-10 |
| `YOU_SEARCH_TIMEOUT_SECONDS` | `20` | 2-60 |
| `YOU_CONTENTS_TIMEOUT_SECONDS` | `30` | 2-60 |
| `YOU_CONTENTS_MAX_AGE_SECONDS` | `86400` | local cache only, never sent to You.com |
| `YOU_RESEARCH_TIMEOUT_SECONDS` | `60` | 10-180 |
| `YOU_MAX_SEARCH_CALLS_PER_ENRICHMENT` | `2` | 1-4 |
| `YOU_MAX_CONTENTS_PAGES_PER_ENRICHMENT` | `8` | 1-10 |
| `YOU_MAX_RESEARCH_CALLS_PER_ENRICHMENT` | `1` | 0-1 |

`Settings.you_search_configured` / `you_contents_configured` /
`you_research_configured` are `True` only when BOTH the key is present AND
the corresponding flag is enabled. `YDC_API_KEY` is `repr=False` (hidden from
`repr`/`str`/logs/audit rows) exactly like every other provider key in
`ops/config.py`, and is never exposed via `NEXT_PUBLIC_*`, frontend props, API
responses, logs, audit events, or exception messages.

## Credit controls

* Search: at most `you_max_search_calls_per_enrichment` calls (default 2),
  `count` capped at 10.
* Contents: at most one batch, capped at `MAX_YOU_CONTENT_URLS` = 10 URLs.
* Research: at most `you_max_research_calls_per_enrichment` (0 or 1), and
  only attempted when Search+Contents produced nothing.
* Bounded retry: `YOU_MAX_RETRIES = 2`, exponential backoff with jitter,
  honors `Retry-After` on 429, retries ONLY 429 / 500 / 502 / 503 / 504 / a
  connection failure — never 400/401/402/403/404/422, and never a programming
  error (`TypeError`/`AttributeError`/`ImportError`/...), which always
  propagates instead of being silently retried or swallowed.

## Cache behavior

`ResearchCache` is a provider-neutral `get`/`put` protocol
(`InMemoryResearchCache` is the reference implementation). Suggested keys and
TTLs:

* `you-search:v1:<digest>` — 24h
* `you-contents:v1:<digest>` — 24h
* `you-research:v1:<digest>` — 7d

Never cached: API keys, credentials, provider authorization headers, private
URLs, error response bodies, login verification links, OTP data.

## URL trust policy

`ResearchHostPolicy` computes the trusted host set from ONLY:

* the verified P1 record's `primary_docs_url` / `evidence_urls`;
* the verified baseline's `developer_portal_url` / `signup_url`;
* the reviewed, static per-app entries already in `ops/browser_host_policy.py`
  (both active AND inactive entries — reading public docs is safe even for
  an app whose browser automation is not yet active).

It never derives a host from a search result approving its own domain, and
never algorithmically widens `developers.vendor.com` into `*.vendor.com`
unless that broader root is already an explicitly reviewed
`vendor_wildcard_domains` entry. All URL-shape/SSRF enforcement is delegated
to the pre-existing `OfficialURLPolicy` — `ResearchHostPolicy` only decides
which hosts that policy trusts.

## Error handling

Sanitized reason codes only (`ops.you_research.map_you_error`):
`you_search_unauthorized`, `you_search_forbidden`, `you_search_credit_exhausted`,
`you_search_rate_limited`, `you_search_invalid_request`, `you_search_timeout`,
`you_search_failed`, and the `you_contents_*` / `you_research_*` equivalents
(`you_research_invalid_schema` instead of `_invalid_request`). Never included
in a log, error, or audit row: the API key, a full response body, query
contents, fetched page content, or raw provider exception text.

## Testing

* `tests/test_you_research.py` — 102+ mocked unit tests: configuration
  gating, candidate ranking/diversification, `ResearchHostPolicy`, Search
  adapter (mocked SDK responses), composite discovery ordering/fallback,
  Contents adapter, `FallbackEvidenceContentFetcher`, error mapping, bounded
  retry, Research fallback validation, the full mocked enricher flow, the
  browser boundary, and the SDK contract test.
* `tests/test_you_eval.py` — offline evaluator using hand-built, sanitized
  fixture candidates (real verified URL shapes, not live output).
* `tests/live/test_you_discovery_live.py` — opt-in live evaluator:

  ```
  RUN_LIVE_YOU_TESTS=1 python -m pytest tests/live/test_you_discovery_live.py
  ```

  Skipped by default; skips per-test when the relevant key is absent even
  when the env var is set; strict hard-coded call budget (3 apps, `count=3`);
  prints only the sanitized report; never imports a browser worker.
* Regression: the entire pre-existing suite (667 tests before this change)
  remains green, because the original `OperationalResearchEnricher` code
  path is untouched — the new dependencies are additive and `None` by
  default.

## Operator probe / debug commands

```
python -m ops.cli research-app "Pipedrive" --provider you
python -m ops.cli probe-you
```

`research-app` runs discovery (+ a best-effort content fetch) for a real P1
app and prints only: app name/slug, provider requested/used, sanitized
official domains, candidate URLs/categories/providers, fetched document
URLs/titles (never full text), missing baseline fields, and latencies. It
never runs Gemini extraction and never touches the browser.

`probe-you` requires explicit execution, performs exactly one cheap Search
call, and returns a sanitized success/failure reason. Normal API health
checks never call it — `RunService.startup()` only records a
sanitized wiring-audit row (`configured: bool`), never a live probe.

## Security boundaries (non-negotiable, unchanged by this integration)

* Browser Use remains the primary production browser harness;
  `Settings.browser_provider` default (`"browser_use"`) is untouched.
* `ops/browser_host_policy.py`'s per-app `allowed_domains` are derived ONLY
  from the reviewed static dataset — never from `OperationalResearch` fields,
  so no You.com/Perplexity/Research result can ever expand a browser
  allowlist. This was already true before this integration and remains true.
* `ops/browser_worker.py::_official_target_url` already gates every candidate
  browser start URL (including `developer_portal_url`/`signup_url`, whether
  from You.com-enriched research or not) through
  `is_allowed_browser_url(url, allowed_domains)` before use.
* You.com never receives login credentials, API keys, OTPs, cookies, or
  vault values — it is called with only an app name and (for Contents) a
  policy-approved public URL.
* `Playwright` remains disabled by default and undeployed; nothing in this
  integration touches `browser_provider` selection or the Playwright harness.

## Rollout stages

1. `YOU_SEARCH_ENABLED=true`, `YOU_CONTENTS_ENABLED=false`,
   `YOU_RESEARCH_ENABLED=false` — evaluate Search discovery vs. Perplexity
   using the pre-existing guarded HTTP fetcher for content.
2. `YOU_CONTENTS_ENABLED=true` — use You.com Contents for selected pages.
3. `YOU_RESEARCH_ENABLED=true` — only after Search+Contents metrics are
   understood, schema validation is tested, and call budgets are confirmed.

## Known limitations

* `search.unified` in the pinned SDK cannot restrict results by domain at
  request time; enforcement is fully downstream (see "Verified SDK contract"
  above). This is safe by design, not a gap, but it does mean every Search
  call queries the open web rather than a domain-scoped index.
* `YouResearchFallback` talks to the REST endpoint directly rather than
  through the SDK's `ResearchTool`, because the installed SDK version's
  Research surface does not support the structured-output/source-citation
  contract this integration requires. It is disabled by default regardless.
* The evaluation dataset's `approved_hosts` for Twilio, Slack, and Zoho were
  verified via direct source lookup during this work but have not yet been
  cross-reviewed into `ops/browser_host_policy.py` — treat them as a
  starting point for human review, not a substitute for it.
* `ops.you_research.classify_category` is keyword-based: a bare root URL with
  no path/hostname keyword (e.g. a login SPA served at the bare domain root)
  classifies as `"unknown"` even when a human would recognize it as a login
  page. The evaluation dataset's `expected_categories` reflect this honestly
  rather than papering over it; category recall on such apps will read lower
  than a human reviewer would score it.
* `.github/workflows/ci.yml` could not be pushed in this session (the
  connected GitHub integration lacks `workflows` write scope, a pre-existing,
  previously-documented limitation from the Playwright work). The CI job
  described in this document exists locally but is not yet live on GitHub.

## Relationship to Browser Use

Browser Use remains unchanged as the executor. Only VALIDATED fields
(`login_url`, `developer_portal_url`, `credential_management_url`,
authentication method, credential fields) may ever reach a browser task, and
only after passing `_validate_operational_urls` and the pre-existing
`is_allowed_browser_url` gate. You.com search snippets, You.com Research
prose, and arbitrary URLs are never passed as browser instructions. You.com
must never be used to bypass CAPTCHA, OTP, MFA, or account verification —
nothing in this integration touches that logic at all.
