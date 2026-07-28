# You.com Integration

## Purpose

You.com improves **public official-document discovery and extraction** for the
operational-research pipeline: finding an app's official login page, signup
page, developer portal, API settings/credentials page, and
authentication/scope documentation faster and more accurately than Perplexity
alone.

> You.com never controls either browser provider. Playwright and Browser Use are
> selected per run by the operator.

You.com is used **only** for: official web-page discovery, official
documentation retrieval, and finding login / signup / developer-portal /
API-authentication / credential-management / OAuth / scope pages, plus an
optional bounded research fallback. It never controls Browser Use or
Playwright, never receives credentials/OTPs/cookies/vault values/private
dashboard URLs, never expands browser host permissions, and never sends email
or deploys anything.

## Pipeline

```
Verified P1 snapshot
    -> Trusted research-host policy (ResearchHostPolicy)
    -> You.com Search (primary discovery)
    -> Perplexity fallback when category coverage is insufficient
    -> Optional bounded You.com Research source discovery (candidate pages only)
    -> You.com Contents (primary content extraction)
    -> Guarded HTTP fallback per URL
    -> Gemini strict structured extraction (the ONLY creator of OperationalResearch)
    -> Field-level evidence validation
    -> OperationalResearch
    -> Direct-route policy (reviewed trace + verified URLs required)
    -> Run-selected Playwright or Browser Use workflow
```

When `YDC_API_KEY` is absent or the You.com feature flags are disabled, provider
execution and fallback behavior remain unchanged. `OperationalResearch` has
additional backward-compatible optional fields (`login_url`,
`credential_management_url`, `credential_creation_instructions`,
`operational_url_claims`), so serialized payloads may contain additional null or
empty fields.

## SDK: pinned and verified (`youdotcom==2.4.0`)

Pinned in `requirements-providers.txt`. The relevant surface was verified by
installing the package and inspecting real signatures (`tests/test_you_research.py::TestSdkContract`
asserts these and fails loudly on a future upgrade):

* `search_post_async(query, count, include_domains=list[str], safesearch, retries, timeout_ms, ...)`
  — the POST variant carries domain lists as a JSON array of **bare** domains.
* `contents.generate_async(urls, formats=[ContentsFormats.MARKDOWN], crawl_timeout, max_age, retries, timeout_ms)`
  — `max_age` is a real request parameter.
* `research_async(input, research_effort, source_control=SourceControl(include_domains=...), output_schema, retries, timeout_ms)`
  — returns `output.content` (structured when `output_schema` is used) and
  `output.sources` (cited `[{url,title,snippets}]`).
* The `You` client supports `async with` cleanup (no `close()` method); it is
  always used as a context manager.
* Every call auto-retries by default; we pass ONE explicit bounded `RetryConfig`.

> Historical note: releases **before 2.4.0** (e.g. 2.2.0/2.3.0) did NOT expose
> `include_domains`, `max_age`, or Research `source_control`/`output_schema`.
> 2.4.0 is the pinned baseline precisely because it does.

## Exact vs. wildcard host semantics

`OfficialURLPolicy` distinguishes three host classes:

* **exact_hosts** — matched only as themselves. `developers.example.com` does
  NOT grant `anything.developers.example.com`.
* **wildcard_domains** — matched as **subdomains only**, identical to
  `ops.browser_host_policy.host_matches_patterns`: a `*.parent` entry does
  **not** permit the bare `parent` root.
* **legacy official_hosts** (original positional arg) — retains the historical
  exact-or-subdomain behavior for pre-existing callers, unchanged.

`ResearchHostPolicy` builds its trusted set from ONLY: the verified P1 record's
`primary_docs_url`/`evidence_urls` and the baseline's developer/signup hosts
(as **exact** hosts), plus the reviewed `ops.browser_host_policy`
`exact_hosts`/`vendor_wildcard_domains` (the sole source of wildcard breadth). A
search result can never approve its own novel host.

## Provider `include_domains` + local validation

Search sends `include_domains` (bare domains; a reviewed `*.pipedrive.com`
becomes `pipedrive.com`) as a **first-pass provider filter**. That is not a
security boundary: every returned result is still re-validated locally by
`ResearchHostPolicy.validate_candidate_url` against the exact/wildcard rule, and
off-policy results are dropped. `exclude_domains`, `boost_domains`, `livecrawl`,
and news results are not used.

## Persistent cache

`ops/research_cache.py::SqliteResearchCache` (WAL, thread-safe, transactional,
TTL, bounded payloads) is shared by Search/Contents/Research and wired through
`RunService`. Keys: `you-search:v2:<hash>`, `you-contents:v2:<hash>`,
`you-research:v2:<hash>`, and `operational-research:v2:<hash>`. TTLs: Search
24h, Contents and fully validated operational-research results =
`YOU_CONTENTS_MAX_AGE_SECONDS`, Research 7d. A per-key lock provides
**single-flight**: concurrent identical requests collapse to one provider call.
Only validated, bounded, public projections are cached — never keys,
credentials, headers, private URLs, OTPs, prompts, or raw provider errors/bodies.
A cached operational result includes the evidence documents needed to rerun the
same identity, current host-policy, and field-level URL-claim checks; a corrupt,
expired, or newly off-policy row is a miss.

## Call budgets

Enforced per enrichment: Search ≤ `YOU_MAX_SEARCH_CALLS_PER_ENRICHMENT`
(default 2), `count` ≤ 10; Contents one batch ≤
`YOU_MAX_CONTENTS_PAGES_PER_ENRICHMENT` (default 8, hard cap 10); Research ≤ 1
call and only when `you_research_configured` (which additionally requires the
per-enrichment budget > 0).

## Single retry layer

The SDK's own retry is configured with one explicit bounded `RetryConfig`
(429/500/502/503/504 + connection errors, ~20s max elapsed, jittered); no
custom retry loop wraps it. Client 4xx (400/401/402/403/404/422) never retry.
An outer `asyncio.wait_for` bounds total time and the final error is mapped to a
sanitized reason code.

## Research fallback condition

Research runs when it is configured AND official hosts exist AND candidate
category coverage is **insufficient** — not only when zero documents were
fetched. It only ADDS candidate pages (validated: each must appear in
`output.sources`, pass the host policy, and classify into the allowed enum) for
the SAME single Contents + Gemini path. Research never populates an
`OperationalResearch` field directly. Effort is `standard`; `deep`/`exhaustive`/
`frontier`/`background` are never used.

## Field-level operational-URL evidence

For each operational URL the extractor outputs that does not exactly reaffirm
the verified baseline, a matching `OperationalUrlClaim` must exist whose `field`
matches, whose `url` matches, whose `source_url` is a page we actually fetched,
whose cited source's text literally contains the exact URL, and whose URL passes
the host policy. A URL merely appearing in *some* document is not enough.

Fetched evidence text is **untrusted**: the Gemini prompt instructs the model to
never obey instructions inside evidence. Fetched Markdown is normalized only
(newlines, control chars, length bound) — never mutated by an injection regex,
which would be both a false sense of safety and a risk of corrupting real facts.

## Safe feature defaults

All three capabilities default to **disabled** — a configured key alone never
spends credits. Staged rollout: enable `YOU_SEARCH_ENABLED`, then
`YOU_CONTENTS_ENABLED`, then (only after evaluation) `YOU_RESEARCH_ENABLED`. A
local `.env` may enable them deliberately.

| Env var | Default | Notes |
|---|---|---|
| `YDC_API_KEY` | unset | server-side only; required by every flag below |
| `YOU_SEARCH_ENABLED` | `false` | Stage 1 |
| `YOU_CONTENTS_ENABLED` | `false` | Stage 2 |
| `YOU_RESEARCH_ENABLED` | `false` | Stage 3 |
| `YOU_SEARCH_COUNT` | 5 | 1–10 |
| `YOU_MAX_SEARCH_CALLS_PER_ENRICHMENT` | 2 | 1–4 |
| `YOU_MAX_CONTENTS_PAGES_PER_ENRICHMENT` | 8 | 1–10 |
| `YOU_MAX_RESEARCH_CALLS_PER_ENRICHMENT` | 1 | 0–1 (0 disables Research) |
| `YOU_CONTENTS_MAX_AGE_SECONDS` | 86400 | sent to Contents + local cache TTL |
| `RESEARCH_CACHE_DB_PATH` | `./private/research_cache.db` | persistent cache |

## Bounded pre-warming command

`python scripts/warm_you_research.py` enumerates only the immutable verified P1
snapshot and constructs the same `RunService` enrichment wiring used at runtime.
It is **dry-run by default**: no You.com, Gemini, browser, Gmail, or vendor call
is made without `--execute`.

```bash
python scripts/warm_you_research.py --all
python scripts/warm_you_research.py --app-slug pipedrive --execute
python scripts/warm_you_research.py --all --execute --limit 5 --concurrency 2
python scripts/warm_you_research.py --all --execute --continue-on-error \
  --output-summary private/you-url-coverage.json
```

The command accepts `--app-slug` or `--all`, `--execute`, `--limit`,
`--concurrency` (maximum 5), `--force-refresh`, `--max-age-seconds`,
`--continue-on-error`, and `--output-summary`. It reports only each app slug,
sanitized result code (`cache_hit`, `enriched`, `skipped`, or `failed`), missing
field names/count, verified-claim count, evidence-backed public operational URLs,
route, reviewed-trace status, and coverage status. The JSON report also contains
aggregate coverage counts. Fresh fully validated results are reused until their
normal TTL expires; `--force-refresh` bypasses reads for that one invocation but
writes refreshed values under the same normal cache keys.

Live browser execution is fail-closed: self-service and hybrid routes require a
reviewed trace plus verified `login_url` and `credential_management_url`. The
first 25 P1 apps currently have reviewed traces; the other 75 remain research-only
until a trace is reviewed. Existing-account sessions open the verified login URL,
then the verified credential-management URL after authentication. Research URLs
never expand the static browser host allowlist.

Run creation accepts immutable `credential_creation_policy` values `reuse_only`
and `create_if_missing`. API and CLI omission defaults to `reuse_only`; the web
form explicitly defaults to `create_if_missing`. Any trace checkpoint marked
HITL remains human-authorized under either policy, including every currently
reviewed irreversible create/generate checkpoint.

## Error handling

Sanitized reason codes only (`map_you_error`): `*_invalid_request` (400/422 non-
research), `*_unauthorized` (401), `*_credit_exhausted` (402), `*_forbidden`
(403), `*_not_found` (404), `you_research_invalid_schema` (422 research),
`*_rate_limited` (429), `*_timeout`, `*_failed`. Never exposes the API key,
Authorization header, full query, full document, provider body, or raw exception
text. Programming errors (`TypeError`/`AttributeError`/`ImportError`/…) are never
degraded to a provider outage — they propagate to monitoring/tests and may
surface as a sanitized HTTP 500.

## Observability (metrics)

One `YouResearchMetrics` per enrichment (via a contextvar) records call counts,
latencies, results returned/accepted, cache hits/misses, and
`discovery_provider_used` (a real provider name: `you_search`,
`you_search+perplexity`, etc. — never a capability reason code). It is attached
to `ResearchEnrichmentOutcome.provider_metrics` and included in the
`operational_research_enriched` audit event. Never contains query text,
snippets, page content, headers, or the key.

## Operator diagnostics

```
python -m ops.cli research-app "Pipedrive" --provider you   # production pipeline: Search -> Contents -> guarded HTTP
python -m ops.cli research-app "HubSpot"   --provider auto  # + Perplexity discovery fallback
python -m ops.cli probe-you                                 # one explicit, cheap Search reachability call
```

`research-app` shows only app name/slug, provider used, approved domains,
candidate public URLs + categories, fetched document URLs + titles, latencies,
real cache hits/misses, and missing baseline fields. Never a key, full snippet,
full Markdown, provider body, credential, cookie, or vault value.

## Testing

* `tests/test_you_research.py` — SDK contract (2.4.0), host policy (exact vs.
  wildcard, sensitive query, private-DNS), config, ranking/coverage, Search,
  composite, Contents, error mapping, Research fallback, missing fields,
  operational-URL claims, enricher flow, persistent cache (persistence,
  expiry, corrupt-payload, single-flight), browser boundary.
* `tests/test_you_eval.py` + `ops/you_eval.py` + `tests/fixtures/you_eval_dataset.json`
  — offline evaluator over reviewed fixtures.
* Opt-in live evaluators (disabled by default, no browser):
  * `RUN_LIVE_YOU_TESTS=1 pytest tests/live/test_you_discovery_live.py`
  * `RUN_LIVE_YOU_CONTENTS_TESTS=1 pytest tests/live/test_you_contents_live.py`
  * `RUN_LIVE_YOU_RESEARCH_TESTS=1 pytest tests/live/test_you_research_live.py`

## Live-test procedure (bounded)

Run with browser and email live actions OFF (You.com research never starts a
browser):

```
ALLOW_LIVE_BROWSER=false ALLOW_LIVE_VENDOR_EMAIL=false \
YOU_SEARCH_ENABLED=true YOU_CONTENTS_ENABLED=true YOU_RESEARCH_ENABLED=false \
RUN_LIVE_YOU_TESTS=1 python -m pytest tests/live/test_you_discovery_live.py -q -s
```

Budgets: discovery ≤ 3 apps × ≤ 2 queries × count 3 (≤ 6 calls); Contents ≤ 3
URLs, one batch; Research one call at `standard` effort.

## Security boundaries (unchanged)

The legacy `browser_provider` default remains `browser_use`, while the website
sends an explicit per-run selection. `ops/browser_host_policy` allowed_domains
come only from the reviewed static dataset — never from `OperationalResearch`
fields — so no You.com/Perplexity/Research result can expand a browser
allowlist. You.com never receives a credential, OTP, cookie, or vault value, and
is never used to bypass CAPTCHA/MFA.
