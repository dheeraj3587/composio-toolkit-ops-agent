# Bootstrap decisions

These decisions apply to the secure runnable Phase 0/1 foundation created on 2026-07-22.

## Repository location

The approved local repository is
`/Users/dheerajjoshi/Desktop/composio-toolkit-ops-agent`, overriding the original sibling path under
`/Users/dheerajjoshi`. Hard-coded P2 paths in `PLAN.md` use the Desktop location. The P1 source
repository remains `/Users/dheerajjoshi/composio` and is not modified.

## Secure runnable depth

The first deliverable includes the Phase 0/1 security core plus a local dry-run CLI and early
Streamlit shell. This intentionally goes beyond the plan's bootstrap-only first commit and brings a
non-provider UI forward from Phase 7. The shell is an operations ledger, not a simulation of future
provider success: it exposes unavailable phases explicitly and contains no browser, email, model,
or paid API integration.

## P1 snapshot-only boundary

Only `out/results.json` and `out/composio_coverage.json` were copied from P1. Their source commit,
copy time, and SHA-256 digests are recorded in `data/p1/SNAPSHOT.json`. No P1 code, report assets,
hand-check material, transcripts, or meeting documents are included. Phase 0/1 never mutates or
operationally enriches these canonical files.

## Work-email reference correction

`.env.example` uses `COMPANY_WORK_EMAIL_REF` rather than the plan's plaintext
`COMPANY_WORK_EMAIL`. This aligns environment configuration with `CompanyProfile.work_email_ref`
and the non-negotiable rule that company/account credentials cross general application code only as
exact `vault://...` references.

## Provider isolation

Provider-facing modules remain typed, injectable boundaries even after the real SDK adapters were
introduced. Importing the application, running normal tests, starting the UI, or creating a run does
not itself authorize a paid/network side effect. A missing key, connected account, encrypted
checkpoint key, live-browser flag, or controlled email recipient produces a typed
configuration-required state. Live tests additionally require `RUN_LIVE_TESTS=1`; fixture and fake
adapter tests are never reported as live-provider evidence.

## Dependencies and deployment

The runtime set retains the versions locked in `PLAN.md` except for Pydantic. The resolver confirmed
that `composio==0.18.0` requires `pydantic>=2.13.4`, which conflicts with the plan's
`pydantic==2.12.5`; the project therefore uses the smallest compatible exact pin,
`pydantic==2.13.4`. Direct dependencies are split by trust boundary: `requirements.txt` contains the
secure core, API, CLI, and internal UI; `requirements-providers.txt` contains LangGraph and external
provider SDKs; `requirements-dev.txt` composes both with verification tools; and
`requirements-api.txt` composes the complete container runtime. `httpx==0.28.1` is an explicit core
pin because the enrichment/validation boundaries use it and every installed provider supports the
same release. `httpx2==2.7.0` remains a development-only dependency because the installed
Starlette `1.3.1` test client imports it explicitly; production provider clients continue to use
`httpx==0.28.1`.

The 2026-07-23 dependency audit reported `PYSEC-2026-1845` against the installed `pytest==8.4.2`;
the first published fixed version is `9.0.3`. `requirements-dev.txt` therefore moves only the pytest
development range from `>=8.4,<9` to `>=9.0.3,<10`. The advisory is not suppressed, and the complete
test suite must pass on pytest 9 before delivery.

Transitive locking remains deferred until a complete configured integration run, as directed by the
plan. Container definitions use unprivileged users and owner-only `/private` state; image-build
verification remains deferred because Docker is unavailable locally.

## Phase 2 snapshot adapter and routing

Phase 2 consumes only the copied P1 snapshot. The adapter pins the expected P1 repository, commit,
results digest, and coverage digest in code as a second trust anchor; it verifies those values and
both files before parsing the exact 19-field contract. Lookups use exact normalized,
case-insensitive app names or slugs and return a typed `found` or `not_found` result. There is no
fuzzy matching and no fallback network research in this phase.

P1 fields map into `OperationalResearch` only where a canonical fact exists. Missing signup,
developer portal, API base, OAuth endpoints, scopes, credential fields, contacts, and production
approval facts remain `None` or empty rather than being guessed. P1's access classification is an
evidence-derived routing input. Deterministic operational facts take priority, with the P1 route
used only when no stronger signal contradicts it. An unknown result permits one injected enrichment
probe and then terminates as a final unknown result.

## Product API and frontend

`ops/` remains the domain and security core. `api/` is a FastAPI transport boundary with strict
sanitized response models and no vault endpoints. `web/` is a Next.js 16, React 19, TypeScript,
Tailwind, and shadcn/ui product surface. The Next.js server is the only frontend tier that knows
`OPS_API_URL`; the variable is deliberately not public and no sensitive state is stored in browser
storage. The Streamlit application remains a trusted internal debugging ledger rather than the
primary product UI.

The HTTP API exposes app search/research, run create/list/detail/timeline, resume, polling, retry,
output, and health routes. External actions return explicit typed configuration-required or
unavailable responses until their exact evidence exists. API schema and documentation endpoints are
available only when `OPS_ENABLE_API_DOCS=true` for local development; containers force them off.
CORS origins come only from the explicit `OPS_CORS_ORIGINS` environment allowlist. Responses use
no-store and restrictive security headers, and neither environment values nor database/vault paths
are part of a response contract.

## Container runtime boundary

FastAPI and Next.js have separate production-oriented container definitions. Next.js uses official
standalone output; both processes run unprivileged. Compose publishes only on `127.0.0.1`, drops
capabilities, uses read-only root filesystems, and keeps API state in a private named volume. These
controls do not provide application authentication. API, dashboard, and Streamlit must remain on a
trusted host or behind an authenticated private-access layer.

Docker is unavailable on the development Mac. The Dockerfiles and Compose configuration are
included and statically reviewed, but image builds, container health checks, and Compose startup are
truthfully deferred until a Docker-capable environment is available.

Compose deliberately does not interpolate provider credentials into its checked-in service
environment because `docker compose config` can render interpolated values. Production operators
must use their deployment platform's secret manager. The checked-in Compose service environment
sets API documentation, live Browser Use, live tests, and vendor email off, publishes only to
loopback, and adds init handling plus a bounded process count.

## Phase 2 runtime hardening

The Next.js boundary follows the installed Next.js 16 CSP guidance. It uses the documented static
policy so statically rendered routes remain cacheable; production excludes `unsafe-eval`, while
inline framework bootstrap code and generated styles require the documented `unsafe-inline`
allowances. Frame embedding, object sources, ambient browser permissions, referrers, MIME sniffing,
and DNS prefetching are disabled. Successful FastAPI envelopes are accepted only after strict Zod
validation, and malformed payloads fail closed as a generic gateway error without exposing rejected
data.

The npm install policy is deny-by-default through `strict-allow-scripts=true`. The one exact
allowlist entry, `unrs-resolver@1.12.2`, is required by the ESLint resolver and stays coupled to the
committed lockfile. New install scripts require an explicit review and exact allowlist entry; they
are not enabled transitively by package name alone.

Next's standalone server does not copy `public/` or `.next/static/` by itself. The build lifecycle
now assembles both into `.next/standalone`, so local `npm start` and the container run the same
complete artifact. The FastAPI image installs only `requirements-api.txt`; application code and the
P1 snapshot are root-owned and read-only, while `/private` is the sole application-owned writable
path. The Compose read-only root filesystem and `/tmp` tmpfs remain defense-in-depth controls.

## Delivery automation and live-test policy

The GitHub Actions workflow has independent backend/security and frontend jobs. The backend job uses
Python 3.11, installs the complete development/provider set and local Playwright Chromium, runs
Ruff, non-live pytest, strict mypy, compileall, detect-secrets enforcement, dependency auditing, and
the targeted credential-pattern scan. The frontend job uses Node.js 22 and the committed npm
lockfile, then runs the dependency audit, ESLint, TypeScript, tests, and production build. Both jobs
run without provider credentials; the backend job forces `RUN_LIVE_TESTS=0`,
`ALLOW_LIVE_BROWSER=false`, and `ALLOW_LIVE_VENDOR_EMAIL=false`.

The local `scripts/security_gate.sh` accepts `backend`, `frontend`, or its default `all` scope so CI
and developers use the same checks. `Makefile` commands are convenience wrappers only; they do not
change the security defaults or load secrets into command arguments. No successful fixture test is
treated as proof of email delivery, Browser Use completion, provider approval, credential capture,
credential validation, or integrator-bundle readiness.
