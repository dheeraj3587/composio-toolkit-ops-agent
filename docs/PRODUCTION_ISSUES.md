# Production Issues Report

**Target:** `https://composio.dheerajjoshi.dev` · **Reviewed at:** `origin/main` · **Method:** live
probe + code audit + spot‑verification.

This report inventories production issues by severity, records the fixes shipped in this change, and
lists what remains. It is a companion to [`GUIDE.md`](./GUIDE.md).

## Live deployment observations

- The site is **up**: `GET /healthz` → `200`.
- Every other route (UI and API) is behind **Caddy Basic Auth** (`401 restricted`); the FastAPI
  service is **not** publicly exposed. This is a strong posture, and it means functional findings
  below are derived from a code audit of the deployed revision, not black‑box probing.

## Summary

The platform posture is strong (single hardened Caddy ingress, token‑gated non‑public API, read‑only
non‑root containers, reference‑only Fernet vault, disciplined redaction — no active secret leak
found). The issues were in the product flow and operational robustness. **The three critical,
flow‑breaking issues are now fixed** (below); a set of high/medium items remain and are tracked for
follow‑up.

## Fixed in this change ✅

### C1 — Obtained credential now has a documented, secure path to the developer
Raw credential values are, by design, revealable only over the api container's **loopback**
interface (never across the network). That path was undocumented and had no tooling. Added
[`scripts/reveal-credential.sh`](../scripts/reveal-credential.sh), which performs the reveal from the
host inside the `api` container over `127.0.0.1`, plus [§15 of the guide](./GUIDE.md#15-obtaining-a-captured-credential).
The deliberate loopback‑only security gate is **unchanged** (a browser‑UI reveal would be a separate,
explicit decision).

### C2 — Email/gated credential path no longer dead‑ends
`poll_email` previously left a run at a terminal `credentials_ready` with no forward action (only the
browser‑path submit could complete it), so gated runs that received credentials by email were stuck
and the UI polled forever. `poll_email` now advances through the two legal hops
(`… → credentials_ready → completed`) and merges the emailed `vault://` references into the
reference‑only bundle. *(`ops/run_service.py`)*

### C3 — Paused HITL runs now survive an api restart
The Browser Use **provider** session id was written to graph state under
`browser_provider_session_id` but was not declared in `OperationsState`, so LangGraph dropped it from
the encrypted checkpoint; after any restart/redeploy a paused `waiting_for_hitl` run failed to resume
(`provider_session_missing`) and lost its live view. The key is now a declared, persisted state
field. *(`ops/state.py`)*

**Verification:** the full offline‑safe suite passes (**320 tests**, incl. new regressions in
`tests/test_critical_fixes.py` and `tests/test_high_severity_fixes.py`), and the quality gate is
green — `ruff check`, `ruff format --check`, and strict `mypy` all pass.

## Also fixed in this change ✅ (high severity)

- **H1** — `GmailWorker` is now built with the encrypted vault + effect ledger, so a reply carrying a
  credential is stored as a `vault://` reference instead of raising `secret_store_missing`.
- **H2** — the Browser Use cost cap now defaults to **$50** (config `from_env` + `compose.prod.yaml`
  + `.env.production.example`), ending the effective $1 mid‑task cutoff.
- **H3** — `ALLOW_LOCAL_CREDENTIAL_SUBMISSION` is surfaced in `compose.prod.yaml` and documented as
  required for owner actions.
- **H4** — the credential‑submit form is rendered only in `browser_running` (with a clear note
  otherwise), so it no longer 409s during `waiting_for_hitl`.
- **H6** — a malformed `SECRET_VAULT_KEY`/`LANGGRAPH_AES_KEY` now fails closed with a clear,
  value‑free log instead of crash‑looping the container.
- **H7** — startup reconciliation moves runs stranded at `browser_running` (navigation thread killed
  by a restart) to the recoverable `configuration_required`; resumable `waiting_for_hitl` runs are
  left intact.
- **H9** — the type/format gate is green: all 9 pre‑existing `mypy` errors fixed and `ruff format`
  applied. *(Gating `update-droplet.sh` on CI remains a follow‑up.)*
- **H10** — `SecurityState.checkpoint_encryption` is emitted (`ready` when the AES key is set), so
  the UI no longer misreports it.

## Remaining — High

| ID | Issue | Why deferred (needs a live environment, not a blind change) |
| -- | ----- | ---------------------------------------------------------- |
| H5 | Auto‑capture exists only for Pipedrive; validation only for HubSpot + Pipedrive. | Real per‑app capture specs require **live** verification of each app's settings URL, credential‑field selector, and validation endpoint. Fabricating them would be wrong and unsafe, so coverage is documented truthfully in the [readiness matrix](./GUIDE.md#14-application-readiness-matrix) and other apps use the manual‑submit path. |
| H8 | `retry` is a stub; wedged runs / `outcome_unknown` ledger rows have no automated recovery. | A correct retry must query the provider by receipt/idempotency key and re‑arm the ledger **without re‑emitting side effects** — this needs a reconciliation design and a live provider, so it is deferred rather than shipped as a blind, risky change. |

## Remaining — Medium / Low (abridged)

Session/credit leaks on the retained‑session path; `ops.db` write transaction held across network
I/O with a 5 s lock and no WAL; a global workflow lock that can make a synchronous resume exceed the
Caddy/web timeout; base `BrowserWorker` client reused across event loops; provider timeouts
classified as clean failures rather than outcome‑unknown; the assignment preflight rewriting a
Composio error into `custom_auth_or_approval_required` (weakening fail‑closed during an outage);
non‑quiesced, un‑gitignored backups with no restore script; cross‑run OTP/magic‑link injection;
redaction gaps for `otp`/`login_email` keys and JSON‑serialized log payloads; a deploy verify command
targeting an unreachable `/api` path; a too‑short submit timeout; poller treating recoverable
statuses as terminal; and a handful of schema‑drift / stale‑copy nits. None is an active secret leak.

## What's solid

Single Caddy ingress with Basic Auth on all routes but `/healthz`; token‑gated API never publicly
exposed; read‑only non‑root containers (`cap_drop: ALL`, `no-new-privileges`, tmpfs, 0700 volumes);
Fernet‑encrypted reference‑only credential vault; deterministic redaction; Gmail idempotency via the
effect ledger; graceful degradation to the verified P1 baseline on provider outage; `.env` untracked.
