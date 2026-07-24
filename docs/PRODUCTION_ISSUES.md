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

**Verification:** 315 tests pass (offline‑safe suite; +5 new regression tests in
`tests/test_critical_fixes.py`), `ruff check` clean, and **no new mypy errors** versus the baseline.

## Remaining — High

| ID | Issue | Fix |
| -- | ----- | --- |
| H1 | `GmailWorker` is built without the secret store, so a reply carrying credentials throws `secret_store_missing` and the poller silently spins. | Pass `secret_store` / `effect_store` at construction. |
| H2 | Effective Browser Use cost cap is **$1** in prod (field default `50.0` vs `from_env` default `1.0`; env var not set in compose). | Fix the `from_env` default and set `BROWSER_USE_MAX_COST_USD` in the prod env. |
| H3 | Owner controls 403 under the documented prod env default (`ALLOW_LOCAL_CREDENTIAL_SUBMISSION=false`). | Set it explicitly in `compose.prod.yaml` and document it as required. |
| H4 | Credential‑submit form is shown during `waiting_for_hitl`, but the backend requires `browser_running` → always 409. | Render the submit form only when `browser_running`. |
| H5 | Auto‑capture exists only for Pipedrive; validation only for HubSpot + Pipedrive. | Add per‑app capture specs + validation policies (see readiness matrix in the guide). |
| H6 | Mis‑sized AES/Fernet keys crash boot into a restart loop; a referenced deploy doc was missing. | Convert key‑format errors to a clear boot message; document key formats. |
| H7 | Deploys/SIGTERM strand runs (daemon threads not joined; no startup reconciliation). | Reconcile stale `browser_running`/`waiting_for_hitl` rows at startup. |
| H8 | `retry` is a stub; wedged runs and `outcome_unknown` ledger rows have no recovery path. | Implement real retry/reconcile for browser/email. |
| H9 | CI/security gate is red at HEAD (ruff‑format + pre‑existing mypy); `update-droplet.sh` deploys without the gate. | Green the gate and gate the deploy on it. |
| H10 | UI reads `SecurityState.checkpoint_encryption`, which the backend never sends → always "Not reported". | Emit the field (or drop the row). |

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
