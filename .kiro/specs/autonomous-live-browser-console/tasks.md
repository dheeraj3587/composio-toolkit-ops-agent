# Implementation Plan: Autonomous Live Browser Console

## Overview

This plan implements the embedded, auto-surfacing autonomous live console described in
`design.md` and specified in `requirements.md`. It is **gated** by two prerequisites that must
complete and pass before any embedding code is written: **Phase 0** reconciles local ↔ deployed
onto one source of truth, and **Phase 1** is the go/no-go iframe-embeddability live spike. Only
after both gates clear does the minimal CSP change, backend gate consolidation, route handler,
`EmbeddedLiveConsole` component, page wiring, contract reconciliation, tests, and the gated
live-smoke extension proceed.

Backend is Python (FastAPI + LangGraph + workers under `ops/` and `api/`); frontend is
TypeScript (Next.js app router under `web/`). All work **extends** existing abstractions
(live-view endpoint, `_require_owner_action`, `resumeWithBrowserLogin`, `HitlLiveControls`,
browser worker) rather than adding parallel routers/gates/workers, per `AGENTS.md`.

Tasks marked `*` are optional test/verification sub-tasks. Sub-tasks marked
**[LIVE — requires explicit user authorization]** perform live provider actions and must run only
with explicit authorization plus `RUN_LIVE_TESTS=1` and `ALLOW_LIVE_BROWSER`; a coding agent must
not execute them autonomously.

## Tasks

- [ ] 1. Phase 0 (GATING) — Source-of-truth reconciliation
  - [ ] 1.1 Land the deployed hot-patches as reviewed commits on `main`
    - Diff the VPS working tree against the repo and commit each hot-patch with review: `BrowserLoginInput` + `ResumeRequest.browser_login` (`api/models.py`); resume `browser_login` handling + owner gate (`api/app.py`); `browser_login → login_email/login_password` mapping (`api/service.py`); `run_service.resume_run` `sensitive_data` inject/clear (`ops/run_service.py`); per-thread `sensitive_data` (`ops/graph.py`); `sensitive_data` + `login_fields` task rendering (`ops/browser_worker.py`, `api/assignment_runtime.py`); `_require_owner_action` superseding `_require_owner_live_view`; loopback-only reveal endpoint; frontend `resumeWithBrowserLogin`, `submitBrowserLoginAction`, sign-in form, and `execute_when_configured` default
    - Confirm no secret or `live_url` appears in any committed diff
    - GATING: all later tasks depend on this reconciled base
    - _Requirements: 12.1, 12.4_
  - [ ] 1.2 Bring the local workspace onto reconciled `main`
    - Rebase/merge `fix/live-ten-app-execution` onto reconciled `main`, or branch fresh from it, so local and deployed contracts are identical
    - GATING
    - _Requirements: 12.2_
  - [ ]* 1.3 Run the offline-safe parity suite
    - Run `ruff`, `mypy`, and `pytest` on the reconciled base and confirm green
    - _Requirements: 12.3, 13.2_
  - [ ]* 1.4 Run the gated live parity smoke **[LIVE — requires explicit user authorization]**
    - With `RUN_LIVE_TESTS=1` + `ALLOW_LIVE_BROWSER` + explicit authorization: execute run reaches `browser_running`/`waiting_for_hitl`; `GET /live-view` → `200` + `live_url` via the web-container path; resume-with-`browser_login` passes the owner gate (`200`)
    - _Requirements: 12.3_
  - [ ]* 1.5 Secret-scan the reconciled tree
    - Run `detect-secrets` and `git grep` for credential/`live_url` patterns; confirm nothing sensitive is committed
    - _Requirements: 12.4_

- [ ] 2. Phase 1 (GATING) — iframe-embeddability spike (go/no-go)
  - [ ] 2.1 Author the spike harness and production-CSP test page
    - Add a throwaway harness (e.g., under `scripts/`) that serves a page with the **exact** production CSP behind Caddy, including `frame-src 'self' https://live.browser-use.com`, and frames a real `live_url`
    - Gate the harness so it refuses to run without `RUN_LIVE_TESTS=1`, `ALLOW_LIVE_BROWSER`, and explicit authorization
    - GATING: the embedding approach is not chosen until this spike returns a decision
    - _Requirements: 11.1, 11.2_
  - [ ]* 2.2 Run the spike, record headers, and record the go/no-go decision **[LIVE — requires explicit user authorization]**
    - Start a real session, load the `live_url` in the harness, confirm the frame renders and accepts typed input; capture the viewer's `X-Frame-Options` and `Content-Security-Policy: frame-ancestors` headers into spike notes
    - Record the decision: proceed with iframe, or trigger the fallback ladder (same-origin proxy → CDP screencast reusing `run_trusted_raw_browser` → degraded panel)
    - _Requirements: 11.2, 11.3, 11.4, 11.5_

- [ ] 3. Checkpoint — parity confirmed and embedding decision recorded
  - Ensure all offline tests pass and the go/no-go decision is documented; ask the user if questions arise.

- [ ] 4. Minimal CSP change
  - [ ] 4.1 Add the single `frame-src` directive in `web/next.config.ts`
    - Add `frame-src 'self' https://live.browser-use.com` to the CSP array; leave `frame-ancestors 'none'`, `X-Frame-Options: DENY`, and all other directives unchanged; make no Caddy or API CSP change
    - _Requirements: 9.1, 9.2, 9.3, 9.4_
  - [ ]* 4.2 Write property test for CSP framing
    - **Property 6: Minimal framing relaxation**
    - Assert `frame-src` equals exactly `{'self', https://live.browser-use.com}` and that `frame-ancestors 'none'` is retained
    - **Validates: Requirements 9.1, 9.2**

- [ ] 5. Backend gate consolidation and contract confirmation
  - [ ] 5.1 Consolidate the owner gate in `api/app.py`
    - Ensure `_require_owner_action` (superseding `_require_owner_live_view`) guards both live-view and resume-with-`browser_login`; keep `_require_local_owner_submission` (loopback-only) guarding `submit_credentials` and `reveal_credentials`; do not add parallel gates
    - _Requirements: 6.1, 6.2, 10.3, 10.4, 10.5_
  - [ ] 5.2 Confirm request/response schemas in `api/models.py`
    - Confirm `ResumeRequest{signal, browser_login?}` with `extra="forbid"` and defaults (empty `{}` valid); `LiveViewResponse{run_id, available, live_url?}`; `HitlRequestView{action_type, message, expected_completion_signal, resumable}`; confirm resume conflict (`409`) semantics are exposed
    - _Requirements: 6.1, 6.2, 6.3, 7.5_
  - [ ]* 5.3 Write backend unit tests for gate and contracts
    - `_require_owner_action` returns `200` for loopback/internal-token and `403` otherwise; `ResumeRequest` accepts valid fields, forbids unknown keys, and accepts empty `{}`; `browser_login` maps to `login_email`/`login_password`; resume when not waiting returns `409`
    - _Requirements: 6.2, 6.3, 7.5, 10.3, 10.4_
  - [ ]* 5.4 Write property test for signed live URL non-persistence (backend)
    - **Property 1: Signed live URL is never persisted**
    - For any sequence of live-view fetches, assert `live_url` is absent from run state, checkpoints, the audit ledger, and logs, and that `available:false` is returned when the worker has no session
    - **Validates: Requirements 8.1, 8.6, 10.1**
  - [ ]* 5.5 Write property test for autonomous-login credential handling
    - **Property 2: Autonomous-login credentials are never persisted or read by the LLM**
    - For any `resume` carrying `browser_login`, assert values are injected as `sensitive_data`, cleared after one resume, absent from state/checkpoints/ledger/logs, and absent from LLM-visible task text (placeholders present instead)
    - **Validates: Requirements 3.2, 3.3, 3.4, 10.2**
  - [ ]* 5.6 Write property test for session continuity across HITL
    - **Property 3: Same session across HITL**
    - For any run that pauses at `waiting_for_hitl` and resumes, assert the same `session_id`/`thread_id` is reused (mock worker) so no new session is created
    - **Validates: Requirements 8.4, 8.5**

- [ ] 6. Frontend live_url route handler
  - [ ] 6.1 Create `web/src/app/runs/[runId]/live-view/route.ts`
    - Implement `GET` that calls `getLiveView` server-side (injecting the internal token) and returns `{available, live_url?}`; set `Cache-Control: no-store`; never log the `live_url`
    - _Requirements: 6.1, 8.2_
  - [ ]* 6.2 Write unit test for the route handler
    - Assert response shape `{available, live_url?}`, `no-store` header, and that the `live_url` is never written to logs (supports Property 1)
    - _Requirements: 8.2_

- [ ] 7. Reconcile `api.ts` / `actions.ts` and fix stale copy
  - [ ] 7.1 Reconcile `web/src/lib/api.ts`
    - Confirm/align `getLiveView` (8s), `resumeWithBrowserLogin` (180s), `performPhaseAction("resume"|"cancel")` (180s), and `submitCredentials`; preserve the synchronous 180s bound for resume paths
    - _Requirements: 6.1, 6.2, 6.4_
  - [ ] 7.2 Reconcile `web/src/app/runs/[runId]/actions.ts` and fix stale copy
    - Confirm `openLiveView`, `submitBrowserLoginAction`, `runPhaseAction`, `submitCredentialAction`; replace the stale "restricted to the owner on localhost" message with owner-only wording
    - _Requirements: 3.1, 5.3, 6.5, 7.3_
  - [ ]* 7.3 Write unit tests for `api.ts`/`actions.ts`
    - Assert `resumeWithBrowserLogin` posts `{signal:"completed", browser_login:{email,password}}` with the 180s bound; `LiveViewResponse` parses; the stale copy is gone and owner-only copy is present; `403` surfaces the owner-only message
    - _Requirements: 3.1, 6.4, 6.5, 7.3_

- [ ] 8. EmbeddedLiveConsole client component
  - [ ] 8.1 Create `web/src/components/embedded-live-console.tsx`
    - Poll the route handler for `live_url` on mount and on an interval while non-terminal; keep the URL only in ephemeral React state (never `localStorage`/`sessionStorage`)
    - Render a **stable-src** `<iframe src={liveUrl}>` that updates only when the value changes, so `router.refresh()` does not remount/reload it
    - Render reconnect/degraded UI when `available:false`, and a degraded panel (owner-only link) when the frame load fails
    - Render the HITL `action_type` + `message`, and select the inline control by `action_type`: sign-in form for `provider_verification`/`account_selection`; "I completed it — resume" for the human-only gates; Cancel always available; include the password-coarseness copy for `provider_verification`
    - Implement the sign-in form with `type=password`, autocomplete disabled, clearing the fields from the DOM after handoff to `submitBrowserLoginAction`
    - _Requirements: 1.1, 1.2, 1.3, 1.4, 2.4, 3.1, 3.5, 4.1, 5.1, 5.2, 5.3, 5.4, 5.5, 7.1, 7.2, 7.6, 8.3, 8.7_
  - [ ]* 8.2 Write property test for auto-surface matching backend state
    - **Property 4: Auto-surface matches backend state**
    - For any status and `plan_only` flag, assert the console renders (and begins polling) iff `status ∈ {browser_running, waiting_for_hitl}` and not `plan_only`, and stops polling/unframes for any terminal status
    - **Validates: Requirements 1.1, 2.1, 2.3, 2.5**
  - [ ]* 8.3 Write property test for inline control matching the gate
    - **Property 5: Inline control matches the gate**
    - For any `waiting_for_hitl` `action_type`, assert the sign-in form is shown iff `action_type ∈ {provider_verification, account_selection}`, a plain resume otherwise, and Cancel is always present
    - **Validates: Requirements 5.1, 5.2, 5.3**
  - [ ]* 8.4 Write unit tests for console branches
    - `<iframe>` shown iff `available`; degraded panel on frame load error; `src` stable across `router.refresh()` (no remount); repeated identical `live_url` does not reload; timeout error surfaced; `409` reconciled via refresh
    - _Requirements: 2.4, 7.1, 7.2, 7.5, 7.6, 7.7, 8.7_

- [ ] 9. Wire EmbeddedLiveConsole into the run page
  - [ ] 9.1 Replace the manual mount in `web/src/app/runs/[runId]/page.tsx`
    - Render `<EmbeddedLiveConsole>` when `status ∈ {browser_running, waiting_for_hitl}` and not `plan_only`, replacing the manual `<HitlLiveControls>`/"Get live browser link" mount; keep `<RunAutoRefresh>` soft-refreshing while non-terminal; ensure no `live_url` is placed in the server-rendered HTML/RSC payload
    - _Requirements: 1.1, 1.4, 2.1, 2.2, 2.3, 2.5_
  - [ ]* 9.2 Write test for frontend non-persistence of `live_url`
    - **Property 1: Signed live URL is never persisted** (frontend portion)
    - Assert the server-rendered page/RSC payload contains no `live_url` and that no client storage API receives it
    - **Validates: Requirements 8.1, 8.3, 10.1**
  - [ ]* 9.3 Write render test for status-driven surfacing on the page
    - Assert the page mounts the console for active statuses and not for `plan_only`/terminal, and that `RunAutoRefresh` schedules refresh only while non-terminal
    - _Requirements: 2.1, 2.2, 2.5_

- [ ] 10. Checkpoint — offline-safe suite green
  - Ensure all offline-safe unit and property tests pass (backend + frontend, including CSP and no-persistence checks); ask the user if questions arise.

- [ ] 11. Gated live wiring proof
  - [ ] 11.1 Extend `scripts/live_smoke.py` with the wiring-correctness steps
    - Add steps that create an `execute` run; wait for `browser_running`/`waiting_for_hitl`; assert `GET /live-view` → `200` + `live_url` via the web-container path; assert `POST /resume` with `browser_login` passes the owner gate (`200`); assert the status advances; keep the harness gated on `RUN_LIVE_TESTS=1` + `ALLOW_LIVE_BROWSER`
    - _Requirements: 13.1, 13.3_
  - [ ]* 11.2 Run the gated live smoke **[LIVE — requires explicit user authorization]**
    - Execute the extended smoke with explicit authorization + flags; confirm the end-to-end path is coherent on the real backend
    - _Requirements: 12.3, 13.3_

- [ ] 12. Manual acceptance documentation
  - [ ] 12.1 Author the manual acceptance checklist
    - Write a checklist doc for the human-observed acceptance: with the embed live, complete a real OTP inside the frame, click "I completed it — resume", and confirm the agent continues in the same session with no new tab opened; note that this step is manual and requires authorization, and that the frontend claims must match verified behavior per `AGENTS.md`
    - _Requirements: 13.4, 13.5_

- [ ] 13. Final checkpoint
  - Ensure all offline tests pass, the gated live proof is recorded, and the feature is integrated through the public API and truthfully represented in the frontend; ask the user if questions arise.

## Notes

- Tasks marked `*` are optional test/verification sub-tasks and can be skipped for a faster path; core implementation tasks are never optional.
- Sub-tasks tagged **[LIVE — requires explicit user authorization]** (1.4, 2.2, 11.2) must not be run autonomously; they require explicit authorization plus `RUN_LIVE_TESTS=1` and `ALLOW_LIVE_BROWSER` per `AGENTS.md`.
- **Phase 0 (task 1)** and **Phase 1 (task 2)** are gating: no embedding code (tasks 4+) begins until reconciliation parity is confirmed and the go/no-go decision is recorded.
- Each property test references a Correctness Property from `design.md` and the requirements clause it validates; property tests use a minimum of 100 iterations.
- Deployment/redeploy is out of scope as a coding task; only the code and gated verifications needed to prove wiring are included.
- All work extends existing abstractions; no parallel routers, gates, or workers are introduced.

## Task Dependency Graph

```json
{
  "waves": [
    { "id": 0, "tasks": ["1.1"] },
    { "id": 1, "tasks": ["1.2", "1.5"] },
    { "id": 2, "tasks": ["1.3", "1.4"] },
    { "id": 3, "tasks": ["2.1"] },
    { "id": 4, "tasks": ["2.2"] },
    { "id": 5, "tasks": ["4.1", "5.1", "5.2", "7.1", "7.2"] },
    { "id": 6, "tasks": ["4.2", "5.3", "5.4", "5.5", "5.6", "6.1", "7.3", "11.1"] },
    { "id": 7, "tasks": ["6.2", "8.1"] },
    { "id": 8, "tasks": ["8.2", "8.3", "8.4", "9.1"] },
    { "id": 9, "tasks": ["9.2", "9.3", "11.2", "12.1"] }
  ]
}
```
