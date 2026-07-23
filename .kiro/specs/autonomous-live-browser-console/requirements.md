# Requirements Document

## Introduction

This document specifies the requirements for the **Autonomous Live Browser Console**, derived
from and fully traceable to the approved design (`design.md`). The feature turns the run page
into a self-contained autonomous console: the Browser Use live session is embedded **inline**
as an interactive feed, the console **auto-surfaces** whenever a run is `browser_running` or
`waiting_for_hitl`, sign-in stays **autonomous** (the agent signs in using credentials the
operator supplies through our UI, injected as Browser Use `sensitive_data`), and the correct
inline control (sign-in form, "I completed it — resume", or Cancel) sits next to the feed. The
operator never leaves the run page.

The backend autonomous-login and live-view contracts already run on deployed `main` plus a set of
uncommitted VPS hot-patches, while the local workspace is behind. The work is therefore primarily
frontend embedding + auto-surfacing + coherent HITL UX, a small CSP change, a firm source-of-truth
reconciliation, and a gated go/no-go spike confirming the viewer can be framed under our production
CSP. Every security invariant from `AGENTS.md`/`PLAN.md` (no raw secret or signed live link across a
durable boundary; extend existing abstractions) must be preserved.

These requirements use user stories plus EARS-style acceptance criteria. Each requirement references
the design section it derives from, and the final section maps every design Correctness Property
(P1–P6) to at least one requirement.

## Glossary

- **Autonomous Live Console**: The run-page surface that embeds the live browser feed, the HITL prompt, and the inline controls; renders for `status ∈ {browser_running, waiting_for_hitl}` when not `plan_only`.
- **Embedded Live Console**: The Next.js client component (`web/src/components/embedded-live-console.tsx`) that renders the `<iframe>`, polls the live URL, shows reconnect UI, and selects the inline control by `action_type`.
- **Run Page**: The server component at `web/src/app/runs/[runId]/page.tsx`.
- **Run Auto Refresh**: The client component that soft-refreshes the Run Page (server re-render) on an interval while a run is non-terminal.
- **Live-View Route Handler**: The Next.js route handler `GET /runs/[runId]/live-view`, the client-pollable source of the live URL; injects the internal token server-side and returns `{available, live_url?}`.
- **Live-View Endpoint**: The FastAPI endpoint `GET /api/runs/{id}/live-view` returning `LiveViewResponse`.
- **Resume Endpoint**: The FastAPI endpoint `POST /api/runs/{id}/resume` accepting `ResumeRequest`.
- **Credentials Endpoint**: The FastAPI endpoint `POST /api/runs/{id}/credentials`.
- **Reveal Endpoint**: The loopback-only FastAPI endpoint `GET /api/runs/{id}/credentials/reveal` that returns raw stored secrets.
- **Owner Gate**: `_require_owner_action` — allows a loopback caller OR (`ALLOW_LOCAL_CREDENTIAL_SUBMISSION=true` AND a valid `X-Ops-Internal-Token`); guards live-view and resume-with-`browser_login`.
- **Local Owner Submission Gate**: `_require_local_owner_submission` — loopback-only; guards `submit_credentials` and `reveal_credentials`.
- **Run Service**: `ops/run_service` (`resume_run`, `get_browser_live_url`).
- **Browser Worker**: `ops/browser_worker` (and `AssignmentBrowserWorker`) — holds the signed `live_url` in memory and manages the `keep_alive` Browser Use session.
- **Browser Use Viewer**: The external live viewer hosted at `https://live.browser-use.com`.
- **Sign-in Form**: The autonomous sign-in form (account email + password) that submits `browser_login` via `submitBrowserLoginAction`.
- **live_url**: A signed, owner-only, ephemeral URL (≈15-min inactivity timeout, ≈4-hour max session) pointing at the Browser Use Viewer for a specific session.
- **HITL**: Human-in-the-loop — a paused run at `waiting_for_hitl` requiring a human action.
- **HumanActionType**: One of `captcha | email_otp | phone_otp | passkey | security_key | device_approval | provider_verification | legal_acceptance | billing | account_selection`.
- **Iframe-Embeddability Spike**: The gated go/no-go live verification that the Browser Use Viewer renders and accepts input inside our iframe under production CSP.
- **Live Smoke Harness**: The gated live-verification script `scripts/live_smoke.py`.
- **Reconciled Main**: The `main` branch after the deployed hot-patches are landed as reviewed commits, treated as the single source of truth.
- **plan_only**: A run created in planning mode that does not execute the browser flow.
- **Terminal Status**: Any `RunStatus` in `{blocked, failed, completed}`.

## Requirements

### Requirement 1: Embedded live browser (inline interactive feed)

**User Story:** As an operator, I want the live browser embedded inline in the run page as an interactive feed, so that I can click and type (CAPTCHA/OTP) without leaving the page or opening a foreign tab.

_Derived from: design "Overview", "What is missing → A. Inline embed", "Frontend Run-Page Layout", "Components and Interfaces"._

#### Acceptance Criteria

1. WHEN a run's `status` is `browser_running` or `waiting_for_hitl` and the run is not `plan_only`, THE Autonomous Live Console SHALL render the live browser as an inline `<iframe>` embed within the Run Page.
2. THE Embedded Live Console SHALL render the live browser feed as an interactive element that accepts operator pointer and keyboard input directed at the Browser Use Viewer.
3. THE Embedded Live Console SHALL source the `<iframe>` from a `live_url` on `https://live.browser-use.com`.
4. THE Embedded Live Console SHALL use the inline embed as the primary live-browser view in place of the external-tab link.

### Requirement 2: Auto-surface and auto-advance

**User Story:** As an operator, I want the console, live feed, HITL prompt, and correct inline control to appear automatically and the page to advance as the run progresses, so that I do not click "Get live browser link" or manually reload.

_Derived from: design "What is missing → B. Auto-surface", "Auto-surface & auto-refresh", Correctness Property P4._

#### Acceptance Criteria

1. WHEN a run's `status` is `browser_running` or `waiting_for_hitl` and the run is not `plan_only`, THE Autonomous Live Console SHALL display the live feed, the HITL prompt, and the inline control without requiring operator action.
2. WHILE a run is in a non-terminal status, THE Run Auto Refresh SHALL soft-refresh the Run Page so that `run.status` and `hitl_request` stay current without a manual reload.
3. WHEN a run's `status` transitions between `waiting_for_hitl`, `browser_running`, the credential page, and `completed`, THE Autonomous Live Console SHALL reflect the new status.
4. WHILE the Run Page performs a server refresh, THE Embedded Live Console SHALL keep the `<iframe>` mounted with a stable `src` so the framed session is not torn down.
5. WHEN a run reaches a Terminal Status, THE Embedded Live Console SHALL stop polling for the `live_url` and stop rendering the `<iframe>`.

### Requirement 3: Autonomous sign-in

**User Story:** As an operator, I want to hand the agent account credentials through our UI so the agent signs in on its own, so that I never type the password into the live browser and the values are used once and discarded.

_Derived from: design "Data-Flow (i) Autonomous login", "Data Models", "Security Considerations", Correctness Property P2._

#### Acceptance Criteria

1. WHEN an operator submits an account email and password through the Sign-in Form, THE Autonomous Live Console SHALL send those values to the Resume Endpoint as `browser_login` and SHALL NOT require the operator to type them into the Browser Use Viewer.
2. WHEN a resume carries `browser_login`, THE Run Service SHALL inject the email and password as Browser Use `sensitive_data` (`login_email` / `login_password`) exactly once and SHALL clear them after that resume.
3. THE Run Service SHALL keep `browser_login` values only in memory for the single resume injection and SHALL NOT write them to run state, checkpoints, the audit ledger, or logs.
4. WHEN login credentials are provided, THE Browser Worker SHALL drop the "entering a password" hard-stop and SHALL instruct the agent to type `<secret>login_email</secret>` / `<secret>login_password</secret>` so the underlying values never enter LLM-visible task text.
5. THE Sign-in Form SHALL use a `type=password` input with autocomplete disabled and SHALL clear the credential fields from the DOM after handoff.

### Requirement 4: HITL scope limited to human-only gates

**User Story:** As an operator, I want the run to pause only for genuinely human-only gates, so that everything else stays autonomous.

_Derived from: design "Goals #5", "Data-Flow (iii) Resume", "Inline control selection by action_type"._

#### Acceptance Criteria

1. WHEN the agent encounters a CAPTCHA, email OTP, phone OTP, passkey, security key, device approval, billing gate, legal consent, or ambiguous account selection, THE system SHALL pause the run at `waiting_for_hitl`.
2. WHILE the agent performs an action that is not a human-only gate, THE system SHALL continue autonomously and SHALL NOT pause for HITL.

### Requirement 5: Inline control selection by action_type

**User Story:** As an operator, I want the inline control chosen by the gate type, so that I always take the correct action for the current HITL reason.

_Derived from: design "Inline control selection by action_type", "Frontend Run-Page Layout", Correctness Property P5._

#### Acceptance Criteria

1. WHEN a run is `waiting_for_hitl` and `action_type` is `provider_verification` or `account_selection`, THE Embedded Live Console SHALL present the autonomous Sign-in Form that submits `browser_login`.
2. WHEN a run is `waiting_for_hitl` and `action_type` is `captcha`, `email_otp`, `phone_otp`, `passkey`, `security_key`, `device_approval`, `legal_acceptance`, or `billing`, THE Embedded Live Console SHALL present an "I completed it — resume" control that resumes with `signal="completed"` and no `browser_login`.
3. WHILE a run is `waiting_for_hitl`, THE Embedded Live Console SHALL present a Cancel control that resumes with `signal="cancelled"` and transitions the run to `blocked`.
4. THE Embedded Live Console SHALL display the HITL `action_type` and `message` adjacent to the live feed.
5. WHERE `action_type` is `provider_verification`, THE Embedded Live Console SHALL display copy noting that a bare password prompt classifies as `provider_verification` and SHALL keep "I completed it — resume" available as a secondary control.

### Requirement 6: Backend↔frontend contract correctness

**User Story:** As a developer, I want the end-to-end contracts (endpoints, payloads, schemas, timeouts, permission states) to be consistent, so that the console behaves predictably and matches the deployed backend.

_Derived from: design "Backend ↔ Frontend Contract", "Components and Interfaces", "Data Models"._

#### Acceptance Criteria

1. THE Live-View Endpoint SHALL return `LiveViewResponse{run_id, available, live_url?}` and SHALL be guarded by the Owner Gate.
2. THE Resume Endpoint SHALL accept `ResumeRequest{signal, browser_login?}` with `extra="forbid"` and SHALL apply the Owner Gate when `browser_login` is present.
3. WHEN posting an empty resume body `{}`, THE Resume Endpoint SHALL accept it as a valid human-gate resume because `signal` defaults to `"completed"` and `browser_login` defaults to null.
4. THE Live-View Route Handler SHALL enforce a client timeout of 8 seconds for live-view requests, and THE resume and resume-with-`browser_login` client calls SHALL enforce a synchronous client timeout of 180 seconds.
5. WHEN the `openLiveView` action reports a permission failure, THE Autonomous Live Console SHALL use owner-only wording and SHALL NOT display the stale "restricted to the owner on localhost" message.

### Requirement 7: Error and permission state handling

**User Story:** As an operator, I want clear, correct behavior for each failure mode, so that I understand the run state and can recover without double-submitting or losing the session.

_Derived from: design "Error Handling" table._

#### Acceptance Criteria

1. IF the Live-View Endpoint returns `available: false`, THEN THE Embedded Live Console SHALL display a "session ended / reconnecting" state and SHALL NOT render the `<iframe>`.
2. IF the Browser Use Viewer refuses to load in the `<iframe>` (blocking `X-Frame-Options` or `frame-ancestors`), THEN THE Embedded Live Console SHALL detect the load failure and display a degraded panel that surfaces the owner-only link.
3. IF the Owner Gate denies a request with `403`, THEN THE Autonomous Live Console SHALL display an owner-only permission message.
4. IF a resume carrying `browser_login` is rejected or re-interrupts, THEN THE system SHALL return the run to `waiting_for_hitl` with a refreshed HITL reason.
5. IF a resume is attempted while the run is not `waiting_for_hitl`, THEN THE Resume Endpoint SHALL return `409` and THE Autonomous Live Console SHALL reconcile state via auto-refresh.
6. IF a resume exceeds the 180-second client bound, THEN THE Autonomous Live Console SHALL surface a timeout error and SHALL leave server-side run state unchanged.
7. IF the live session expires mid-HITL (≈15-min inactivity or ≈4-hour maximum elapsed), THEN THE Live-View Endpoint SHALL report `available: false` and THE Autonomous Live Console SHALL surface session expiry.

### Requirement 8: live_url lifecycle and session continuity

**User Story:** As a security-conscious operator, I want the signed `live_url` to stay ephemeral and unpersisted and the session to persist across HITL, so that the embed stays on the same session before and after resume and no URL leaks to a durable boundary.

_Derived from: design "live_url Lifecycle Handling", "Architecture" (client-side fetch), Correctness Properties P1 and P3._

#### Acceptance Criteria

1. THE Browser Worker SHALL hold the signed `live_url` only in worker memory and SHALL NOT persist it to run state, checkpoints, the audit ledger, logs, client storage, or SSR/RSC HTML.
2. THE Live-View Route Handler SHALL set `Cache-Control: no-store` and SHALL NOT log the `live_url`.
3. THE Embedded Live Console SHALL keep the `live_url` only in ephemeral client state and SHALL NOT write it to `localStorage` or `sessionStorage`.
4. WHEN a run pauses at `waiting_for_hitl`, THE Browser Worker SHALL keep the session alive (`keep_alive`) so the same `session_id` and `live_url` persist across the pause.
5. WHEN a run is resumed, THE Run Service SHALL reuse the same `thread_id` and `session_id` so the Embedded Live Console points at the same live session before and after resume.
6. WHEN the Browser Worker has no active session, THE Live-View Endpoint SHALL return `available: false` and THE Embedded Live Console SHALL stop framing and show reconnect/ended.
7. WHEN the polled `live_url` value is unchanged, THE Embedded Live Console SHALL leave the `<iframe>` `src` unchanged, and SHALL update it only when the value changes.

### Requirement 9: Minimal CSP / framing relaxation

**User Story:** As a security engineer, I want the page CSP to permit framing exactly the two required sources and nothing else, so that framing relaxation is minimal and our own pages stay unframeable.

_Derived from: design "CSP / Framing Plan", Correctness Property P6._

#### Acceptance Criteria

1. THE Run Page CSP SHALL set `frame-src` to exactly `'self'` and `https://live.browser-use.com` and no other host.
2. THE Run Page CSP SHALL keep `frame-ancestors 'none'` in effect.
3. THE system SHALL keep the `X-Frame-Options: DENY` response header on our pages unchanged.
4. THE system SHALL leave the FastAPI (API) CSP and the Caddy CSP/frame headers unchanged.

### Requirement 10: Security invariants preserved

**User Story:** As a security engineer, I want every existing invariant preserved, so that no raw credential, token, cookie, or signed live link crosses a durable boundary and existing gates and abstractions are reused.

_Derived from: design "Security Considerations", "Components and Interfaces", `AGENTS.md`, `PLAN.md §16A`, Correctness Properties P1 and P2._

#### Acceptance Criteria

1. THE system SHALL ensure no raw credential, token, cookie, or signed `live_url` crosses a durable boundary (run state, checkpoints, audit ledger, logs, client storage, or SSR/RSC HTML).
2. THE system SHALL inject autonomous-login credentials, then discard them, and SHALL keep them out of LLM-visible task text.
3. THE Reveal Endpoint SHALL remain loopback-only under the Local Owner Submission Gate and SHALL NOT be called by the deployed Autonomous Live Console.
4. THE system SHALL preserve the Owner Gate (`_require_owner_action`) for live-view and resume-with-`browser_login`, and the Local Owner Submission Gate (`_require_local_owner_submission`) for `submit_credentials` and `reveal_credentials`.
5. THE implementation SHALL extend the existing live-view endpoint, owner gate, `resumeWithBrowserLogin`, `HitlLiveControls`, and browser worker rather than adding parallel routers, gates, or workers.

### Requirement 11: iframe-embeddability spike (go/no-go)

**User Story:** As a developer, I want a required gated live verification that the viewer frames and accepts input under our production CSP before committing to the iframe approach, so that we do not build on an unverified assumption.

_Derived from: design "The Embedding Decision", "Recommendation: iframe first, with a mandatory spike and a defined fallback", "Testing & Verification Strategy → Gated live"._

#### Acceptance Criteria

1. WHEN the Iframe-Embeddability Spike runs, THE spike SHALL require `RUN_LIVE_TESTS=1`, `ALLOW_LIVE_BROWSER`, and explicit operator authorization.
2. THE Iframe-Embeddability Spike SHALL load a real `live_url` under the exact production CSP behind Caddy and SHALL confirm the frame renders and accepts typed input.
3. THE Iframe-Embeddability Spike SHALL record the Browser Use Viewer's `X-Frame-Options` and `Content-Security-Policy: frame-ancestors` response headers in the spike notes.
4. IF the Browser Use Viewer refuses framing, THEN THE team SHALL apply the documented fallback ladder in order: same-origin reverse-proxy embed, then CDP screencast reusing the `run_trusted_raw_browser` boundary, then a degraded in-page panel.
5. THE iframe approach SHALL NOT be adopted as the committed implementation until the Iframe-Embeddability Spike returns a "go".

### Requirement 12: Source-of-truth reconciliation prerequisite

**User Story:** As a developer, I want all environments on one reconciled source of truth before implementation, so that the feature is not built on a divergent local base.

_Derived from: design "Local ↔ Deployed Reconciliation Prerequisite", "Local ↔ deployed divergence" table._

#### Acceptance Criteria

1. BEFORE embedding implementation begins, THE team SHALL land the deployed hot-patches as reviewed commits on `main` (Reconciled Main), including `BrowserLoginInput`, `ResumeRequest.browser_login`, resume `browser_login` handling and owner gate, `run_service.resume_run` `sensitive_data` inject/clear, `ops/graph.py` per-thread `sensitive_data`, `browser_worker`/`AssignmentBrowserWorker` `sensitive_data` + `login_fields` rendering, `_require_owner_action` (superseding `_require_owner_live_view`), the loopback-only Reveal Endpoint, and the frontend `resumeWithBrowserLogin`, `submitBrowserLoginAction`, Sign-in Form, and `execute_when_configured` default.
2. THE team SHALL bring the local workspace onto Reconciled Main.
3. THE team SHALL verify local equals deployed using the offline-safe suite (`ruff`, `mypy`, `pytest`) and a gated live parity smoke that confirms an execute run reaches `browser_running`/`waiting_for_hitl`, `GET /live-view` returns `200` with a `live_url` via the web-container path, and resume-with-`browser_login` passes the Owner Gate with `200`.
4. THE reconciliation process SHALL NOT commit any secret or `live_url`.

### Requirement 13: Verification and definition of done

**User Story:** As a developer, I want the feature verified end-to-end and truthfully represented, so that "done" means integrated through the public API, covered by tests, and honestly reflected in the frontend.

_Derived from: design "Testing & Verification Strategy", "Manual acceptance", `AGENTS.md`._

#### Acceptance Criteria

1. THE feature SHALL be integrated through the public API (live-view, resume, credentials paths).
2. THE feature SHALL be covered by offline-safe unit tests for backend and frontend, including CSP assertions (`frame-src` contains `https://live.browser-use.com`; `frame-ancestors 'none'` retained) and no-persistence checks for `live_url` and credentials.
3. THE feature SHALL be covered by a gated live smoke that extends `scripts/live_smoke.py` and proves the end-to-end wiring on the real backend.
4. THE frontend SHALL truthfully represent behavior per `AGENTS.md`, with no claim of working behavior that file presence alone would imply.
5. WHEN the manual acceptance check is performed, THE feature SHALL allow completing a real OTP inside the embed, resuming, and the agent continuing in the same session with no new browser tab opened.

## Requirements ↔ Design Correctness Properties

Each design Correctness Property (P1–P6 in `design.md`) is covered by at least one requirement below.

| Design Property | Statement (summary) | Covered by requirements |
|---|---|---|
| **P1** | Signed `live_url` is never persisted (state/checkpoints/ledger/logs/client storage/SSR-RSC HTML) | 8.1, 8.2, 8.3, 8.6, 10.1 |
| **P2** | Autonomous-login credentials are never persisted or read by the LLM | 3.2, 3.3, 3.4, 10.2 |
| **P3** | Same session across HITL (`session_id`/`thread_id` reused before and after resume) | 8.4, 8.5 |
| **P4** | Auto-surface matches backend state (renders for active statuses; unframes on terminal) | 2.1, 2.3, 2.5 |
| **P5** | Inline control matches the gate (sign-in form iff login gate; plain resume otherwise; cancel always) | 5.1, 5.2, 5.3 |
| **P6** | Minimal framing relaxation (`frame-src` exactly `'self'` + `https://live.browser-use.com`; `frame-ancestors 'none'` retained) | 9.1, 9.2 |
