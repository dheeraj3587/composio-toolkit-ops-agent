# Requirements Document

## Introduction

This feature converges the Composio Toolkit Ops Agent onto a single canonical runtime. Today the public FastAPI transport and the Next.js control plane are driven by a local dry-run application service, while the durable LangGraph workflow and the fail-closed provider adapters exist beside the public runtime rather than powering it. The goal of this feature is convergence: the durable workflow and provider adapters become the engine behind the public API, with `ops/run_service.py::RunService` as the one application service that owns and invokes the durable workflow and projects its state into the sanitized operations ledger.

These requirements are derived from the approved design (`design.md`) and constrained by the actual repository code: the single `RunStatus` vocabulary in `ops/state.py`, the strict Pydantic v2 contracts in `api/models.py`, and the configuration caps in `ops/config.py`. No scope beyond the design is introduced.

The posture is truthfulness and security first. A capability that did not run is reported as `configuration_required`, never as fake success. Raw credential material never enters graph state, checkpoints, ledgers, logs, API responses, frontend state, URLs, screenshots, fixtures, prompts, or Git; only exact `vault://<app>/<kind>/<id>` references cross general application boundaries. External actions require explicit policy flags, idempotency reservation, bounded retries, truthful receipts, and reconciliation of ambiguous outcomes rather than blind replay. Completion is defined by executed behavior, not by file presence.

## Glossary

- **plan_only**: The logical execution mode in which a run performs P1 lookup, deterministic routing, baseline construction, and sanitized persistence with no network or provider action; it terminates at `route_selected` and never reaches `completed`.
- **execute_when_configured**: The logical execution mode in which the durable workflow runs only configured, policy-enabled capabilities and otherwise records `configuration_required`.
- **canonical runtime**: The single application service (`RunService`) that owns the durable workflow, invokes it, and projects its state into the operations ledger; the only component the API talks to.
- **operations ledger**: The sanitized SQLite projection (`ops/storage.py::OperationsStorage`, `ops_db_path`) of run record, status, route, research projection, audit events, and the `side_effect_intents` mirror; the derived source the API reads.
- **LangGraph checkpoint**: The encrypted execution-truth store (`checkpoint_db_path`) owned by `DurableOperationsWorkflow`, holding the live graph position, interrupts, and in-flight `OperationsState`.
- **provider effect ledger**: The external-effect-truth store (`ops/effect_ledger.py::SQLiteEffectStore`, `provider_effects_db_path`) recording whether a provider action was reserved, completed, ambiguous, or failed, with secret-free receipts.
- **secret vault**: The Fernet-encrypted credential-truth store (`ops/secret_store.py::SQLiteSecretStore`, `secret_vault_db_path`) keyed by exact `vault://` references, with no list, reveal, or export interface.
- **state_revision**: A monotonic per-run counter incremented on every committed checkpoint (or every ledger mutation for `plan_only`).
- **last_projected_revision**: The per-run revision the operations ledger has already applied, used to guard projection idempotency.
- **projection**: The revision-guarded operation `project(run_id, state, revision)` that applies authoritative graph state to the operations ledger only when `revision > last_projected_revision`.
- **effectively-once**: The side-effect guarantee of atomic local reservation, durable non-secret receipt, and reconciliation of ambiguous outcomes with no blind replay; it does not claim exactly-once remote delivery for providers lacking native idempotency.
- **reconciliation**: Resolving an ambiguous provider outcome (`outcome_unknown` / `reconcile_required`) by a provider read that determines whether the effect landed, then transitioning to `completed` or `failed`.
- **HITL**: Human-in-the-loop; a durable interrupt that pauses a run at `waiting_for_hitl` for human action and resumes on the same thread.
- **request_id**: An opaque, server-issued HITL identifier of the form `hitl_<opaque-id>`, minted when an interrupt is raised, stored non-secret in the checkpoint and mirrored to the ledger.
- **run_conflict**: The typed HTTP 409 error, added to the existing strict error-envelope union, returned when a competing command modifies the same run.
- **app adapter**: A registered, secret-free `AppAdapter` (`ops/app_adapters/base.py`) supplying the ordered non-secret navigation and validation metadata that drives deterministic Playwright capture and read-only validation.
- **working self-serve adapter**: A deterministic app adapter that actually executes a full onboarding flow end to end (portal entry, login detection or HITL, developer-app lookup, idempotent creation, callback and scope configuration, credential-page navigation, immediate vault capture, read-only validation, and IntegratorBundle generation), as distinct from a mere registry entry or interface.
- **IntegratorBundle**: The reference-only output artifact describing integration readiness, credential references, scopes, callbacks, and evidence, rebuilt from sanitized storage.
- **available_scopes**: The set of scopes derived only from verified P1 data and official evidence for an app; a scope not present in verified evidence never appears here.
- **requested_scopes**: The scopes implied by the request's scope policy (`minimum`, `recommended`, or `maximum`) before selection.
- **selected_scopes**: The scopes chosen for configuration in the developer app, being the maximum documented scopes permitted by the requested scope policy.
- **excluded_scopes**: Scopes present in `available_scopes` but not selected, each carrying an exclusion reason and supporting evidence.
- **vault reference**: An exact `vault://<app>/<kind>/<id>` string; the only credential-shaped value permitted to cross general boundaries.
- **official-host allowlist**: The per-run set of official hosts (built from the P1 record via `OfficialURLPolicy.from_p1_record`, exact host/subdomain match, HTTPS-only, standard port) against which every external URL is verified.

## Requirements

### REQ-001: Canonical Runtime Convergence

**User Story:** As an integration engineer, I want one application service to own and drive the durable workflow, so that the public runtime executes real behavior instead of sitting beside the durable engine.

#### Acceptance Criteria

1. WHEN the FastAPI transport processes any run command THEN THE FastAPI transport SHALL invoke only RunService and SHALL NOT import ops/graph.py, provider adapters, OperationsStorage internals, the secret vault, or the effect ledger directly.
2. WHERE durable execution is required THE RunService SHALL be the only component that constructs and invokes DurableOperationsWorkflow.
3. WHEN DurableOperationsWorkflow returns an OperationsState after an invoke or resume THEN THE RunService SHALL project that state into the operations ledger and SHALL rebuild all public views from the operations ledger.
4. WHERE a run service, router, redactor, secret vault, provider client, or status enum already exists THE feature SHALL extend that single component and SHALL NOT introduce a second one.
5. WHEN the API returns any run view THEN THE RunService SHALL derive that view from sanitized storage and SHALL NOT return raw checkpoint state.

### REQ-002: Execution Modes

**User Story:** As a reviewer, I want a plan-only mode that touches no provider and a configured-execution mode that runs only enabled capabilities, so that runs are explainable and never fabricate execution.

#### Acceptance Criteria

1. WHEN a run is created with execution_mode plan_only THEN THE RunService SHALL perform P1 lookup, routing, baseline construction, and sanitized persistence with no network or provider action.
2. WHILE a run is in plan_only mode THE RunService SHALL keep external_actions false and SHALL terminate the run at route_selected.
3. IF a run is in plan_only mode THEN THE RunService SHALL NOT advance the run to browser_running, outreach_sent, or completed.
4. WHEN a run is created with execution_mode execute_when_configured THEN THE RunService SHALL start the durable workflow on a stable thread_id and SHALL run only configured, policy-enabled capabilities.
5. IF a required capability is not configured or not policy-enabled in execute_when_configured mode THEN THE RunService SHALL record configuration_required rather than performing that capability.

### REQ-003: execution_mode Single Control and dry_run Deprecated Alias

**User Story:** As an API consumer, I want one execution control with a backward-compatible alias, so that legacy callers keep working while behavior is governed by a single field.

#### Acceptance Criteria

1. WHERE CreateRunRequest is accepted THE FastAPI transport SHALL expose execution_mode with values plan_only and execute_when_configured and SHALL default it to plan_only.
2. WHEN a request supplies dry_run true and omits execution_mode THEN THE FastAPI transport SHALL normalize the request to execution_mode plan_only.
3. IF a request supplies dry_run true together with execution_mode execute_when_configured THEN THE FastAPI transport SHALL reject the request with HTTP 422.
4. WHEN a request has been normalized THEN THE RunService SHALL consult only execution_mode to control behavior and SHALL NOT consult dry_run.
5. WHILE live provider capabilities are policy-disabled THE RunService SHALL perform no provider action for execute_when_configured and SHALL return configuration_required.

### REQ-004: Persisted Execution-Mode Token Mapping

**User Story:** As a maintainer, I want the persisted mode tokens preserved while the API presents one vocabulary, so that no database migration is required in the first milestone.

#### Acceptance Criteria

1. WHERE a run is persisted THE OperationsStorage SHALL store the execution-mode token local_dry_run for plan_only and operations for execute_when_configured.
2. WHEN the projection layer presents a run at the API boundary THEN THE RunService SHALL map local_dry_run to plan_only and operations to execute_when_configured.
3. WHILE this milestone is in effect THE OperationsStorage SHALL NOT migrate existing execution-mode database rows.

### REQ-005: Synchronous Command Execution and Real Status

**User Story:** As an operator, I want every command to run synchronously and report the true resulting status, so that the UI never implies queued work that has not happened.

#### Acceptance Criteria

1. WHEN any of POST /api/runs, POST /api/runs/{id}/resume, POST /api/runs/{id}/poll-email, POST /api/runs/{id}/retry, or GET /api/runs/{id}/output is invoked THEN THE FastAPI transport SHALL execute the command synchronously within the request.
2. WHERE the runtime processes commands THE FastAPI transport SHALL NOT use a background worker or command queue.
3. WHEN POST /api/runs completes THEN THE FastAPI transport SHALL return the real resulting RunStatus.
4. WHEN POST /api/runs/{id}/resume, POST /api/runs/{id}/poll-email, or POST /api/runs/{id}/retry completes THEN THE FastAPI transport SHALL return the real resulting status.
5. WHEN any POST command completes THEN THE FastAPI transport SHALL NOT return the status accepted.
6. WHEN GET /api/runs/{id}/output is invoked THEN THE FastAPI transport SHALL return a RunOutputResponse or a typed configuration or not-ready response.
7. WHERE GET /api/runs/{id}/output responds THE FastAPI transport SHALL NOT be required to return a RunStatus.
8. WHEN a legal POST command finds the run already at rest THEN THE FastAPI transport SHALL return the receipt-level outcome no_change.

### REQ-006: Single Status-Transition Validator

**User Story:** As a maintainer, I want one transition authority consumed by the backend layers, so that transition logic is not duplicated or divergent.

#### Acceptance Criteria

1. WHERE run status changes THE domain layer SHALL expose exactly one validate_status_transition(previous_status, next_status, command) function co-located with the RunStatus vocabulary.
2. WHEN the projection layer writes a status to the operations ledger THEN THE RunService SHALL call validate_status_transition before writing.
3. IF validate_status_transition rejects a transition THEN THE RunService SHALL reject the write and SHALL NOT overwrite the stored status.
4. WHERE transition decisions are needed THE FastAPI transport, the graph, and OperationsStorage SHALL consume the single validator's verdict and SHALL NOT keep separate transition logic.

### REQ-007: Legal Status Transitions

**User Story:** As a reviewer, I want the legal transition table enforced, so that runs cannot reach impossible or dishonest states.

#### Acceptance Criteria

1. WHEN a run is initialized THEN THE RunService SHALL transition created to researching.
2. WHERE a run is in plan_only mode THE RunService SHALL treat route_selected as terminal and SHALL NOT provide a route_selected to completed transition.
3. WHILE a run is in configuration_required THE RunService SHALL treat configuration_required as a first-class non-terminal state and SHALL NOT present it as success.
4. WHEN a run reaches completed or blocked THEN THE RunService SHALL treat that state as terminal.
5. IF a run is failed THEN THE RunService SHALL allow re-entry only through an explicit bounded retry into a specific node.
6. WHEN any transition not present in the legal transition table is attempted THEN THE RunService SHALL reject it as illegal.

### REQ-008: Cross-Database Authority Model

**User Story:** As a maintainer, I want each of the four databases to have a defined authority, so that disagreements resolve by a fixed precedence rather than by chance.

#### Acceptance Criteria

1. WHERE execution position is in question THE LangGraph checkpoint SHALL be authoritative for execution truth.
2. WHERE an external effect's landing is in question THE provider effect ledger SHALL be authoritative for external-effect truth.
3. WHERE credential material is in question THE secret vault SHALL be authoritative for credential truth.
4. WHILE any source disagrees with the operations ledger THE RunService SHALL treat the operations ledger as a derived projection and SHALL NOT let it override the checkpoint, the effect ledger, or the vault.
5. WHEN the API reads run state THEN THE FastAPI transport SHALL read only the operations ledger.

### REQ-009: Monotonic Revision and Idempotent Projection

**User Story:** As a maintainer, I want revision-guarded projection, so that replay after a crash never double-applies or regresses a run.

#### Acceptance Criteria

1. WHEN the workflow commits a checkpoint THEN THE DurableOperationsWorkflow SHALL increment the run's monotonic state_revision.
2. WHERE a plan_only run mutates the ledger THE RunService SHALL increment state_revision on each ledger mutation.
3. WHEN project(run_id, state, revision) is called with revision greater than last_projected_revision THEN THE RunService SHALL apply the projection and SHALL advance last_projected_revision.
4. IF project(run_id, state, revision) is called with revision less than or equal to last_projected_revision THEN THE RunService SHALL treat the projection as a no-op.
5. WHEN a projection is replayed after a crash THEN THE RunService SHALL produce the same ledger row without a duplicate audit event and without a status regression.

### REQ-010: Startup Reconciliation and Recovery

**User Story:** As an operator, I want startup reconciliation across the four databases, so that runs recover correctly after a process death.

#### Acceptance Criteria

1. WHEN the RunService initializes THEN THE RunService SHALL reconcile every run not in a terminal state against the authoritative checkpoint and effect-ledger outcomes.
2. IF the checkpoint state_revision is ahead of last_projected_revision THEN THE RunService SHALL replay the idempotent projection forward without double-applying.
3. IF the effect ledger shows a completed or outcome_unknown effect that the checkpoint predates THEN THE RunService SHALL re-reserve the same idempotency key on resume and SHALL NOT perform a blind resend.
4. IF the operations ledger reflects a status the checkpoint does not yet reflect THEN THE RunService SHALL treat the checkpoint as authoritative and SHALL correct the ledger only through a legal transition.
5. IF last_projected_revision is greater than the checkpoint revision for a live thread THEN THE RunService SHALL flag the projection as stale and SHALL resolve it against the checkpoint rather than silently rewinding.
6. WHEN reconciliation runs THEN THE RunService SHALL flip external_actions to true only when the effect ledger shows a completed receipt.

### REQ-011: Per-Run Command Serialization and run_conflict

**User Story:** As an operator, I want competing commands on one run to be serialized, so that concurrent commands cannot cause partial writes or duplicate external actions.

#### Acceptance Criteria

1. WHERE multiple mutating commands target the same run THE RunService SHALL serialize them per run_id using the per-run lock and an optimistic state_revision guard.
2. WHEN a second concurrent command observes a revision mismatch on the same run THEN THE FastAPI transport SHALL return the typed run_conflict error with HTTP 409.
3. WHEN run_conflict is returned THEN THE FastAPI transport SHALL use the existing strict error-envelope structure with error run_conflict added to the error union and SHALL NOT define a parallel envelope class.
4. IF a command loses the per-run serialization guard THEN THE RunService SHALL perform no partial write and no external action.

### REQ-012: Effectively-Once Side Effects

**User Story:** As a reviewer, I want external side effects executed effectively once, so that crashes and retries never silently duplicate provider actions.

#### Acceptance Criteria

1. WHEN a provider action is about to execute THEN THE provider boundary SHALL perform an atomic local reservation in the SQLiteEffectStore before the call.
2. IF the reservation returns completed THEN THE provider boundary SHALL return the stored receipt and SHALL NOT resend.
3. IF the reservation returns reconcile_required THEN THE provider boundary SHALL trigger a reconciliation read and SHALL NOT perform a blind resend.
4. WHEN a provider call succeeds THEN THE provider boundary SHALL record a durable receipt containing only bounded non-secret identifiers.
5. WHEN a provider outcome is ambiguous THEN THE provider boundary SHALL record outcome_unknown and SHALL resolve it by a reconciliation read.
6. WHERE a provider offers no native idempotency key THE runtime SHALL NOT guarantee remote exactly-once delivery and SHALL rely on reconciliation.
7. WHEN and only when the effect ledger transitions to completed with a validated non-secret receipt THEN THE RunService SHALL set external_actions to true.

### REQ-013: HITL Canonical Resume Contract

**User Story:** As an operator, I want one canonical resume contract with strict identifier checks, so that stale or duplicate resumes cannot double-advance a run.

#### Acceptance Criteria

1. WHERE a run is resumed THE FastAPI transport SHALL accept exactly the contract request_id of the form hitl_<opaque-id> and signal in completed, cancelled, or retry.
2. WHEN a resume presents a request_id that does not match the outstanding interrupt for the thread THEN THE FastAPI transport SHALL reject it with the typed run_conflict error and SHALL NOT issue a second Command(resume=...).
3. IF a resume presents an already-consumed request_id THEN THE FastAPI transport SHALL reject it with run_conflict and SHALL NOT issue a second Command(resume=...).
4. IF a resume presents a request_id issued for a different thread_id than the addressed run THEN THE FastAPI transport SHALL reject it with run_conflict.
5. WHEN a concurrent duplicate resume targets the same run THEN THE FastAPI transport SHALL reject the loser with run_conflict.
6. WHEN a live, unconsumed, thread-matched request_id is accepted THEN THE RunService SHALL mark the request_id consumed before the graph advances.
7. WHEN the signal is retry THEN THE RunService SHALL re-enter the interrupted node under effectively-once rules so that an already-completed effect returns its stored receipt rather than being replayed.

### REQ-014: Durable HITL Restart and Resume

**User Story:** As an operator, I want a run to survive process death and resume on the same thread, so that human gates do not lose durable progress.

#### Acceptance Criteria

1. WHEN a run reaches a human interrupt THEN THE DurableOperationsWorkflow SHALL persist an encrypted checkpoint and SHALL report status waiting_for_hitl.
2. WHEN the process restarts THEN THE DurableOperationsWorkflow SHALL reopen the encrypted checkpoint on the same stable thread_id.
3. IF a resume is requested for a run not in waiting_for_hitl THEN THE RunService SHALL reject the resume as illegal.
4. WHEN a resume is accepted after a restart THEN THE DurableOperationsWorkflow SHALL complete the run with each external effect executed effectively once.

### REQ-015: Secret Non-Exposure Invariants

**User Story:** As a security reviewer, I want raw secrets excluded from every general boundary, so that only vault references ever leave the credential boundaries.

#### Acceptance Criteria

1. WHERE any value crosses graph state, checkpoints, databases, logs, API responses, frontend state, URLs, screenshots, fixtures, prompts, or Git THE runtime SHALL exclude raw passwords, API keys, OAuth secrets, access tokens, refresh tokens, auth codes, cookies, OTP values, TOTP values, private keys, CDP URLs, and signed live-view URLs.
2. WHERE a credential-shaped value must cross a general application boundary THE runtime SHALL represent it only as an exact vault://<app>/<kind>/<id> reference.
3. IF a value that is not a valid vault reference matches a credential-shaped pattern at a general boundary THEN THE runtime SHALL reject or redact it.

### REQ-016: Secret Vault

**User Story:** As a security reviewer, I want an encrypted exact-reference vault with no enumeration, so that credentials cannot be listed, revealed, or exported.

#### Acceptance Criteria

1. WHERE credentials are stored THE SQLiteSecretStore SHALL encrypt values with Fernet in an owner-only database.
2. WHEN a credential is retrieved THEN THE SQLiteSecretStore SHALL require an exact vault reference.
3. WHERE the vault interface is exposed THE SQLiteSecretStore SHALL NOT provide any list, reveal, or export method.
4. IF a retrieval uses a wrong key THEN THE SQLiteSecretStore SHALL raise a decryption error and SHALL NOT return plaintext.

### REQ-017: Checkpoint Secret-Absence Verification

**User Story:** As a security reviewer, I want strengthened checkpoint secret-absence proof, so that no raw secret survives in ciphertext-at-rest or deserialized state.

#### Acceptance Criteria

1. WHEN a run that touched secrets is verified THEN THE verification SHALL inspect the raw encrypted checkpoint database bytes and SHALL assert no injected test secret value appears in ciphertext-at-rest.
2. WHEN test checkpoints are verified THEN THE verification SHALL decrypt them with the test AES key using the same serializer construction the workflow uses and SHALL inspect the serialized OperationsState.
3. WHEN the deserialized state is inspected THEN THE verification SHALL assert only exact vault:// references and non-secret identifiers are present.
4. WHEN state mapping entries are inspected THEN THE verification SHALL reject credential-shaped keys and credential-shaped values on both sides of each entry.
5. WHEN a run is verified THEN THE verification SHALL inspect logs, structured audit records, API JSON responses, and frontend-rendered output and SHALL assert none contain the raw value.

### REQ-018: Browser Path

**User Story:** As an integration engineer, I want deterministic adapter-owned browser navigation only, so that the runtime never performs unrestricted autonomous navigation.

#### Acceptance Criteria

1. WHEN autonomous Browser Use agent navigation is requested THEN THE BrowserWorker SHALL fail closed to contract_incompatible because the SDK cannot prove the mandatory allowed_domains restriction.
2. WHERE a controlled browser flow runs THE BrowserWorker SHALL walk the registered adapter's ordered non-secret navigation steps using deterministic Playwright over CDP.
3. WHEN any browser action is about to occur THEN THE BrowserWorker SHALL validate the current page host against allowed_domains immediately before that action.
4. IF no adapter is registered for the app THEN THE BrowserWorker SHALL return configuration_required and SHALL NOT use a guessed selector or agent navigation.
5. WHEN a challenge is detected by the adapter's challenge hints THEN THE BrowserWorker SHALL escalate to HITL and SHALL NOT bypass it.
6. WHERE credential capture occurs THE BrowserWorker SHALL treat capture as one step inside the flow and SHALL NOT treat capture alone as completed onboarding.
7. WHILE a browser session is active THE BrowserWorker SHALL keep cdp_url and live_url ephemeral and SHALL NOT enter them into state, logs, storage, or the API.

### REQ-019: App-Adapter Registry

**User Story:** As a maintainer, I want a complete non-secret adapter contract, so that deterministic capture and validation never guess selectors, URLs, or endpoints.

#### Acceptance Criteria

1. WHERE an AppAdapter is registered THE AppAdapter SHALL provide app slug, allowed domains, developer portal URL, developer console URL, login-ready signal, developer-app lookup selectors, developer-app creation selectors, callback URL selectors, scope selectors, credential-page selectors, credential field selectors, challenge detection hints, completion signal, read-only validation endpoint, and validation authentication policy.
2. WHERE adapter metadata is stored THE AppAdapter SHALL contain only non-secret fields and SHALL NOT contain credential values.
3. IF an adapter is missing for an app THEN THE RunService SHALL return configuration_required for browser navigation, capture, and validation.
4. IF a registered adapter is missing any required field THEN THE RunService SHALL return configuration_required and SHALL NOT use a guessed selector, URL, or endpoint.

### REQ-020: Working Self-Serve Adapter

**User Story:** As an implementation lead, I want at least one adapter that actually executes an end-to-end onboarding flow, so that a registry or interface alone is never mistaken for working self-serve capability.

#### Acceptance Criteria

1. WHERE final assignment completion is claimed THE runtime SHALL require at least one deterministic app adapter that actually executes an onboarding flow.
2. WHEN the working self-serve adapter runs THEN THE adapter SHALL enter the developer portal.
3. WHEN the developer portal is reached THEN THE adapter SHALL detect login completion or escalate to HITL.
4. WHEN the adapter proceeds past login THEN THE adapter SHALL look up an existing developer app.
5. IF no developer app exists THEN THE adapter SHALL create the developer app idempotently.
6. WHEN a developer app is present THEN THE adapter SHALL configure the callback URL.
7. WHEN a developer app is present THEN THE adapter SHALL configure the selected scopes.
8. WHEN scope and callback configuration completes THEN THE adapter SHALL navigate to the credential page.
9. WHEN the credential page is reached THEN THE adapter SHALL capture credentials immediately into the encrypted vault as a vault reference.
10. WHEN credentials are captured THEN THE adapter SHALL perform read-only credential validation.
11. WHEN validation completes THEN THE adapter SHALL generate a standardized IntegratorBundle.
12. WHERE only a registry or interface exists without one working adapter THE runtime SHALL NOT treat this requirement as satisfied.

### REQ-021: Credential Capture

**User Story:** As a security reviewer, I want deterministic capture to vault raw values immediately, so that raw credentials never enter graph state or storage.

#### Acceptance Criteria

1. WHEN CredentialCapture reads a credential field THEN THE CredentialCapture SHALL store the raw value in the secret vault immediately and SHALL return only a vault reference.
2. WHILE capture executes THE CredentialCapture SHALL NOT place raw values into graph state, the checkpoint, storage, or the API.
3. WHEN CredentialCapture connects over CDP THEN THE CredentialCapture SHALL assert the page host is in allowed_domains before reading any field.

### REQ-022: Read-Only Credential Validation

**User Story:** As a reviewer, I want validation to be read-only against an allowed endpoint and to resolve directly, so that there is no lingering validating state and no persisted response body.

#### Acceptance Criteria

1. WHEN CredentialValidator validates a credential THEN THE CredentialValidator SHALL require the endpoint to be in the adapter's exact allowed-endpoint set.
2. WHEN validation completes THEN THE CredentialValidator SHALL resolve directly to credentials_ready, configuration_required, or failed.
3. WHERE validation runs THE CredentialValidator SHALL NOT persist the response body and SHALL persist only status, endpoint, HTTP code, timestamp, and reason code.
4. WHERE the status vocabulary is defined THE runtime SHALL NOT include validating_credentials in the RunStatus enum or in the frontend vocabulary.

### REQ-023: Scope Selection

**User Story:** As an integration engineer, I want scopes derived only from verified evidence and selected by policy, so that the developer app is configured with truthful, documented, maximum-permitted scopes.

#### Acceptance Criteria

1. WHEN available scopes are derived THEN THE RunService SHALL derive available_scopes only from verified P1 data and official evidence.
2. WHERE a scope is not present in verified evidence THE RunService SHALL NOT include that scope in available_scopes.
3. WHEN scope identifiers are collected THEN THE RunService SHALL normalize and deduplicate them.
4. WHERE scopes are represented THE RunService SHALL distinguish available_scopes, requested_scopes, selected_scopes, and excluded_scopes as separate sets.
5. WHEN scopes are selected THEN THE RunService SHALL select the maximum documented scopes permitted by the requested scope policy.
6. WHEN scopes are evaluated THEN THE RunService SHALL identify restricted, privileged, or approval-required scopes.
7. WHERE a scope is excluded THE RunService SHALL store an exclusion reason for that scope.
8. WHERE a scope is excluded THE RunService SHALL store supporting evidence for that scope.
9. WHEN credentials_ready is about to be reported THEN THE RunService SHALL verify that the scopes configured in the developer app match the selected scopes before reporting credentials_ready.

### REQ-024: Gmail Path

**User Story:** As an integration engineer, I want a controlled Composio Gmail send, fetch, classify, and reply loop, so that a gated app can be demonstrated end to end with bounded, sanitized, truthful behavior.

#### Acceptance Criteria

1. WHEN the controlled gated-app demonstration runs THEN THE GmailWorker SHALL use the Composio Gmail toolkit.
2. WHEN outreach is sent in the controlled demonstration THEN THE GmailWorker SHALL send an actual email to the configured controlled recipient.
3. WHEN an outreach email is sent THEN THE RunService SHALL persist the Gmail thread ID.
4. WHEN replies are polled THEN THE GmailWorker SHALL fetch replies from the persisted Gmail thread.
5. WHEN a Gmail thread is processed THEN THE GmailWorker SHALL follow the order fetch, deterministic secret extraction to the vault, [REDACTED_SECRET:*] placeholder substitution, sanitized thread assembly, then classification.
6. WHEN a reply is composed THEN THE GmailWorker SHALL reply in the same Gmail thread.
7. WHILE the outreach and reply loop runs THE GmailWorker SHALL bound outreach and reply rounds by MAX_OUTREACH_ROUNDS.
8. WHILE unclear replies are handled THE GmailWorker SHALL bound unclear-reply retries by MAX_UNCLEAR_RETRIES.
9. WHEN a poll-email command runs THEN THE GmailWorker SHALL perform at most one bounded fetch and classify pass.
10. WHEN the outreach round cap is reached THEN THE RunService SHALL stop the run at configuration_required.
11. WHEN the outreach round cap is reached THEN THE GmailWorker SHALL NOT send a further auto-reply.
12. IF ALLOW_LIVE_VENDOR_EMAIL is false THEN THE GmailWorker SHALL send to the outreach recipient override.
13. WHEN an outreach email is sent THEN THE RunService SHALL persist the intended recipient.
14. WHEN an outreach email is sent THEN THE RunService SHALL persist the actual recipient.
15. WHEN the Gmail path transitions to the browser path THEN THE RunService SHALL transition only through official allowlisted setup URLs.
16. WHEN the Gmail demonstration terminates THEN THE RunService SHALL produce a terminal result that is exactly one of a credentials_ready bundle, configuration_required, or blocked.

### REQ-025: ReplyClassifier Sanitized Input and Output Contract

**User Story:** As a security reviewer, I want the classifier to see only sanitized data and emit only bounded output, so that raw email content never reaches the LLM and output cannot smuggle secrets or unofficial URLs.

#### Acceptance Criteria

1. WHERE the ReplyClassifier is invoked THE input SHALL contain only the sanitized thread, app_name, and the non-secret company profile whose work_email_ref is a vault reference.
2. WHERE raw Gmail content exists THE ReplyClassifier SHALL NOT receive raw message bodies, raw headers beyond sanitized fields, credential values, or expanded vault values.
3. WHEN the ReplyClassifier returns a result THEN THE ReplyClassifier SHALL emit only a bounded ReplyClass, count- and length-capped questions, official-host-allowlisted setup URLs, and a deterministic next action.
4. WHERE the output model is defined THE ReplyClassifier output SHALL use extra=forbid and SHALL NOT echo free-form provider text as the next action.
5. WHEN a setup URL is not on the official-host allowlist THEN THE ReplyClassifier SHALL discard it before output.

### REQ-026: Official-Host Verification Before Gmail-to-Browser Transition

**User Story:** As a security reviewer, I want every classified setup URL verified before any browser transition, so that the runtime never navigates to an unverified host.

#### Acceptance Criteria

1. WHEN a reply is classified approved_setup_required with setup URLs THEN THE RunService SHALL verify every setup URL against the official-host allowlist before transitioning from the Gmail path to the browser path.
2. IF a setup URL is not on the official-host allowlist THEN THE RunService SHALL drop that URL.
3. IF no official setup URL remains after verification THEN THE RunService SHALL record configuration_required and SHALL NOT enter the browser path.

### REQ-027: Official-Evidence Enrichment

**User Story:** As a reviewer, I want enrichment guarded and non-mutating, so that missing fields can be filled without SSRF, hallucination, or P1 corruption.

#### Acceptance Criteria

1. WHERE enrichment runs THE operational research module SHALL be invoked only for the bounded unknown-probe or to fill missing operational fields.
2. WHEN enrichment fetches an external document THEN THE OfficialEvidenceFetcher SHALL enforce the official-host allowlist, public-DNS resolution, redirect revalidation, response-size limits, content-type limits, and explicit HTTP/HTTPS validation.
3. WHEN enrichment extracts structured data THEN THE extractor SHALL cite only fetched-pack URLs and SHALL NOT change the app identity.
4. WHERE enrichment executes THE operational research module SHALL NOT mutate P1 data.
5. IF discovery or extraction is unconfigured THEN THE RunService SHALL record configuration_required and SHALL retain the P1 baseline.

### REQ-028: P1 Verified Lookup

**User Story:** As a reviewer, I want provenance and hash verification before any record is exposed, so that only trusted P1 evidence drives routing.

#### Acceptance Criteria

1. WHEN the P1 adapter loads a record THEN THE P1 adapter SHALL verify pinned provenance and hashes before exposing any record.
2. IF a P1 artifact or manifest is tampered THEN THE P1 adapter SHALL raise a snapshot integrity error.
3. WHERE the runtime operates THE runtime SHALL NOT modify the canonical P1 files or the protected P1 repository.

### REQ-029: IntegratorBundle Truthful Readiness

**User Story:** As a reviewer, I want a complete reference-only bundle whose readiness requires real evidence, so that a developer account alone never implies credentials are ready and no raw credential ever appears.

#### Acceptance Criteria

1. WHERE the IntegratorBundle is produced THE integrator SHALL emit reference-only output.
2. WHERE applicable THE IntegratorBundle SHALL contain app_name, app_slug, auth_scheme, api_base_url, authorization_url, token_url, callback_urls, available_scopes, requested_scopes, selected_scopes, excluded_scopes with reasons, developer_app_id, client_id_ref, client_secret_ref, api_key_ref, credential validation status, readiness status, evidence URLs, and operational notes.
3. WHERE credential references appear in the bundle THE integrator SHALL represent client_id_ref, client_secret_ref, and api_key_ref only as exact vault:// references.
4. WHERE the bundle is produced THE integrator SHALL NOT include any raw credential value.
5. WHEN readiness is credentials_ready THEN THE integrator SHALL require at least one vault reference.
6. WHEN readiness is credentials_ready THEN THE integrator SHALL require a valid read-only validation.
7. IF only a developer app or provider account exists without a valid validation THEN THE integrator SHALL NOT report credentials_ready.
8. WHEN GET /api/runs/{id}/output is requested THEN THE RunService SHALL rebuild and validate the IntegratorBundle from sanitized storage.

### REQ-030: FastAPI Lifespan Ownership

**User Story:** As a maintainer, I want the app lifespan to own workflow construction and teardown, so that the API never constructs or closes the workflow or checkpoint directly.

#### Acceptance Criteria

1. WHEN the FastAPI app starts THEN THE app lifespan SHALL call RunService startup, which constructs the workflow and opens the encrypted checkpoint connection when LANGGRAPH_AES_KEY is present.
2. IF LANGGRAPH_AES_KEY is absent at startup THEN THE RunService SHALL leave the workflow unavailable and SHALL cause commands to return configuration_required.
3. WHEN the FastAPI app shuts down THEN THE app lifespan SHALL call RunService shutdown, which closes the checkpoint connection under the database lock and disposes provider adapters.
4. WHERE the workflow lifecycle is managed THE FastAPI transport SHALL NOT construct, hold, or close the workflow or checkpoint connection directly and SHALL hold only the RunService.

### REQ-031: Sanitized FastAPI Responses

**User Story:** As a security reviewer, I want strict response models and preserved headers, so that no internal value leaks through the transport.

#### Acceptance Criteria

1. WHERE any API response model is defined THE FastAPI transport SHALL use strict Pydantic v2 with extra=forbid.
2. WHERE a response is serialized THE FastAPI transport SHALL NOT include vault values, provider payloads, environment values, or database paths.
3. WHEN any response is returned THEN THE FastAPI transport SHALL preserve the no-store header and the standard security headers.

### REQ-032: Frontend Accurate State Mapping

**User Story:** As an operator, I want the UI to show real state without secrets and without its own transition logic, so that readiness and conflicts are represented truthfully and accessibly.

#### Acceptance Criteria

1. WHERE the frontend calls the API THE Next.js control plane SHALL use a server-only API client and SHALL NOT expose OPS_API_URL or secret material in client state.
2. WHERE credential references are shown THE Next.js control plane SHALL render count and readiness only and SHALL NOT provide a reveal control.
3. WHEN a command result is rendered THEN THE Next.js control plane SHALL render the real resulting status and SHALL NOT render accepted.
4. WHEN a run_conflict or configuration_required response is received THEN THE Next.js control plane SHALL render it as an accessible non-failure explanation.
5. WHERE the frontend vocabulary is defined THE Next.js control plane SHALL NOT include validating_credentials.
6. WHERE statuses are displayed THE Next.js control plane SHALL consume statuses produced by the API.
7. WHERE status transitions are concerned THE Next.js control plane SHALL NOT maintain its own legal status-transition table.
8. WHERE domain transition validation is concerned THE Next.js control plane SHALL NOT directly execute the Python domain transition validator.

### REQ-033: First Vertical Slice

**User Story:** As an implementation lead, I want POST /api/runs wired to the durable runtime with no adapters and live actions disabled, so that graph routing and sanitized projection are proven with no external action.

#### Acceptance Criteria

1. WHEN POST /api/runs runs in execute_when_configured mode in the first slice THEN THE RunService SHALL invoke DurableOperationsWorkflow with no provider adapters injected.
2. WHILE the first slice runs THE RunService SHALL keep all live provider actions disabled and SHALL perform no external action.
3. WHERE the run is plan_only THE RunService SHALL preserve the existing plan_only behavior terminating at route_selected.
4. IF LANGGRAPH_AES_KEY is configured THEN THE RunService SHALL run the graph and SHALL project routing state into the operations ledger and audit events.
5. IF LANGGRAPH_AES_KEY is absent THEN THE RunService SHALL return configuration_required honestly.
6. WHERE the first vertical slice is delivered THE runtime SHALL treat it as an infrastructure milestone and SHALL NOT treat it by itself as assignment completion.

### REQ-034: Verification and Truthfulness Posture

**User Story:** As a reviewer, I want offline-safe default tests and truthfully labeled evidence, so that fixtures are never presented as live provider results.

#### Acceptance Criteria

1. WHERE tests run by default THE test suite SHALL be offline-safe and SHALL NOT call paid or live providers.
2. IF a test performs a live provider action THEN THE test SHALL require explicit authorization, RUN_LIVE_TESTS=1, and the provider-specific safety flags.
3. WHERE evidence is reported THE runtime SHALL NOT present fixture evidence as live-provider evidence.
4. WHERE completion is claimed THE runtime SHALL define completion by executed behavior and SHALL NOT define completion by file presence.

### REQ-035: Ten-App Demonstration Matrix

**User Story:** As a reviewer, I want ten P1 applications demonstrated with truthful depth labels, so that routing-only results are never mistaken for live-provider evidence.

#### Acceptance Criteria

1. WHERE the demonstration matrix is presented THE runtime SHALL demonstrate ten P1 applications.
2. WHERE a matrix result is labeled THE runtime SHALL label each result as exactly one of routing-only, fixture-integration, local end-to-end, or live-controlled.
3. WHERE the matrix is composed THE matrix SHALL include self-serve, OAuth self-serve, gated, hybrid, and blocked/unknown applications.
4. WHERE a result is not live-controlled THE runtime SHALL NOT present it as live-provider evidence.

### REQ-036: Assignment Completion

**User Story:** As an implementation lead, I want completion defined by executed vertical slices, so that infrastructure alone is never mistaken for a finished assignment.

#### Acceptance Criteria

1. WHERE assignment completion is evaluated THE runtime SHALL NOT treat the first vertical slice by itself as assignment completion.
2. WHERE assignment completion is claimed THE runtime SHALL require one working self-serve local or live-controlled flow.
3. WHERE assignment completion is claimed THE runtime SHALL require one controlled Composio Gmail send, fetch, and reply flow.
4. WHERE assignment completion is claimed THE runtime SHALL require one durable restart-safe HITL demonstration.
5. WHERE assignment completion is claimed THE runtime SHALL require one tested scope-selection result.
6. WHERE assignment completion is claimed THE runtime SHALL require one credentials_ready standardized IntegratorBundle.
7. WHERE assignment completion is claimed THE runtime SHALL require ten P1 application demonstrations.

### REQ-037: Unsupported Capabilities

**User Story:** As a security reviewer, I want prohibited capabilities explicitly excluded, so that the runtime cannot be extended into unsafe behavior.

#### Acceptance Criteria

1. WHERE the vault is exposed THE runtime SHALL NOT provide any reveal-secret or export-secret interface.
2. WHERE a CAPTCHA, OTP, TOTP, passkey, device-verification, billing, or legal-acceptance step occurs THE runtime SHALL route it to HITL and SHALL NOT bypass it.
3. WHERE an irreversible action is required THE runtime SHALL require HITL and SHALL NOT automate it without HITL.
4. WHERE browser navigation is required THE runtime SHALL NOT perform autonomous Browser Use agent navigation.
5. WHERE commands are processed THE runtime SHALL NOT use a background worker or command queue.
6. WHERE a provider lacks native idempotency THE runtime SHALL NOT guarantee remote exactly-once delivery.

## Traceability

This mapping links each stable requirement ID to the relevant design.md section(s), the mapped correctness properties (P1–P23), and a concise, offline-safe test descriptor that would prove the requirement.

| Requirement ID | Design section | Correctness property | Expected test evidence |
|----------------|----------------|----------------------|------------------------|
| REQ-001 (Canonical Runtime Convergence) | §2.2, §3, §4 (domain 1) | P15 | Boundary test: api layer imports only RunService; static-import assertion finds no ops.graph/provider/vault/ledger import in api/. |
| REQ-002 (Execution Modes) | §1, §6, §7 | P18, P19 | Mode test: plan_only run terminates at route_selected with external_actions=false; execute_when_configured with no config yields configuration_required. |
| REQ-003 (execution_mode Single Control and dry_run Alias) | §1, §13 | P14, P19 | Request-normalization test: dry_run=true maps to plan_only; dry_run=true + execute_when_configured returns 422. |
| REQ-004 (Persisted Execution-Mode Token Mapping) | §1, §4 (domain 1) | P19 | Storage round-trip test: local_dry_run<->plan_only and operations<->execute_when_configured; assert no row migration. |
| REQ-005 (Synchronous Command Execution and Real Status) | §5, §13 | P21 | Endpoint test: POST returns real RunStatus never accepted; GET output returns RunOutputResponse or typed not-ready; grep no queue/worker module. |
| REQ-006 (Single Status-Transition Validator) | §6 | P20 | Single-authority test: exactly one validate_status_transition; api/graph/storage call it; grep asserts no parallel is_final heuristic. |
| REQ-007 (Legal Status Transitions) | §6 | P6, P19, P20 | Transition-table property test: illegal transitions rejected; no route_selected->completed edge; completed/blocked terminal. |
| REQ-008 (Cross-Database Authority Model) | §4A.1 | P15, P20 | Precedence test: ledger never overrides checkpoint/effect-ledger/vault; API read path touches only ops ledger. |
| REQ-009 (Monotonic Revision and Idempotent Projection) | §4A.2 | P20 | Idempotent-projection property test: replay same revision is a no-op; lower revision no-op; no duplicate audit event. |
| REQ-010 (Startup Reconciliation and Recovery) | §4A.3, §4A.4, §4A.5 | P7, P8, P20 | Restart reconciliation test: checkpoint-ahead replays forward; external_actions flips only on completed receipt. |
| REQ-011 (Per-Run Command Serialization and run_conflict) | §4A.3, §4A.6 | P21 | Concurrency test: second competing command returns 409 run_conflict with no partial write and no external action. |
| REQ-012 (Effectively-Once Side Effects) | §12 | P7, P8, P18 | Effect-ledger property test: reserve->completed no resend; outcome_unknown triggers reconcile read; external_actions only on completed receipt. |
| REQ-013 (HITL Canonical Resume Contract) | §10 | P22 | Resume-contract test: stale/consumed/thread-mismatched/duplicate request_id returns run_conflict; no second Command(resume=...). |
| REQ-014 (Durable HITL Restart and Resume) | §10 | P6, P7 | Checkpoint restart-resume test: process restart, same thread_id resume, exactly one external side effect executed. |
| REQ-015 (Secret Non-Exposure Invariants) | §4, §16 | P3, P4, P5 | Leakage regression test: no raw secret in state/checkpoint/db/logs/API/frontend; only vault:// refs cross boundaries. |
| REQ-016 (Secret Vault) | §4 (domain 4), §11 | P4, P5 | Vault test: Fernet encryption, exact-ref get, no list/reveal/export method, wrong-key raises decryption error. |
| REQ-017 (Checkpoint Secret-Absence Verification) | "Secret-absence testing approach" | P3, P4, P5 | Checkpoint decrypt+inspect test asserts only vault:// refs and non-secret IDs; ciphertext-at-rest contains no injected secret. |
| REQ-018 (Browser Path) | §8 | P11, P14 | Browser boundary test: agent nav -> contract_incompatible; host validated before each action; cdp_url/live_url never persisted. |
| REQ-019 (App-Adapter Registry) | "Developer-portal adapter registry design" | P14 | Adapter-contract test: missing adapter or any missing field yields configuration_required; no guessed selector/URL/endpoint. |
| REQ-020 (Working Self-Serve Adapter) | §8, "Developer-portal adapter registry design" | P11, P12, P14 | Fake-portal integration test: one adapter executes portal->login/HITL->lookup->idempotent create->callback/scope->capture->validate->bundle; registry-only not satisfied. |
| REQ-021 (Credential Capture) | §8, §11 | P5, P11 | Capture test: raw value vaulted immediately, only vault ref returned, host asserted before each field read. |
| REQ-022 (Read-Only Credential Validation) | §11 | P12, P14 | Validation test: endpoint allowlist enforced; only status/endpoint/code/timestamp/reason persisted; no validating_credentials in enum. |
| REQ-023 (Scope Selection) | "Developer-portal adapter registry design", §4 (IntegratorBundle) | P12, P13 | Scope-selection test: available_scopes derived only from P1/evidence; normalize+dedup; excluded scopes carry reason+evidence; configured==selected before credentials_ready. |
| REQ-024 (Gmail Path) | §9, §9.1, §12 | P9, P10, P23 | Fake-Composio integration test: thread_id persisted, reply in same thread, intended+actual recipients recorded, bounded rounds, terminal one-of. |
| REQ-025 (ReplyClassifier Sanitized Input and Output Contract) | §9.3 | P10, P23 | Classifier input/output test: only sanitized fields in; bounded typed output; non-allowlisted URLs discarded; extra=forbid. |
| REQ-026 (Official-Host Verification Before Gmail-to-Browser Transition) | §9.2 | P13, P23 | Allowlist-gate test: every setup URL verified before browser transition; none official -> configuration_required, no navigation. |
| REQ-027 (Official-Evidence Enrichment) | "Official-evidence enrichment integration" | P13, P16 | Enrichment guard test: SSRF/allowlist/redirect/size/content-type enforced; no P1 mutation; unconfigured -> configuration_required. |
| REQ-028 (P1 Verified Lookup) | §2.1 | P1, P16 | Provenance test: tampered artifact/manifest raises SnapshotIntegrityError; assert P1 files unmodified after run. |
| REQ-029 (IntegratorBundle Truthful Readiness) | §4 (domain 1), "integrator" | P12 | Bundle test: only vault:// refs for *_ref fields; credentials_ready requires >=1 vault ref + valid validation; dev app alone not ready. |
| REQ-030 (FastAPI Lifespan Ownership) | §4 (workflow lifecycle), §5.1 | P15 | Lifespan test: startup builds workflow when key present; API holds only RunService; shutdown closes checkpoint under lock. |
| REQ-031 (Sanitized FastAPI Responses) | §13 | P4, P15 | Response-model test: extra=forbid rejects drift; no vault/env/path fields; no-store + security headers preserved. |
| REQ-032 (Frontend Accurate State Mapping) | §14 | P17, P21 | Frontend boundary test: OPS_API_URL server-only; refs count/readiness only; consumes API status; no local transition table; renders run_conflict as non-failure. |
| REQ-033 (First Vertical Slice) | §15 (Increment 1) | P15, P16, P19, P20 | First-slice test: execute_when_configured with no adapters reaches route_selected via graph; no provider touched; key absent -> configuration_required. |
| REQ-034 (Verification and Truthfulness Posture) | "CI / Docker / release verification", "Secret-absence testing approach" | P14 | CI gate test: default offline-safe; live tests require RUN_LIVE_TESTS=1 + flags; assert fixtures never labeled live. |
| REQ-035 (Ten-App Demonstration Matrix) | "Ten-app demonstration matrix" | P14, P16 | Matrix test: ten apps present; each labeled exactly one of the four depths; all five categories represented; non-live not labeled live. |
| REQ-036 (Assignment Completion) | §15, "Ten-app demonstration matrix" | P12, P14 | Completion-audit test: first slice alone not completion; asserts self-serve + Gmail + HITL + scope + credentials_ready bundle + ten apps present. |
| REQ-037 (Unsupported Capabilities) | §17 | P11, P14 | Unsupported test: no reveal/export interface; challenges route to HITL; no agent nav; no queue/worker; no exactly-once delivery claim. |
