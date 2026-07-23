# Implementation Plan

Milestones are sequential: each one closes a real behavior gap and must leave the repository runnable and tested (green focused tests plus the affected full gate) before the next begins. The MUST tasks form the critical submission path; SHOULD tasks add breadth and polish; DEFER tasks are out of submission scope. The corrected critical path runs M1 -> M3 -> M4 -> M5 -> M6 -> M4B -> M7, with M2 (remaining production hardening) and M8 (release evidence) following. M1 is an infrastructure milestone: it wires one public command to the durable engine with no providers AND folds in the minimum runtime-integrity foundation (the single transition validator, revision-guarded idempotent projection, FastAPI lifespan workflow ownership, and the minimum per-run command serialization plus `run_conflict`) that M3-M6 all depend on — it is explicitly not final completion. Every task reuses the single `RunService`, `DurableOperationsWorkflow`, `OperationsStorage`, `SQLiteEffectStore`, `SQLiteSecretStore`, `RunStatus`, redaction, routing, and integrator; no second run service, workflow engine, router, vault, ledger, redactor, provider client, or status enum is introduced.

## Scope and dependencies

- P1 is already complete and is a READ-ONLY upstream dependency. P2 loads verified P1 records via the provenance/hash-checked `ops/p1_adapter.py`; it SHALL NOT rebuild, regenerate, re-run, or mutate P1 research or the canonical `data/p1/{SNAPSHOT.json,results.json,composio_coverage.json}` files (reinforces REQ-028).
- P3 implementation is OUT OF SCOPE. P2 stops at the standardized reference-only IntegratorBundle handoff; it does not build the P3 toolkit generator or integrator runtime.
- P2 owns only operational execution, credential acquisition, read-only credential validation, and the standardized IntegratorBundle handoff. Everything in this plan sits inside that boundary; anything outside it is a non-goal.

## M1 Canonical runtime wiring and minimum runtime-integrity foundation

**Requirements satisfied:** REQ-001, REQ-002, REQ-003, REQ-004, REQ-005 (POST path), REQ-006, REQ-007, REQ-009, REQ-011 (minimum), REQ-028, REQ-030, REQ-031, REQ-033
**Files to inspect:** `ops/run_service.py`, `ops/graph.py`, `ops/storage.py`, `ops/state.py`, `ops/p1_adapter.py`, `ops/config.py`, `ops/effect_ledger.py`, `api/app.py`, `api/service.py`, `api/models.py`, `tests/test_run_service.py`, `tests/test_api.py`, `tests/test_api_operations.py`, `tests/test_boundaries.py`, `tests/test_storage_operations.py`, `tests/test_phase2.py`
**Files expected to change:** `ops/run_service.py`, `ops/state.py`, `ops/storage.py`, `api/models.py`, `api/app.py`, `api/service.py`, `tests/test_run_service.py`, `tests/test_api_operations.py`, `tests/test_storage_operations.py`, and new `tests/test_graph_execution.py`, `tests/test_state_transitions.py`, `tests/test_projection.py`, `tests/test_run_conflict.py`
**Existing code to reuse:** `RunService.create_run`/`_public_run`, `DurableOperationsWorkflow.start`/`build_graph`/`WorkflowDependencies`, `OperationsUnitOfWork.update_run`/`append_audit_event`, `OperationsStorage._update_run`/`_run_from_row`, `RunStatus`, `decide_access`, `to_operational_research`, `redact_data`, `DurableOperationsWorkflow._lock`/`_database_lock`, `PhaseUnavailableResponse`/`IdempotencyConflictResponse` envelope machinery
**Security checks:** no provider adapters injected (`WorkflowDependencies(browser=None, gmail=None)`); `execute_when_configured` performs no external action; `external_actions` stays `false` (flips only on a `completed` receipt); projection never overrides checkpoint/effect-ledger/vault; conflict path performs no partial write and no external action; error union extended in place (no parallel envelope class); strict `extra="forbid"` response models; no vault/env/DB-path fields in responses; checkpoint bytes never returned by API
**Exact verification commands:** `RUN_LIVE_TESTS=0 python -m pytest tests/test_graph_execution.py tests/test_state_transitions.py tests/test_projection.py tests/test_run_conflict.py -q`, `RUN_LIVE_TESTS=0 python -m pytest tests/test_run_service.py tests/test_api_operations.py tests/test_storage_operations.py -q`, then the affected full gate `./scripts/security_gate.sh backend`
**Acceptance evidence:** `tests/test_graph_execution.py::test_execute_when_configured_reaches_route_selected_via_graph` (graph start -> checkpoint -> reopen -> read routed state), `::test_execute_when_configured_without_key_is_configuration_required`, `tests/test_run_service.py::test_plan_only_terminates_at_route_selected`, `tests/test_state_transitions.py::test_illegal_transition_rejected`, `tests/test_projection.py::test_replay_same_revision_is_noop`, `tests/test_run_conflict.py::test_second_concurrent_command_returns_run_conflict`, and `tests/test_api_operations.py::test_dry_run_alias_conflicts_with_execute_mode` all pass; observable: an `execute_when_configured` run row shows `route_selected`/`configuration_required` with `execution_mode='operations'`, `external_actions=0`, `state_revision`/`last_projected_revision` columns present, and a replayed projection produces no duplicate `audit_events`
**Suggested commit message:** `feat(runtime): drive POST /api/runs through the durable workflow with the minimum runtime-integrity foundation`
**Deferred work:** exhaustive four-database reconciliation, advanced concurrency/property coverage, stale-ledger edge cases, and effect-ledger vocabulary cleanup (M2 — non-blocking, minimum safe versions ship here); resume/poll-email/retry wiring (M5, M6); scope selection and bundle output (M3)

- [ ] 1. [MUST] Add `execution_mode` to the request contract and normalize the `dry_run` alias in `api/models.py::CreateRunRequest`.
  - 1.1 Add field `execution_mode: Literal["plan_only", "execute_when_configured"] = "plan_only"` and widen `dry_run` to `bool = True`; add a `model_validator(mode="after")` that maps `dry_run=true` -> `plan_only`, and raises `ValueError` when `dry_run=true` and `execution_mode="execute_when_configured"` (surfaced as HTTP 422 by the existing `RequestValidationError` handler).
  - 1.2 Extend `RunSummary.execution_mode`/`IntegratorBundleView` view mapping so the API presents the logical values `plan_only`/`operations`; keep the persisted token untouched (REQ-004).
  - 1.3 Add `tests/test_api_operations.py::test_dry_run_alias_conflicts_with_execute_mode` and `::test_execution_mode_defaults_to_plan_only` asserting 422 on conflict and default normalization.
  - _Requirements: REQ-003.1, REQ-003.2, REQ-003.3, REQ-031.1_

- [ ] 2. [MUST] Give `RunService.create_run` an `execution_mode` parameter and preserve plan-only behavior in `ops/run_service.py`.
  - 2.1 Replace the `if not request.dry_run: raise ValueError` guard with an `execution_mode` branch; `plan_only` keeps the existing P1 lookup + `decide_access` + `OperationsUnitOfWork` path and stores token `local_dry_run` with `external_actions=False`, terminating at `route_selected`/`researching`.
  - 2.2 Keep `_public_run` mapping `local_dry_run`->`plan_only` and `operations`->`execute_when_configured` at the boundary; assert no DB migration of the `execution_mode` column.
  - 2.3 Add `tests/test_run_service.py::test_plan_only_terminates_at_route_selected` asserting terminal `route_selected`, `external_actions False`, no `browser_running`/`completed`.
  - _Requirements: REQ-002.1, REQ-002.2, REQ-002.3, REQ-004.1, REQ-004.2, REQ-004.3, REQ-007.2, REQ-028.1_

- [ ] 3. [MUST] Add the single `validate_status_transition(previous_status, next_status, command)` to `ops/state.py`.
  - 3.1 Encode the legal-transition table from design §6 as a module-level mapping and raise `IllegalStatusTransition(ValueError)` for any transition not present; include the plan-only rule that `route_selected` has no `->completed` edge and that `completed`/`blocked` are terminal.
  - 3.2 Export it in `ops/state.py::__all__` so `ops/run_service.py`, `ops/graph.py`, and `ops/storage.py` consume the one verdict (no parallel `is_final` heuristics).
  - 3.3 Add `tests/test_state_transitions.py::test_illegal_transition_rejected`, `::test_terminal_states_are_terminal`, `::test_no_route_selected_to_completed_edge`.
  - _Requirements: REQ-006.1, REQ-006.4, REQ-007.1, REQ-007.2, REQ-007.3, REQ-007.4, REQ-007.5, REQ-007.6_

- [ ] 4. [MUST] Add `state_revision` and `last_projected_revision` columns to `ops/storage.py` and the `OperationsState` TypedDict in `ops/state.py`.
  - 4.1 Extend the `runs` table schema and the `migration_columns` map with `state_revision INTEGER NOT NULL DEFAULT 0` and `last_projected_revision INTEGER NOT NULL DEFAULT 0`; add both to `_RUN_COLUMNS` and `_run_from_row`.
  - 4.2 Add `state_revision: int` and `last_projected_revision: int` to `OperationsState`; increment `state_revision` in `DurableOperationsWorkflow` node returns on each committed checkpoint and in `RunService` on each plan-only ledger mutation.
  - 4.3 Add `tests/test_storage_operations.py::test_revision_columns_round_trip` asserting defaults and monotonic increment without row migration of existing data.
  - _Requirements: REQ-009.1, REQ-009.2_

- [ ] 5. [MUST] Add revision-guarded idempotent `RunService.project(run_id, state, revision)` in `ops/run_service.py`.
  - 5.1 Apply the projection only when `revision > last_projected_revision`; otherwise no-op; call `validate_status_transition(previous, next, command)` before every `update_run`; advance `last_projected_revision` inside the same `OperationsUnitOfWork`.
  - 5.2 Reuse `_public_run`/`redact_data`; never read raw checkpoint state into a response; keep the operations ledger a derived projection that never overrides the checkpoint, effect ledger, or vault.
  - 5.3 Add `tests/test_projection.py::test_replay_same_revision_is_noop`, `::test_lower_revision_is_noop`, `::test_projection_calls_validator_and_rejects_illegal`.
  - _Requirements: REQ-006.2, REQ-006.3, REQ-008.4, REQ-009.3, REQ-009.4, REQ-009.5_

- [ ] 6. [MUST] Let `RunService` own and invoke `DurableOperationsWorkflow` for `execute_when_configured` in `ops/run_service.py`.
  - 6.1 Add `RunService.startup()`/`shutdown()` that build the workflow via `ops.graph.build_graph(dependencies=WorkflowDependencies(browser=None, gmail=None))` only when `Settings.langgraph_aes_key` is present, else leave `self._workflow = None`; store on the service instance.
  - 6.2 In `create_run(execute_when_configured)`, when `self._workflow is None` persist `configuration_required` honestly (reuse `ConfigurationRequiredError(phase=3)` semantics); otherwise call `workflow.start(request, thread_id=thread_id)` and `project` the returned `OperationsState.status`/`access_route` into the run row + audit events via `OperationsUnitOfWork`.
  - 6.3 Never inject providers; assert `WorkflowDependencies.browser`/`gmail` are `None` so `_browser_start`/`_outreach_send` yield `configuration_required` without external action.
  - _Requirements: REQ-001.2, REQ-002.4, REQ-002.5, REQ-033.1, REQ-033.2, REQ-033.4, REQ-033.5_

- [ ] 7. [MUST] Add the MINIMUM per-run command serialization and the typed `run_conflict` error sufficient for safe single-process execution.
  - 7.1 Add `run_conflict` to the error-literal union by extending `api/models.py` with a `RunConflictResponse` reusing the strict envelope shape (`error`, `message`, `run_id`, `action`, `external_actions: Literal[False]`) and register a 409 handler in `api/app.py` (same family as `PhaseUnavailableResponse`); do not define a parallel envelope class.
  - 7.2 In `ops/run_service.py`, serialize mutating commands per `run_id` using the workflow `_lock(thread_id)` plus an optimistic `state_revision` guard; a losing writer raises `RunConflictError` with no partial write and no external action. This is the minimum single-process guard; the exhaustive race matrix is deferred to M2.
  - 7.3 Add `tests/test_run_conflict.py::test_second_concurrent_command_returns_run_conflict` and `::test_conflict_performs_no_external_action`.
  - _Requirements: REQ-011.1, REQ-011.2, REQ-011.3, REQ-011.4_

- [ ] 8. [MUST] Add the durable-path execution test in a new `tests/test_graph_execution.py`.
  - 8.1 `test_execute_when_configured_reaches_route_selected_via_graph`: build a workflow with a temp `checkpoint_path` and a 32-byte test AES key, `start` a verified-app request, `close`, reopen `build_graph` on the same DB, `get_state(thread_id)` and assert `status in {route_selected, configuration_required}` and `access_route` is set.
  - 8.2 `test_execute_when_configured_without_key_is_configuration_required`: with no `LANGGRAPH_AES_KEY`, assert `RunService` returns `configuration_required` and touches no provider.
  - 8.3 Mark the module offline-safe (no live providers); use the P1 verified snapshot loader only.
  - _Requirements: REQ-033.3, REQ-033.6, REQ-005.3, REQ-001.5_

- [ ] 9. [MUST] Wire `api/service.py::LocalRunService.create_run` and the FastAPI lifespan to the mode-aware service so the app owns workflow lifecycle.
  - 9.1 Pass `request.execution_mode` into `OperationsRequest`/`RunService.create_run`; return the real resulting `RunStatus` in `RunDetailResponse` (never `accepted`).
  - 9.2 Make `api/app.py::lifespan` call `active_service.startup()`/`shutdown()` only; `LocalRunService.startup`/`shutdown` delegate to `self._service.startup()`/`self._service.shutdown()`, which construct the workflow and close the checkpoint connection under the DB lock and dispose provider adapters; the API holds only `application.state.run_service` and never constructs, holds, or closes the workflow/checkpoint directly.
  - 9.3 Add `tests/test_api_operations.py::test_execute_when_configured_returns_real_status`, `::test_lifespan_builds_workflow_when_key_present`, and `::test_api_never_imports_graph_directly` (static-import assertion over `api/`).
  - _Requirements: REQ-001.1, REQ-005.1, REQ-005.3, REQ-005.5, REQ-030.1, REQ-030.2, REQ-030.3, REQ-030.4_

- [ ] 10. [SHOULD] Add a P1 immutability regression guard in `tests/test_snapshot.py`.
  - 10.1 `test_run_does_not_mutate_p1_files`: hash `data/p1/{SNAPSHOT.json,results.json,composio_coverage.json}` before and after an `execute_when_configured` run and assert equality; assert tampering raises `SnapshotIntegrityError`.
  - _Requirements: REQ-028.2, REQ-028.3_

Coverage: M1 tasks cover REQ-001, REQ-002, REQ-003, REQ-004, REQ-005(POST), REQ-006, REQ-007, REQ-009, REQ-011(minimum), REQ-028, REQ-030, REQ-031, REQ-033. (MUST 9, SHOULD 1, DEFER 0)

## M3 Standardized IntegratorBundle and scope selection

**Requirements satisfied:** REQ-005 (GET path), REQ-022, REQ-023, REQ-027, REQ-029
**Files to inspect:** `ops/integrator.py`, `ops/models.py`, `ops/run_service.py`, `ops/credential_validator.py`, `ops/operational_research.py`, `api/models.py`, `api/service.py`, `tests/test_models.py`, `tests/test_phase2.py`, `tests/test_api_operations.py`
**Files expected to change:** `ops/integrator.py`, `ops/models.py`, `api/models.py`, `api/service.py`, `ops/run_service.py`, and new `tests/test_integrator_bundle.py`, `tests/test_scope_selection.py`, `tests/test_enrichment.py`
**Existing code to reuse:** `build_integrator_bundle`/`_readiness`, `IntegratorBundle` model, `CredentialValidationResult`, `RunService.get_output`, `IntegratorBundleView`/`RunOutputResponse`, `OperationalResearch.scopes`, `OfficialURLPolicy.from_p1_record`, `redact_data`
**Security checks:** `*_ref` fields are `vault://` references only; no raw credential value in the bundle; readiness requires >=1 vault ref AND a valid read-only validation; enrichment enforces allowlist/DNS/redirect/size/content-type and never mutates P1
**Exact verification commands:** `RUN_LIVE_TESTS=0 python -m pytest tests/test_integrator_bundle.py tests/test_scope_selection.py tests/test_enrichment.py -q`, `RUN_LIVE_TESTS=0 python -m pytest tests/test_models.py tests/test_api_operations.py -q`, then `./scripts/security_gate.sh backend`
**Acceptance evidence:** `tests/test_integrator_bundle.py::test_credentials_ready_requires_ref_and_valid_validation`, `::test_dev_app_alone_not_ready`; `tests/test_scope_selection.py::test_available_scopes_only_from_evidence` and `::test_excluded_scopes_carry_reason_and_evidence`; `tests/test_api_operations.py::test_output_returns_not_ready_when_no_bundle`; observable: `GET /api/runs/{id}/output` returns a full `RunOutputResponse` or a typed `PhaseUnavailableResponse(available_in=["output"])`
**Suggested commit message:** `feat(integrator): full bundle schema, scope selection, and guarded enrichment`
**Deferred work:** live credential validation against a real provider endpoint (M4/live); browser-captured refs feeding the bundle (M4)

- [ ] 1. [MUST] Expand `IntegratorBundle` (`ops/models.py`) and `IntegratorBundleView` (`api/models.py`) to the full REQ-029 field set.
  - 1.1 Add `available_scopes`, `requested_scopes`, `selected_scopes`, `excluded_scopes` (each with `reason` + `evidence`), `client_id_ref`, `client_secret_ref`, `api_key_ref` (typed `VaultReference`), `developer_app_id`, and `credential_validation_status`; keep `extra="forbid"`.
  - 1.2 Mirror the new fields in `IntegratorBundleView` and the frontend Zod schema contract expectations (rendered in M7).
  - 1.3 Add `tests/test_integrator_bundle.py::test_bundle_refs_are_vault_only` and `::test_bundle_rejects_raw_credential_value`.
  - _Requirements: REQ-029.1, REQ-029.2, REQ-029.3, REQ-029.4_

- [ ] 2. [MUST] Enforce truthful readiness in `ops/integrator.py::_readiness`.
  - 2.1 Keep `credentials_ready` gated on `refs_present and validation.status == "valid"`; add an assertion that configured scopes equal `selected_scopes` before `credentials_ready` is returned.
  - 2.2 Add `tests/test_integrator_bundle.py::test_credentials_ready_requires_ref_and_valid_validation` and `::test_dev_app_alone_not_ready`.
  - _Requirements: REQ-029.5, REQ-029.6, REQ-029.7, REQ-023.9_

- [ ] 3. [MUST] Add a deterministic scope-selection helper in `ops/run_service.py` (or `ops/integrator.py`).
  - 3.1 Derive `available_scopes` only from `OperationalResearch.scopes` (P1/evidence), normalize+deduplicate, select the maximum documented scopes permitted by `requested_scope_policy`, and record `excluded_scopes` with reason + supporting evidence; identify restricted/privileged/approval-required scopes.
  - 3.2 Add `tests/test_scope_selection.py::test_available_scopes_only_from_evidence`, `::test_scope_normalize_and_dedup`, `::test_excluded_scopes_carry_reason_and_evidence`, `::test_maximum_policy_selects_documented_max`.
  - _Requirements: REQ-023.1, REQ-023.2, REQ-023.3, REQ-023.4, REQ-023.5, REQ-023.6, REQ-023.7, REQ-023.8_

- [ ] 4. [MUST] Rebuild the bundle from sanitized storage in `RunService.get_output` and wire `GET /api/runs/{id}/output`.
  - 4.1 In `ops/run_service.py::get_output`, validate the persisted bundle via `IntegratorBundle.model_validate`, sanitize with `redact_data`, and return reference-only; keep the empty-bundle `{}` sentinel that `LocalRunService.get_output` maps to `PhaseUnavailableResponse(available_in=["output"])`.
  - 4.2 Add `tests/test_api_operations.py::test_output_returns_not_ready_when_no_bundle` and `::test_output_returns_bundle_view_when_ready`.
  - _Requirements: REQ-005.6, REQ-005.7, REQ-029.8_

- [ ] 5. [SHOULD] Add read-only validation resolution and enrichment guard tests.
  - 5.1 Add `tests/test_enrichment.py::test_validation_endpoint_allowlist_enforced` (reuse `CredentialValidator` with a fake `httpx.AsyncClient`) asserting only status/endpoint/http_status/checked_at/reason_code persist and `validating_credentials` is absent from `RunStatus`.
  - 5.2 Add `tests/test_enrichment.py::test_enrichment_guards_enforced_and_no_p1_mutation` covering allowlist/public-DNS/redirect/size/content-type via `ops/operational_research.py` fakes; unconfigured discovery -> `configuration_required` with P1 baseline retained.
  - _Requirements: REQ-022.1, REQ-022.2, REQ-022.3, REQ-022.4, REQ-027.1, REQ-027.2, REQ-027.3, REQ-027.4, REQ-027.5_

Coverage: M3 tasks cover REQ-005(GET), REQ-022, REQ-023, REQ-027, REQ-029. (MUST 4, SHOULD 1, DEFER 0)

## M4 Working reusable self-serve adapter

**Requirements satisfied:** REQ-018, REQ-019, REQ-020, REQ-021, REQ-022, REQ-023, REQ-037 (browser)
**Files to inspect:** `ops/app_adapters/base.py`, `ops/browser_worker.py`, `ops/credential_capture.py`, `ops/credential_validator.py`, `ops/integrator.py`, `ops/config.py`, `fixtures/browser/README.md`, `tests/test_boundaries.py`
**Files expected to change:** `ops/app_adapters/base.py`, a new `ops/app_adapters/<app>.py` working adapter, a new `ops/app_adapters/registry.py`, a shared deterministic onboarding driver reused across apps, a controlled local fixture page under `fixtures/browser/`, and new `tests/test_app_adapter.py`, `tests/test_self_serve_adapter.py`
**Existing code to reuse:** `AppAdapter` Protocol, `CredentialFieldSelector`, `CredentialCapture.for_operation`/`capture_page_and_store`, `is_allowed_browser_url`/`validate_allowed_domains`, `CredentialValidationPolicy`/`CredentialValidator`, `build_integrator_bundle`, `Settings.allow_live_browser`
**Security checks:** agent navigation fails closed to `contract_incompatible`; host validated before every action; missing adapter/field -> `configuration_required`; capture returns vault refs only and never enters state/logs/storage/API; challenge hints escalate to HITL; capture is one step, not whole onboarding; the local fixture E2E is fixture-integration evidence only and is never labeled live; any live-controlled attempt is gated and never presented as fixture
**Exact verification commands:** `RUN_LIVE_TESTS=0 python -m pytest tests/test_self_serve_adapter.py tests/test_app_adapter.py -q`, `RUN_LIVE_TESTS=0 python -m pytest tests/test_boundaries.py -q`, then `./scripts/security_gate.sh backend`; live-controlled variant only (explicit authorization required): `RUN_LIVE_TESTS=1 ALLOW_LIVE_BROWSER=true python -m pytest -m live tests/test_self_serve_adapter.py -q`
**Acceptance evidence:** `tests/test_self_serve_adapter.py::test_full_onboarding_flow_against_fixture_portal` (portal -> login/HITL -> lookup -> idempotent create -> callback/scope -> capture -> validate -> bundle) and `::test_registry_only_is_not_satisfied`; `tests/test_app_adapter.py::test_missing_field_yields_configuration_required`; observable: the fixture run produces a `credentials_ready` bundle labeled fixture-integration whose `credential_refs` are `vault://` only; a live-controlled run (when authorized) produces either a truthful `credentials_ready` bundle labeled live-controlled or a truthful external-blocker state
**Suggested commit message:** `feat(adapters): reusable AppAdapter contract, registry, shared driver, and one working self-serve adapter`
**Deferred work:** additional bespoke live vendor automations beyond the one working adapter and the ten-app reuse in M4B (SHOULD/DEFER breadth)

- [ ] 1. [MUST] Expand `ops/app_adapters/base.py::AppAdapter` to the full 16-field non-secret contract and add a reusable registry.
  - 1.1 Add the properties from design "adapter registry" (`developer_portal_url`, `developer_console_url`, `login_ready_signal`, `developer_app_lookup_selectors`, `developer_app_creation_selectors`, `callback_url_selectors`, `scope_selectors`, `credential_page_selectors`, `challenge_detection_hints`, `completion_signal`, `read_only_validation_endpoint`, `validation_authentication_policy`) keeping all fields non-secret.
  - 1.2 Add `ops/app_adapters/registry.py` with an `app_slug`-keyed lookup returning the adapter; missing adapter or missing required field -> `configuration_required`. This registry is the single contract that M4B reuses across the ten apps.
  - 1.3 Add `tests/test_app_adapter.py::test_missing_adapter_yields_configuration_required` and `::test_missing_field_yields_configuration_required`.
  - _Requirements: REQ-019.1, REQ-019.2, REQ-019.3, REQ-019.4_

- [ ] 2. [MUST] Keep autonomous Browser Use agent navigation failing closed in `ops/browser_worker.py`.
  - 2.1 Assert `BrowserWorker.start`/`navigate_onboarding`/`resume_after_hitl` raise `ProviderContractError(v3_domain_restriction_unavailable)` -> `contract_incompatible`; the only supported path is deterministic adapter-owned Playwright over CDP with `is_allowed_browser_url` before each action.
  - 2.2 Add `tests/test_boundaries.py::test_agent_navigation_is_contract_incompatible` and `::test_host_validated_before_each_action`.
  - _Requirements: REQ-018.1, REQ-018.2, REQ-018.3, REQ-018.7, REQ-037.4_

- [ ] 3. [MUST] Implement ONE deterministic working adapter driving a controlled local fixture portal via a REUSABLE shared driver.
  - 3.1 Add `ops/app_adapters/<app>.py` implementing the full contract and a shared onboarding driver (reused by M4B, not one-off per app) that: enters the portal, detects login-ready (else HITL), looks up an existing developer app, creates it idempotently when absent, configures callback + selected scopes, navigates to the credential page, and reads the completion signal.
  - 3.2 Add a controlled offline fixture page under `fixtures/browser/` (fixture-integration evidence only; never labeled live) served locally; drive capture with `CredentialCapture.capture_page_and_store` (vault refs only).
  - 3.3 On a `challenge_detection_hints` match, escalate to HITL (`waiting_for_hitl`) and never bypass.
  - _Requirements: REQ-020.1, REQ-020.2, REQ-020.3, REQ-020.4, REQ-020.5, REQ-020.6, REQ-020.7, REQ-020.8, REQ-018.4, REQ-018.5, REQ-018.6, REQ-037.2, REQ-037.3_

- [ ] 4. [MUST] Capture, validate, and bundle inside the working adapter flow.
  - 4.1 Capture credentials immediately to the vault as `vault://` refs via `CredentialCapture`; run read-only validation with a `CredentialValidationPolicy` against the adapter's `read_only_validation_endpoint` (fake `httpx.AsyncClient`); build the `IntegratorBundle` and assert `selected_scopes` equal configured scopes before `credentials_ready`.
  - 4.2 Add `tests/test_self_serve_adapter.py::test_full_onboarding_flow_against_fixture_portal`, `::test_capture_returns_only_vault_refs`, `::test_registry_only_is_not_satisfied`.
  - _Requirements: REQ-020.9, REQ-020.10, REQ-020.11, REQ-020.12, REQ-021.1, REQ-021.2, REQ-021.3, REQ-022.1, REQ-022.2, REQ-022.3, REQ-023.9_

- [ ] 5. [MUST] Add at least one REAL/LIVE-CONTROLLED self-serve provider attempt as submission evidence, gated and skipped by default.
  - 5.1 Add `tests/test_self_serve_adapter.py::test_live_controlled_self_serve_attempt` marked `@pytest.mark.live`, skipped unless explicit user authorization plus `RUN_LIVE_TESTS=1` and `ALLOW_LIVE_BROWSER=true` are set; it drives the shared driver against a real developer portal and asserts the outcome is either a truthful `credentials_ready` bundle labeled live-controlled or a truthful external-blocker state (`configuration_required`/`blocked`), never fabricated success.
  - 5.2 Never present fixture execution as live-provider execution; the fixture E2E in task 4 stays labeled fixture-integration and the live attempt is the only result that may carry the live-controlled label.
  - _Requirements: REQ-020.1, REQ-020.12, REQ-034.2, REQ-034.3, REQ-037.2_

Coverage: M4 tasks cover REQ-018, REQ-019, REQ-020, REQ-021, REQ-022, REQ-023, REQ-037(browser). (MUST 5, SHOULD 0, DEFER 0)

## M5 Controlled Composio Gmail flow

**Requirements satisfied:** REQ-012 (reservation), REQ-015, REQ-024, REQ-025, REQ-026
**Files to inspect:** `ops/gmail_worker.py`, `ops/reply_classifier.py`, `ops/effect_ledger.py`, `ops/secret_store.py`, `ops/config.py`, `ops/graph.py`, `fixtures/gmail/README.md`, `prompts/reply_classifier.system.md`, `tests/test_boundaries.py`, `tests/test_redaction.py`
**Files expected to change:** `ops/reply_classifier.py`, `ops/run_service.py`, `ops/graph.py`, sanitized fixtures under `fixtures/gmail/`, and new `tests/test_gmail_flow.py`, `tests/test_reply_classifier.py`, `tests/test_official_host_gate.py`
**Existing code to reuse:** `GmailWorker.send_outreach`/`fetch_thread`/`reply`, `SanitizedGmailThread`/`SanitizedGmailMessage`, `_store_and_redact_email_secrets`, `SQLiteEffectStore.reserve`/`complete`/`mark_outcome_unknown`, `ReplyClass`/`ReplyClassification`, `OfficialURLPolicy.from_p1_record`, `Settings.max_outreach_rounds`/`max_unclear_retries`/`outreach_recipient_override`/`allow_live_vendor_email`
**Security checks:** fetch -> deterministic secret extraction to vault -> `[REDACTED_SECRET:*]` -> sanitized thread -> classifier order is non-negotiable; classifier sees only sanitized fields and a `vault://` `work_email_ref`; setup URLs verified against the official-host allowlist before any browser transition; bounded rounds; recipient override unless `ALLOW_LIVE_VENDOR_EMAIL=true`; the offline fake-Composio test is the default and is never labeled live; the live-controlled test is skipped when unconfigured and never presented as fixture
**Exact verification commands:** `RUN_LIVE_TESTS=0 python -m pytest tests/test_gmail_flow.py tests/test_reply_classifier.py tests/test_official_host_gate.py -q`, `RUN_LIVE_TESTS=0 python -m pytest tests/test_boundaries.py tests/test_redaction.py -q`, then `./scripts/security_gate.sh backend`; live-controlled variant only (explicit authorization required): `RUN_LIVE_TESTS=1 ALLOW_LIVE_VENDOR_EMAIL=true python -m pytest -m live tests/test_gmail_flow.py -q` (requires a configured controlled recipient)
**Acceptance evidence:** `tests/test_gmail_flow.py::test_thread_id_persisted_and_reply_in_same_thread`, `::test_bounded_rounds_stop_at_configuration_required`, `::test_intended_and_actual_recipients_persisted`; `tests/test_reply_classifier.py::test_classifier_receives_only_sanitized_fields` and `::test_output_discards_non_allowlisted_urls`; `tests/test_official_host_gate.py::test_no_official_url_blocks_browser_transition`; observable: the offline fake-Composio run persists a Gmail `thread_id` and a bounded terminal result; when configured and authorized, the live-controlled run sends to the controlled override recipient and preserves one Gmail thread across send/fetch/reply
**Suggested commit message:** `feat(gmail): controlled send/fetch/classify/reply loop with sanitized classifier`
**Deferred work:** meeting-scheduling classifications beyond the demo set (DEFER)

- [ ] 1. [MUST] Implement `ops/reply_classifier.py::ReplyClassifier.classify` behind the sanitization boundary.
  - 1.1 Replace the `PhaseUnavailableError` stub with a Gemini-backed (lazy import) classifier whose input is only `app_name`, `SanitizedGmailThread`, and the non-secret `CompanyProfile` (`work_email_ref` stays `vault://`); output is a strict `extra="forbid"` `ReplyClassification` with bounded `ReplyClass`, count/length-capped `explicit_questions`, allowlisted `official_setup_urls`, and a deterministic `required_next_action` (never echoed free-form provider text).
  - 1.2 Discard any setup URL not on the official-host allowlist before output.
  - 1.3 Add `tests/test_reply_classifier.py::test_classifier_receives_only_sanitized_fields`, `::test_output_is_bounded_and_extra_forbid`, `::test_output_discards_non_allowlisted_urls` (fake classifier client + sanitized fixtures).
  - _Requirements: REQ-025.1, REQ-025.2, REQ-025.3, REQ-025.4, REQ-025.5_

- [ ] 2. [MUST] Wire the bounded Gmail loop into `RunService`/`ops/graph.py` with a fake Composio client as the DEFAULT automated test.
  - 2.1 Drive `send_outreach` (persist `gmail_thread_id`, intended + actual recipients), one bounded `fetch_thread`+`classify` pass per `poll-email`, and `reply` in the same thread; bound rounds by `Settings.max_outreach_rounds` and unclear retries by `max_unclear_retries`; at the cap stop at `configuration_required` with no further auto-reply.
  - 2.2 Enforce fetch -> secret-extraction-to-vault -> `[REDACTED_SECRET:*]` -> sanitized thread -> classify ordering; terminal result is exactly one of `credentials_ready`/`configuration_required`/`blocked`.
  - 2.3 Add `tests/test_gmail_flow.py::test_thread_id_persisted_and_reply_in_same_thread`, `::test_bounded_rounds_stop_at_configuration_required`, `::test_intended_and_actual_recipients_persisted`, `::test_fetch_extracts_secrets_before_classifier` (all offline with the fake Composio client).
  - _Requirements: REQ-024.1, REQ-024.2, REQ-024.3, REQ-024.4, REQ-024.5, REQ-024.6, REQ-024.7, REQ-024.8, REQ-024.9, REQ-024.10, REQ-024.11, REQ-024.12, REQ-024.13, REQ-024.14, REQ-024.16_

- [ ] 3. [MUST] Enforce the official-host gate before the Gmail->browser transition in `RunService`.
  - 3.1 On `approved_setup_required`, verify every setup URL via `OfficialURLPolicy.from_p1_record`; drop non-official URLs; if none remain, record `configuration_required` and do not enter the browser path.
  - 3.2 Add `tests/test_official_host_gate.py::test_every_setup_url_verified_before_transition` and `::test_no_official_url_blocks_browser_transition`.
  - _Requirements: REQ-024.15, REQ-026.1, REQ-026.2, REQ-026.3_

- [ ] 4. [MUST] Prove effectively-once reservation and secret non-exposure in the Gmail path.
  - 4.1 Assert `send_outreach`/`reply` reserve in `SQLiteEffectStore` before the call, return the stored receipt on `completed` (no resend), and `mark_outcome_unknown` on ambiguous outcomes; `external_actions` flips only on a `completed` receipt.
  - 4.2 Add `tests/test_gmail_flow.py::test_reserve_completed_does_not_resend` and a leakage regression `tests/test_redaction.py::test_no_raw_secret_in_sanitized_thread_or_ledger` asserting only `vault://` refs cross the boundary.
  - _Requirements: REQ-012.1, REQ-012.2, REQ-012.3, REQ-012.4, REQ-012.5, REQ-012.6, REQ-015.1, REQ-015.2, REQ-015.3_

- [ ] 5. [MUST] Add the controlled actual Composio Gmail send/fetch/reply demonstration, gated and conditioned on configured credentials.
  - 5.1 Add `tests/test_gmail_flow.py::test_live_controlled_send_fetch_reply_same_thread` marked `@pytest.mark.live`, skipped unless explicit user authorization plus `RUN_LIVE_TESTS=1` and `ALLOW_LIVE_VENDOR_EMAIL=true` are set AND Composio credentials are configured (skipped when unconfigured); it sends only to the configured `outreach_recipient_override`, then fetches and replies preserving the same Gmail `thread_id` across send/fetch/reply.
  - 5.2 Never label this fixture; assert the produced evidence carries the live-controlled depth label and that the offline fake-Composio test remains the default automated coverage.
  - _Requirements: REQ-024.1, REQ-024.2, REQ-024.3, REQ-024.4, REQ-024.6, REQ-012.7, REQ-034.2, REQ-034.3_

Coverage: M5 tasks cover REQ-012(reservation), REQ-015, REQ-024, REQ-025, REQ-026. (MUST 5, SHOULD 0, DEFER 0)

## M6 Durable HITL proof

**Requirements satisfied:** REQ-012, REQ-013, REQ-014, REQ-017
**Files to inspect:** `ops/graph.py`, `ops/run_service.py`, `ops/state.py`, `api/models.py`, `api/app.py`, `api/service.py`, `tests/test_boundaries.py`, `tests/test_secret_store.py`
**Files expected to change:** `ops/graph.py`, `ops/run_service.py`, `api/models.py`, `api/app.py`, `api/service.py`, and new `tests/test_hitl_resume.py`, `tests/test_checkpoint_secret_absence.py`
**Existing code to reuse:** `DurableOperationsWorkflow.resume`/`get_interrupts`/`_human_interrupt`/`_config`, `_resume_signal`, `_build_saver`/`EncryptedSerializer`, `HitlRequest`, `RunConflictResponse` (from M1), `validate_status_transition` (from M1)
**Security checks:** interrupt carries a server-issued `request_id`; stale/consumed/thread-mismatched/duplicate resumes rejected with `run_conflict` and no second `Command(resume=...)`; effectively-once across restart; checkpoint bytes contain no raw secret; only `vault://` refs and non-secret IDs in serialized state
**Exact verification commands:** `RUN_LIVE_TESTS=0 python -m pytest tests/test_hitl_resume.py tests/test_checkpoint_secret_absence.py -q`, `RUN_LIVE_TESTS=0 python -m pytest tests/test_boundaries.py tests/test_secret_store.py -q`, then `./scripts/security_gate.sh backend`
**Acceptance evidence:** `tests/test_hitl_resume.py::test_restart_resume_executes_side_effect_effectively_once` (interrupt -> close workflow/process -> reopen checkpoint -> same-thread resume -> one side effect), `::test_stale_or_consumed_request_id_returns_run_conflict`; `tests/test_checkpoint_secret_absence.py::test_decrypted_state_has_only_vault_refs`; observable: a resumed run reaches `completed`/`blocked` with exactly one effect-ledger `completed` receipt
**Suggested commit message:** `feat(hitl): canonical request_id resume contract with durable restart proof`
**Deferred work:** multi-interrupt chains beyond one HITL pause (DEFER); live browser HITL against a real portal (live-controlled)

- [ ] 1. [MUST] Extend the resume contract to `{request_id, signal}` in `api/models.py::ResumeRequest`.
  - 1.1 Add `request_id: Annotated[str, StringConstraints(pattern=r"^hitl_[A-Za-z0-9_-]{8,}$")]` and widen `signal` to `Literal["completed","cancelled","retry"]`.
  - 1.2 Update `api/app.py::resume_run` and `api/service.py::resume` to pass `request_id`+`signal` into `RunService.resume`.
  - _Requirements: REQ-013.1_

- [ ] 2. [MUST] Mint, store, and consume `request_id` in `ops/graph.py`/`ops/run_service.py`.
  - 2.1 In `DurableOperationsWorkflow._human_interrupt`, mint a server-issued `hitl_<opaque>` id, include it in the interrupt payload and mirror it (non-secret) into the ledger; on resume, validate the id is live, unconsumed, and thread-matched, else raise `RunConflictError`; mark it consumed before `Command(resume=...)` advances the graph.
  - 2.2 `retry` re-enters the interrupted node under effectively-once rules (re-reserve key, return stored receipt for a completed effect).
  - 2.3 Add `tests/test_hitl_resume.py::test_stale_or_consumed_request_id_returns_run_conflict`, `::test_thread_mismatched_request_id_rejected`, `::test_duplicate_resume_loses_and_returns_run_conflict`.
  - _Requirements: REQ-013.2, REQ-013.3, REQ-013.4, REQ-013.5, REQ-013.6, REQ-013.7, REQ-011.2_

- [ ] 3. [MUST] Add the durable restart/resume proof in `tests/test_hitl_resume.py`.
  - 3.1 `test_restart_resume_executes_side_effect_effectively_once`: start a run with a fake browser adapter to `waiting_for_hitl`, `close()` the workflow, reopen `build_graph` on the same `checkpoint_db_path`+key, resume the same `thread_id`, and assert the run completes with exactly one effect-ledger `completed` receipt.
  - 3.2 `test_resume_illegal_when_not_waiting_for_hitl` asserting rejection via `validate_status_transition`.
  - _Requirements: REQ-014.1, REQ-014.2, REQ-014.3, REQ-014.4, REQ-012.1, REQ-012.2_

- [ ] 4. [MUST] Add the strengthened checkpoint secret-absence test in `tests/test_checkpoint_secret_absence.py`.
  - 4.1 Inject a known test secret, run to a checkpoint, then: read the raw encrypted `checkpoints.db` bytes and assert the secret is absent from ciphertext-at-rest.
  - 4.2 Decrypt the checkpoint with the test AES key using the same `EncryptedSerializer`/`SqliteSaver` construction as `ops/graph.py::_build_saver`, inspect the serialized `OperationsState`, and assert only `vault://<app>/<kind>/<id>` refs and non-secret IDs are present; reject credential-shaped keys AND values on both sides of each mapping entry.
  - 4.3 Assert the raw value is absent from `runs`/`audit_events`/`side_effect_intents` bytes, the effect-ledger `receipt_json`, logs, API JSON, and rendered output.
  - _Requirements: REQ-017.1, REQ-017.2, REQ-017.3, REQ-017.4, REQ-017.5_

Coverage: M6 tasks cover REQ-012, REQ-013, REQ-014, REQ-017. (MUST 4, SHOULD 0, DEFER 0)

## M4B Ten-app P2 execution expansion

**Requirements satisfied:** REQ-020, REQ-022, REQ-023, REQ-024, REQ-029, REQ-035 (execution-backed), REQ-036 (ten demonstrations)
**Files to inspect:** `ops/run_service.py`, `ops/p1_adapter.py`, `ops/routing.py`, `ops/app_adapters/registry.py`, `ops/gmail_worker.py`, `ops/integrator.py`, `data/p1/SNAPSHOT.json`, `data/p1/results.json`, `data/p1/composio_coverage.json`, `tests/test_self_serve_adapter.py`, `tests/test_gmail_flow.py`, `tests/test_snapshot.py`
**Files expected to change:** a new read-only orchestration harness `ops/demo_matrix.py` (reuse-only, no new engine), `ops/run_service.py` (only if `execute_when_configured` needs a thin dispatch seam), and new `tests/test_ten_app_execution.py`
**Existing code to reuse:** `RunService.execute_when_configured`/`create_run`, `decide_access` (route categories), `ops/p1_adapter.py` verified-record loader, the M4 `AppAdapter` contract + `registry.py` + shared onboarding driver, the M5 gated Gmail flow, the M3 scope-selection helper, and `build_integrator_bundle`
**Security checks:** P1 records are loaded read-only and never regenerated or mutated; routing-only results are excluded from the primary ten-app count; every per-app result records either a standardized IntegratorBundle or a truthful external-blocker state (never fabricated success); default tests are offline-safe with fixtures; any live-controlled per-app attempt is gated (`RUN_LIVE_TESTS=1` + provider flag + explicit authorization) and is never labeled fixture
**Exact verification commands:** `RUN_LIVE_TESTS=0 python -m pytest tests/test_ten_app_execution.py -q`, `RUN_LIVE_TESTS=0 python -m pytest tests/test_self_serve_adapter.py tests/test_gmail_flow.py -q`, then `./scripts/security_gate.sh backend`
**Acceptance evidence:** `tests/test_ten_app_execution.py::test_ten_apps_selected_from_verified_p1_categories`, `::test_each_app_executes_not_only_routes`, `::test_each_app_records_bundle_or_external_blocker`, and `::test_routing_only_excluded_from_primary_count`; observable: ten verified P1 apps are dispatched through `execute_when_configured`, each producing a bundle or a truthful external-blocker outcome with a truthful depth label, and no routing-only result counts toward the primary ten
**Suggested commit message:** `feat(demo): execute ten selected P1 apps through P2 with truthful per-app outcomes`
**Deferred work:** live-controlled per-app runs for apps beyond the M4/M5 demonstrations (gated, opt-in); breadth beyond the ten selected apps (DEFER)

- [ ] 1. [MUST] Select the ten apps from the verified P1 snapshot via `decide_access` categories in a read-only `ops/demo_matrix.py::select_demo_apps`.
  - 1.1 Load verified records through `ops/p1_adapter.py` (provenance/hash-checked, read-only) and choose ten apps spanning self-serve, OAuth self-serve, gated, hybrid, and blocked/unknown using `decide_access`; favor mostly low-friction self-serve apps to maximize `credentials_ready` results. Never regenerate or mutate P1.
  - 1.2 Add `tests/test_ten_app_execution.py::test_ten_apps_selected_from_verified_p1_categories` asserting exactly ten apps, all five categories represented, and `data/p1/*` unchanged after selection.
  - _Requirements: REQ-035.1, REQ-035.3, REQ-036.7, REQ-028.3_

- [ ] 2. [MUST] Add a shared parametrized execution harness `ops/demo_matrix.py::run_demo_matrix` that EXECUTES each selected app through P2 by reusing existing components.
  - 2.1 For each app, call `RunService.execute_when_configured`, perform M3 scope selection, dispatch the self-serve path via the M4 `registry.py` shared driver OR the M5 gated Gmail flow, attempt account/developer-app/access setup, and capture+validate credentials where possible — with no bespoke per-app engine and no second run service.
  - 2.2 Add `tests/test_ten_app_execution.py::test_each_app_executes_not_only_routes` (offline, fixtures/fakes) asserting every app advances past `route_selected` into an execution attempt (self-serve driver or gated flow), not merely routing.
  - _Requirements: REQ-020.1, REQ-022.1, REQ-023.1, REQ-023.5, REQ-024.1, REQ-029.1_

- [ ] 3. [MUST] Record a truthful per-app outcome (standardized IntegratorBundle OR external-blocker state), excluding routing-only from the primary count.
  - 3.1 Persist for each app either a `credentials_ready`/reference-only `IntegratorBundle` via `build_integrator_bundle`, or a truthful external-blocker state (`configuration_required`/`blocked`) with reason; tag each with a truthful depth label (fixture-integration / local end-to-end / live-controlled) and never label a fixture live. A `route_selected`-only result is recorded as routing-only and excluded from the primary ten-app result.
  - 3.2 Add `tests/test_ten_app_execution.py::test_each_app_records_bundle_or_external_blocker` and `::test_routing_only_excluded_from_primary_count`.
  - _Requirements: REQ-029.5, REQ-029.7, REQ-035.2, REQ-035.4, REQ-036.7_

- [ ] 4. [SHOULD] Add a gated per-app live-controlled attempt path, skipped by default.
  - 4.1 Add `tests/test_ten_app_execution.py::test_live_controlled_per_app_attempt` marked `@pytest.mark.live`, skipped unless explicit authorization plus `RUN_LIVE_TESTS=1` and the relevant provider flag (`ALLOW_LIVE_BROWSER=true` or `ALLOW_LIVE_VENDOR_EMAIL=true`) are set; a live attempt produces a truthful bundle or external-blocker state labeled live-controlled and is never presented as fixture evidence.
  - _Requirements: REQ-035.4, REQ-034.2, REQ-034.3_

Coverage: M4B tasks cover REQ-020, REQ-022, REQ-023, REQ-024, REQ-029, REQ-035(execution-backed), REQ-036(ten demonstrations). (MUST 3, SHOULD 1, DEFER 0)

## M7 Frontend and demonstration

**Requirements satisfied:** REQ-005 (render), REQ-016 (no reveal), REQ-029 (refs), REQ-032, REQ-035
**Files to inspect:** `web/src/app/page.tsx`, `web/src/app/runs/**`, `web/src/app/apps/**`, `web/src/app/system/**`, `web/src/app/api/ops/**`, `web/src/lib/api.ts`, `web/src/lib/api-schemas.ts`, `web/src/lib/types.ts`, `web/src/components/phase-action-form.tsx`, `web/src/components/run-detail-panels.tsx`, `web/src/components/new-run-form.tsx`, `web/src/components/status-badge.tsx`, `web/package.json`
**Files expected to change:** `web/src/lib/types.ts`, `web/src/lib/api-schemas.ts`, `web/src/lib/api.ts`, `web/src/components/phase-action-form.tsx`, `web/src/components/run-detail-panels.tsx`, `web/src/components/new-run-form.tsx`, and test files `web/src/components/run-detail-panels.test.tsx`, `web/src/lib/frontend-security.test.ts`
**Existing code to reuse:** server-only `apiRequest`/`performPhaseAction`/`createRun`, Zod schemas (`runDetailResponseSchema`, `actionReceiptSchema`, `runOutputResponseSchema`), `PhaseConflictError`, `status-badge`, `run-detail-panels`, `phase-action-form`
**Security checks:** `OPS_API_URL` stays server-only; no run/credential data in browser storage; credential refs rendered as count/readiness only with no reveal control; no `dangerouslySetInnerHTML`; UI consumes API statuses and keeps no local transition table; `run_conflict`/`configuration_required` render as accessible non-failure notices
**Exact verification commands:** `cd web && npx vitest run src/lib/frontend-security.test.ts src/components/run-detail-panels.test.tsx`, then the affected full gate `./scripts/security_gate.sh frontend` (runs `npm audit`, `npm run lint`, `npm run typecheck`, `npm run test`, `npm run build`)
**Acceptance evidence:** `web/src/lib/frontend-security.test.ts` asserts `OPS_API_URL` is never in client output and credential refs render as count/readiness only; `web/src/components/run-detail-panels.test.tsx` asserts real resulting status (never `accepted`) and an accessible `run_conflict` notice; observable: the ten-app matrix view renders EXECUTED apps with evidence-depth labels and excludes routing-only from the primary count
**Suggested commit message:** `feat(web): render real statuses, HITL resume contract, and evidence-labeled executed matrix`
**Deferred work:** live-view browser embedding (never supported — refs only); real-time streaming updates (DEFER)

- [ ] 1. [MUST] Align the frontend contract with the backend real-status vocabulary.
  - 1.1 In `web/src/lib/types.ts` and `api-schemas.ts`, add `execute_when_configured`/`plan_only` presentation, remove `validating_credentials` from the status vocabulary, and update `ActionReceipt.status` to the real resulting set (drop `accepted`).
  - 1.2 Add `run_conflict` handling in `web/src/lib/api.ts` (409 branch) as a typed non-failure alongside `PhaseConflictError`.
  - 1.3 Update `web/src/lib/frontend-security.test.ts::rejects accepted status` (or add) to assert `accepted` and `validating_credentials` are not accepted by the schemas.
  - _Requirements: REQ-032.3, REQ-032.5, REQ-032.6, REQ-032.7, REQ-032.8_

- [ ] 2. [MUST] Render run header, phases, route, providers, and scope decision in `web/src/components/run-detail-panels.tsx`.
  - 2.1 Map `RunStatus` -> badge, `PhaseState[]` -> phase rail, `RouteDecisionView` -> route explanation, `ProviderState[]` -> provider panel, and the new `available/requested/selected/excluded` scopes -> a scope decision view; render `IntegratorBundleView.credential_refs` as count + readiness only with no reveal control.
  - 2.2 Add `web/src/components/run-detail-panels.test.tsx::renders credential refs as count only` and `::renders real resulting status not accepted`.
  - _Requirements: REQ-005.4, REQ-016.1, REQ-016.3, REQ-029.3, REQ-032.2, REQ-032.6_

- [ ] 3. [MUST] Add HITL controls carrying `{request_id, signal}` in `web/src/components/phase-action-form.tsx`.
  - 3.1 Extend `performPhaseAction`/the resume form to send `request_id` + `signal` (`completed|cancelled|retry`); render `run_conflict`/`configuration_required` as accessible non-failure explanations (semantic HTML, visible focus, keyboard support).
  - 3.2 Add `web/src/components/run-detail-panels.test.tsx::renders run_conflict as accessible non-failure notice`.
  - _Requirements: REQ-013.1, REQ-032.4, REQ-032.3_

- [ ] 4. [MUST] Add the app-name input and execution-mode selector to `web/src/components/new-run-form.tsx`.
  - 4.1 Add an app-name field and an `execution_mode` selector (default `plan_only`); keep validation via the existing React Hook Form + Zod path; never persist run data in browser storage.
  - 4.2 Extend the form test to assert `plan_only` default and server-only submission.
  - _Requirements: REQ-005.4, REQ-032.1_

- [ ] 5. [SHOULD] Add the ten-app matrix view of EXECUTED apps with evidence-depth labels under `web/src/app/apps/`.
  - 5.1 Render the ten executed P1 apps across self-serve, OAuth self-serve, gated, hybrid, and blocked/unknown, each labeled exactly one of routing-only / fixture-integration / local end-to-end / live-controlled from the M4B execution results; reflect EXECUTED outcomes (bundle or external-blocker), exclude routing-only from the primary count, and never label a non-live result live.
  - 5.2 Add a test asserting each cell carries exactly one depth label, all five categories are present, and routing-only results are visually separated from the primary executed ten.
  - _Requirements: REQ-035.1, REQ-035.2, REQ-035.3, REQ-035.4_

Coverage: M7 tasks cover REQ-005(render), REQ-016, REQ-029(refs), REQ-032, REQ-035. (MUST 4, SHOULD 1, DEFER 0)

## M2 Remaining production hardening

**Requirements satisfied:** REQ-008 (full), REQ-010 (full), REQ-011 (advanced), REQ-012 (reconciliation cleanup)
**Files to inspect:** `ops/run_service.py`, `ops/graph.py`, `ops/storage.py`, `ops/effect_ledger.py`, `ops/state.py`, `api/app.py`, `api/service.py`, `tests/test_storage_operations.py`, `tests/test_run_service.py`, `tests/test_projection.py`, `tests/test_run_conflict.py`, `tests/test_boundaries.py`
**Files expected to change:** `ops/run_service.py`, `ops/effect_ledger.py`, and new `tests/test_reconciliation.py`, `tests/test_concurrency_races.py`
**Existing code to reuse:** the M1 `validate_status_transition`, `RunService.project`/`startup`/`shutdown`, revision columns, `RunConflictResponse`, `SQLiteEffectStore.reserve`/`complete`/`mark_outcome_unknown`, `DurableOperationsWorkflow._lock`/`_database_lock`
**Security checks:** projection never overrides checkpoint/effect-ledger/vault; `external_actions` flips only on a `completed` receipt; reconciliation resolves ambiguous outcomes by a read (never blind resend); conflict paths perform no partial write and no external action
**Exact verification commands:** `RUN_LIVE_TESTS=0 python -m pytest tests/test_reconciliation.py tests/test_concurrency_races.py -q`, `RUN_LIVE_TESTS=0 python -m pytest tests/test_storage_operations.py tests/test_run_service.py tests/test_projection.py tests/test_run_conflict.py -q`, then `./scripts/security_gate.sh backend`
**Acceptance evidence:** `tests/test_reconciliation.py::test_checkpoint_ahead_replays_forward`, `::test_external_actions_flips_only_on_completed_receipt`, `::test_stale_projection_resolved_against_checkpoint`; `tests/test_concurrency_races.py::test_concurrent_command_property_no_partial_write`; `tests/test_storage_operations.py::test_effect_status_vocabulary_is_consistent`; observable: after simulated process death, all non-terminal runs reconcile to the authoritative checkpoint without double-applying
**Suggested commit message:** `feat(runtime): exhaustive reconciliation, concurrency coverage, and effect-ledger vocabulary cleanup`
**Deferred work:** none blocking. Note: the minimum safe versions of the transition validator, revision-guarded projection, lifespan ownership, and per-run command serialization + `run_conflict` already shipped in M1; this milestone only hardens breadth and edge cases off the critical path.

- [ ] 1. [SHOULD] Implement exhaustive four-database startup reconciliation across the full recovery matrix in `ops/run_service.py::startup`.
  - 1.1 For every non-terminal run, load checkpoint state (when workflow configured) and effect-ledger outcomes, recompute the projection to `max(checkpoint_revision, last_projected_revision)`, and flip `external_actions` only on an effect-ledger `completed` receipt; treat checkpoint as authoritative on disagreement; re-reserve the same idempotency key on resume for a completed/`outcome_unknown` effect the checkpoint predates rather than resending.
  - 1.2 Add `tests/test_reconciliation.py::test_checkpoint_ahead_replays_forward` and `::test_external_actions_flips_only_on_completed_receipt`.
  - _Requirements: REQ-008.1, REQ-008.2, REQ-008.3, REQ-008.5, REQ-010.1, REQ-010.2, REQ-010.3, REQ-010.4, REQ-010.6, REQ-012.7_

- [ ] 2. [SHOULD] Add advanced concurrent-command race coverage beyond the M1 minimum conflict guard.
  - 2.1 Add `tests/test_concurrency_races.py::test_concurrent_command_property_no_partial_write` and `::test_losing_writer_performs_no_external_action` as thorough concurrency/property tests exercising interleavings against the per-run `_lock` + optimistic `state_revision` guard.
  - _Requirements: REQ-011.1, REQ-011.4_

- [ ] 3. [SHOULD] Handle stale-ledger recovery edge cases.
  - 3.1 When `last_projected_revision > checkpoint_revision` for a live thread, flag the projection as stale and resolve it against the checkpoint rather than silently rewinding; correct the ledger only through a legal `validate_status_transition`.
  - 3.2 Add `tests/test_reconciliation.py::test_stale_projection_resolved_against_checkpoint`.
  - _Requirements: REQ-008.4, REQ-010.5_

- [ ] 4. [SHOULD] Reconcile the effect-ledger status-vocabulary mismatch called out in design §2 risks.
  - 4.1 In `ops/effect_ledger.py`, align the `EffectStatus` literal (`reserved|completed|reconcile_required`) with the DB CHECK (`pending|completed|outcome_unknown|failed`) by mapping stored `pending`->`reserved` and `outcome_unknown`->`reconcile_required` at the `reserve` boundary; add `tests/test_storage_operations.py::test_effect_status_vocabulary_is_consistent`.
  - _Requirements: REQ-012.1, REQ-012.5_

Coverage: M2 tasks cover REQ-008(full), REQ-010(full), REQ-011(advanced), REQ-012(reconciliation cleanup). Minimum safe versions of these primitives ship in M1. (MUST 0, SHOULD 4, DEFER 0)

## M8 Release evidence

**Requirements satisfied:** REQ-017, REQ-031, REQ-034, REQ-035, REQ-036, REQ-037 (release scope)
**Files to inspect:** `Makefile`, `pyproject.toml`, `scripts/security_gate.sh`, `.github/workflows/ci.yml`, `compose.yaml`, `Dockerfile.api`, `README.md`, `DECISIONS.md`, `.env.example`, `web/package.json`, `ops/demo_matrix.py`, all `tests/**`
**Files expected to change:** `README.md`, `.env.example`, and new `tests/test_completion_audit.py`, `tests/test_demo_matrix.py` (docs updated only for real behavior changes)
**Existing code to reuse:** `make test`/`make lint`/`make typecheck`/`make security`, `scripts/security_gate.sh {backend|frontend|all}`, `pytest -m live` marker, CI backend/frontend jobs, `SecurityState` truthfulness fields, `ops/demo_matrix.py` executed-app results
**Security checks:** default tests offline-safe and never call live providers; live tests require `RUN_LIVE_TESTS=1` + provider flags; no fixture labeled live; canonical P1 files never modified; strict `extra="forbid"` responses; no vault/env/path in responses
**Exact verification commands:** `make test` (`RUN_LIVE_TESTS=0 python -m pytest -q`), `make lint`, `make typecheck`, `make security` (`./scripts/security_gate.sh all` = backend + frontend gates), and `RUN_LIVE_TESTS=0 python -m pytest tests/test_completion_audit.py tests/test_demo_matrix.py -q`
**Acceptance evidence:** `tests/test_completion_audit.py::test_first_slice_alone_is_not_completion` and `::test_completion_requires_self_serve_gmail_hitl_scope_bundle_matrix`; `tests/test_demo_matrix.py::test_ten_apps_labeled_by_depth`; observable: `./scripts/security_gate.sh all` passes and README documents run instructions, env vars, the controlled demo script, known limitations, and the four evidence labels
**Suggested commit message:** `docs(release): completion checklist, demo script, and truthful evidence labels`
**Deferred work:** Docker image build/health (truthfully deferred per `DECISIONS.md` until a Docker-capable environment is available); live-controlled demonstration recordings (gated)

- [ ] 1. [MUST] Add the assignment-completion audit test in `tests/test_completion_audit.py`.
  - 1.1 `test_first_slice_alone_is_not_completion` asserts M1 wiring by itself does not satisfy completion; `test_completion_requires_self_serve_gmail_hitl_scope_bundle_matrix` asserts presence of one working self-serve flow, one controlled Gmail flow, one durable HITL demonstration, one tested scope-selection result, one `credentials_ready` bundle, and ten EXECUTED app demonstrations (routing-only excluded).
  - _Requirements: REQ-036.1, REQ-036.2, REQ-036.3, REQ-036.4, REQ-036.5, REQ-036.6, REQ-036.7_

- [ ] 2. [MUST] Add the ten-app matrix and truthfulness test in `tests/test_demo_matrix.py`.
  - 2.1 `test_ten_apps_labeled_by_depth` asserts the ten EXECUTED P1 apps (from `ops/demo_matrix.py`) span all five categories, each labeled exactly one of routing-only / fixture-integration / local end-to-end / live-controlled, that routing-only results are excluded from the primary executed count, and that no non-live result is labeled live.
  - 2.2 Add `::test_no_fixture_is_labeled_live` scanning fixtures for a live label.
  - _Requirements: REQ-034.3, REQ-034.4, REQ-035.1, REQ-035.2, REQ-035.3, REQ-035.4_

- [ ] 3. [MUST] Add an offline-safety and unsupported-capability gate test.
  - 3.1 Extend `tests/test_boundaries.py` (or add `tests/test_completion_audit.py::test_offline_safety_and_unsupported`) asserting default tests set `RUN_LIVE_TESTS=0`, the vault exposes no list/reveal/export method, no queue/worker module exists, and no exactly-once delivery claim is made.
  - 3.2 Assert challenge steps route to HITL and agent navigation is unsupported (reuse M4 boundary assertions).
  - _Requirements: REQ-034.1, REQ-034.2, REQ-037.1, REQ-037.2, REQ-037.3, REQ-037.5, REQ-037.6, REQ-016.3, REQ-017.1_

- [ ] 4. [MUST] Document run instructions, env vars, demo script, and known limitations in `README.md` and `.env.example`.
  - 4.1 Document `make api`/`make web`/`make security`, the four evidence labels, the controlled demo script, and known limitations; document every `ops/config.py::Settings` env var (`LANGGRAPH_AES_KEY`, `SECRET_VAULT_KEY`, `COMPOSIO_*`, `ALLOW_LIVE_VENDOR_EMAIL`, `ALLOW_LIVE_BROWSER`, `MAX_*`, DB paths) in `.env.example`.
  - 4.2 State completion is defined by executed behavior, not file presence; the first slice is an infrastructure milestone.
  - _Requirements: REQ-034.4, REQ-036.1_

- [ ] 5. [MUST] Confirm sanitized-response invariants under the full gate.
  - 5.1 Extend `tests/test_api.py`/`tests/test_api_operations.py` to assert `extra="forbid"` rejects drift, no vault/env/DB-path fields appear, and `no-store` + security headers are preserved; run `./scripts/security_gate.sh all`.
  - _Requirements: REQ-031.1, REQ-031.2, REQ-031.3_

Coverage: M8 tasks cover REQ-017, REQ-031, REQ-034, REQ-035, REQ-036, REQ-037(release). (MUST 5, SHOULD 0, DEFER 0)
