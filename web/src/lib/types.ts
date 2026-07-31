export type AccessRoute =
  | "self_serve"
  | "approval_required"
  | "partner_gated"
  | "hybrid"
  | "blocked"
  | "unknown"

export type RunStatus =
  | "created"
  | "researching"
  | "route_selected"
  | "connection_required"
  | "browser_running"
  | "waiting_for_hitl"
  | "outreach_sent"
  | "waiting_for_reply"
  | "credentials_ready"
  | "configuration_required"
  | "blocked"
  | "failed"
  | "completed"

export type ExecutionMode = "plan_only" | "execute_when_configured"
export type AccountMode = "existing_account" | "create_account"
export type CredentialCreationPolicy = "reuse_only" | "create_if_missing"
export type RouteKind = "managed_auth" | "playwright" | "gated"
export type ReadinessTier =
  | "managed_auth_ready"
  | "browser_ready"
  | "owner_submit_ready"
  | "outreach_ready"
  | "outreach_review_required"
export type StateEngine = "canonical_v1" | "legacy"
export type PrimaryActionKind =
  | "connect_account"
  | "poll_connection"
  | "open_browser"
  | "submit_credentials"
  | "review_outreach"
  | "poll_reply"
  | "none"

export interface PrimaryAction {
  kind: PrimaryActionKind
  enabled: boolean
  reason_code: string
}

export interface RunSummary {
  run_id: string
  thread_id: string
  app_name: string
  app_slug: string
  status: RunStatus
  access_route?: AccessRoute | null
  execution_mode: ExecutionMode
  browser_provider: BrowserProvider
  credential_creation_policy: CredentialCreationPolicy
  recipe_version: string | null
  route_kind: RouteKind | null
  readiness_tier: ReadinessTier | null
  attempt: number
  phase: string
  reason_code: string | null
  state_engine: StateEngine
  external_actions: boolean
  account_mode?: AccountMode | null
  created_at: string
  updated_at: string
}

export interface RunListResponse {
  items: RunSummary[]
  total: number
  limit: number
  offset: number
}

export interface ScopeRequirement {
  name: string
  description?: string | null
  required?: boolean | null
  source_url: string
}

/** Mirrors ops/core/models.py::OperationalUrlField exactly. */
export type OperationalUrlField =
  | "api_base_url"
  | "authorization_url"
  | "token_url"
  | "developer_portal_url"
  | "signup_url"
  | "login_url"
  | "credential_management_url"
  | "contact_url"

/** @deprecated Use {@link OperationalUrlField}. */
export type OperationalUrlFieldName = OperationalUrlField

/** Field-level evidence that an operational URL is documented on `source_url`. */
export interface OperationalUrlClaim {
  field: OperationalUrlField
  url: string
  source_url: string
}

export interface OperationalResearch {
  app_name: string
  app_slug: string
  api_available: boolean | null
  api_type: string
  api_base_url: string | null
  auth_methods: string[]
  authorization_url: string | null
  token_url: string | null
  credential_fields: string[]
  credential_creation_instructions: string[]
  scopes: ScopeRequirement[]
  developer_portal_url: string | null
  signup_url: string | null
  login_url: string | null
  credential_management_url: string | null
  operational_url_claims: OperationalUrlClaim[]
  access_route: AccessRoute
  production_approval_required: boolean | null
  contact_email: string | null
  contact_url: string | null
  evidence_urls: string[]
  confidence: number
  source?: "p1_snapshot" | "official_enrichment" | "combined" | "unavailable"
  missing_fields?: string[]
}

export type PhaseStatus =
  | "not_started"
  | "unavailable"
  | "configuration_required"
  | "ready"
  | "running"
  | "waiting"
  | "blocked"
  | "failed"
  | "complete"

export interface PhaseState {
  key?: string
  name?: string
  phase?: string
  status?: PhaseStatus | string
  detail?: string | null
  available?: boolean
  retryable?: boolean
  updated_at?: string | null
}

export type PhaseCollection = PhaseState[] | Record<string, PhaseState | string | null> | null

export interface SecurityState {
  redaction?: string
  secret_vault?: string
  operational_state_storage?: string
  owner_only_storage?: string
  live_vendor_email?: string
  live_browser?: string
  external_actions?: boolean
  raw_secrets_exposed?: false
  notes?: string[]
}

export interface HitlRequest {
  action_type: string
  message: string
  expected_completion_signal: string
  resumable: boolean
}

export interface RouteDecision {
  route: AccessRoute
  reason_code: string
  explanation: string
  is_final?: boolean
}

/** The browser session lifecycle as the backend recorded it. */
export type BrowserLifecycle =
  | "not_started"
  | "running"
  | "waiting_for_hitl"
  | "credential_page_ready"
  | "failed"
  | "session_lost"
  | "unavailable"

/**
 * Backend-authoritative browser capabilities for one run
 * (api/models.py::BrowserUiState). Each boolean is a backend decision: the
 * interface must render these rather than infer permissions from `run.status`.
 */
export interface BrowserUiState {
  provider: BrowserProvider
  lifecycle: BrowserLifecycle
  live_view_mode: LiveViewMode
  live_view_available: boolean
  interaction_available: boolean
  screenshot_available: boolean
  credential_page_verified: boolean
  can_submit_login: boolean
  can_submit_otp: boolean
  can_resume: boolean
  can_submit_credential: boolean
  reason_code?: string | null
}

/** The durable position inside the onboarding walk (ops/onboarding/phase.py). */
export type OnboardingPhase =
  | "research"
  | "vault_check"
  | "awaiting_admission"
  | "route_selected_login"
  | "route_selected_signup"
  | "signup"
  | "email_verification"
  | "authenticated"
  | "developer_app"
  | "credential_generation"
  | "vault_storage"
  | "credential_validation"
  | "captcha_paused"
  | "completed"
  | "paused"
  | "blocked"
  | "cancelled"

/** The steps an operator may re-attempt in place (api/models.py::RetryableStep). */
export type RetryableStep =
  | "research"
  | "signup"
  | "email_verification"
  | "developer_app"
  | "credential_generation"
  | "credential_validation"

/**
 * The onboarding sub-state projected onto the run detail response
 * (api/models.py::OnboardingStateView). `goal`, `step`, and `latest_decision`
 * are short decision-shaped labels, never prompts or reasoning traces.
 */
export interface OnboardingStateView {
  phase: OnboardingPhase
  phase_at_pause?: OnboardingPhase | null
  profile_digest: string
  reason_code?: string | null
  goal: string
  step: string
  latest_decision: string
  attempt: number
  admission_prompts: number
  captcha_prompts: number
  correlation_id: string
}

/**
 * Backend-projected control availability (api/models.py::OnboardingControlsView).
 * Each flag is a decision: the console never infers a control from run status.
 */
export interface OnboardingControlsView {
  can_decide_admission: boolean
  can_pause: boolean
  can_resume: boolean
  can_cancel: boolean
  can_reset: boolean
  can_retry_step: boolean
  retryable_step?: RetryableStep | null
  reason_code?: string | null
  resume_withheld_reason?: string | null
}

/** The operator's answer to the one admission prompt (ops/onboarding/admission.py). */
export type AdmissionInput = "create_account" | "cancel"
export type AdmissionRoute = "login" | "signup" | "cancelled"
export type AdmissionDecider = "system" | "operator"
/** A provider-visible effect the ledger can prove was already performed. */
export type OnboardingEffect = "signup_submit" | "create_dev_app" | "generate_credential"
export type ExpectedRestartRoute = "login" | "signup" | "undetermined"

/** The recorded admission decision (api/models.py::AdmissionDecisionResponse). */
export interface AdmissionDecisionResponse {
  run_id: string
  route: AdmissionRoute
  reason_code: string
  decided_by: AdmissionDecider
  decided_at: string
  // True when the run already held a decision; the body is then the ORIGINAL
  // record and nothing was rewritten.
  replayed: boolean
  onboarding: OnboardingStateView
}

/** Where a pause takes effect (api/models.py::PauseResponse). */
export interface PauseResponse {
  run_id: string
  accepted: boolean
  pausing_after_phase: OnboardingPhase
  reason_code: string
  // Always false: a pause keeps the authenticated browser session alive.
  browser_session_released: false
  onboarding: OnboardingStateView
}

/** The four facts that make a reset trustworthy (api/models.py::ResetResponse). */
export interface ResetResponse {
  run_id: string
  reason_code: string
  phase: OnboardingPhase
  browser_session_released: boolean
  workflow_state_cleared: boolean
  vault_references_preserved: number
  expected_route_on_restart: ExpectedRestartRoute
}

/** What a step retry re-attempted (api/models.py::RetryStepResponse). */
export interface RetryStepResponse {
  run_id: string
  accepted: boolean
  phase: OnboardingPhase
  attempt: number
  reason_code: string
  skipped_effects: OnboardingEffect[]
}

/** The durable per-run autonomy record, projected once the run is terminal. */
export interface AutonomyOutcomeView {
  verdict: "fully_autonomous" | "operator_assisted" | "blocked" | "cancelled"
  terminal_phase: OnboardingPhase
  reason_code: string
  admission_prompts: number
  captcha_prompts: number
  duration_seconds: number
}

export type ApprovalRequirement = "none" | "manual_review" | "invite_only" | "unknown"
export type BillingRequirement = "none" | "card_required" | "paid_plan_required" | "unknown"
export type FlowKind = "developer_app" | "oauth" | "api_key" | "pat" | "client_credentials"
export type CredentialKind =
  | "oauth_client_id"
  | "oauth_client_secret"
  | "api_key"
  | "personal_access_token"
  | "client_credentials_pair"
export type AuxiliaryHostKind = "identity_provider" | "static_assets" | "email_link_host"
export type ProfileField =
  | "registrable_domain"
  | "developer_portal_url"
  | "signup_url"
  | "login_url"
  | "developer_docs_url"
  | "developer_app_flow"
  | "oauth_flow"
  | "api_key_flow"
  | "pat_flow"
  | "approval_requirement"
  | "billing_requirement"

/** One credential-producing path through the provider's own site. */
export interface FlowSpecView {
  kind: FlowKind
  supported: boolean
  entry_url?: string | null
  steps: string[]
  produces: CredentialKind[]
  requires_approval: boolean
  requires_billing: boolean
}

/** Why one profile field is believed: the citation and its digest, never the excerpt. */
export interface FieldEvidenceView {
  field: ProfileField
  value: string
  source_url: string
  source_digest: string
  adapters: string[]
  corroborations: number
  confidence: number
}

export interface AuxiliaryHostView {
  host: string
  kind: AuxiliaryHostKind
}

/**
 * The sanitized provider profile served by `GET /api/runs/{id}/profile`
 * (api/models.py::ProviderProfileView). It deliberately omits raw evidence
 * excerpts, prompts, adapter responses, and anything carrying page content.
 */
export interface ProviderProfileView {
  run_id: string
  profile_digest: string
  provider_name: string
  app_slug: string
  registrable_domain: string
  allowed_host_patterns: string[]
  auxiliary_hosts: AuxiliaryHostView[]
  developer_portal_url?: string | null
  signup_url?: string | null
  login_url?: string | null
  developer_docs_url?: string | null
  flows: FlowSpecView[]
  approval_requirement: ApprovalRequirement
  billing_requirement: BillingRequirement
  evidence: FieldEvidenceView[]
  confidence: number
  built_at: string
}

export interface RunDetailResponse {
  run: RunSummary
  research: OperationalResearch | null
  phases: PhaseCollection
  security: SecurityState | null
  route_decision?: RouteDecision | null
  hitl_request?: HitlRequest | null
  missing_fields?: string[]
  provider_states?: ProviderStatus[]
  browser?: BrowserUiState | null
  primary_action?: PrimaryAction | null
  // Onboarding projections: absent on a legacy run; `autonomy` is present only
  // once the run reaches a terminal phase.
  onboarding?: OnboardingStateView | null
  controls?: OnboardingControlsView | null
  autonomy?: AutonomyOutcomeView | null
}

export interface ManagedConnectionResponse {
  run: RunSummary
  connection_request_id: string
  state: "pending" | "active" | "terminal"
  redirect_url?: string | null
  replayed: boolean
}

/** Correlation attribution carried by an onboarding timeline event. */
export interface TimelineCorrelation {
  run_id: string
  correlation_id: string
  onboarding_phase: OnboardingPhase
  profile_digest: string
  attempt: number
  reason_code: string
  browser_session_id?: string | null
  vault_reference_id?: string | null
}

/** A closed union of non-secret timeline detail fields (no free text). */
export interface TimelineDetail {
  adapters_engaged?: string[] | null
  registrable_domain?: string | null
  evidence_count?: number | null
  credentials_present?: boolean | null
  decision?: "create_account" | "cancel" | null
  decided_by?: "system" | "operator" | null
  host?: string | null
  sender_domain?: string | null
  verification_kind?: "link" | "code" | null
  developer_app_id?: string | null
  credential_kind?: CredentialKind | null
  validation_endpoint?: string | null
  validation_http_status?: number | null
  checked_at?: string | null
  duration_seconds?: number | null
  verdict?: "fully_autonomous" | "operator_assisted" | "blocked" | "cancelled" | null
}

export interface TimelineItem {
  event_id: number
  event_type: string
  summary: string
  status: "recorded" | "completed" | "blocked" | "failed"
  created_at: string
  correlation?: TimelineCorrelation | null
  detail?: TimelineDetail | null
}

export type LoopStage =
  | "observe"
  | "candidates"
  | "decide"
  | "act"
  | "verify"
  | "gate"
  | "exhausted"

export interface RunProgressEvent {
  step_index: number
  stage: LoopStage
  elapsed_ms: number
  onboarding_phase: OnboardingPhase
  recorded_at: string
}

export interface TimelineResponse {
  run_id: string
  items: TimelineItem[]
  progress: RunProgressEvent[]
}

export interface SnapshotHealth {
  verified: boolean
  source_repository?: string
  source_commit?: string
  copied_at?: string
  results_sha256?: string
  coverage_sha256?: string
}

export interface HealthCheck {
  name: string
  status: "pass" | "fail" | "configuration_required" | "disabled"
  detail?: string | null
}

export interface ProviderStatus {
  provider: string
  // Backend emits: not_configured | disabled | configured_not_verified | ready |
  // schema_incompatible. Kept as a string so the interface renders the exact
  // backend-reported status without silently dropping unmapped values.
  status: string
  detail: string
  reason_code?: string | null
  checked_at?: string | null
  expires_at?: string | null
}

export interface BrowserServiceHealthView {
  state: string
  reason_code: string
  version: string
  chromium_installed: boolean
  context_launch_ok: boolean
  capacity_total: number
  capacity_in_use: number
  janitor_running: boolean
}

export interface HealthResponse {
  status: "healthy" | "degraded"
  phase: string
  version: string
  snapshot: SnapshotHealth
  checks: HealthCheck[]
  providers?: ProviderStatus[]
  browser_service?: BrowserServiceHealthView | null
}

export interface CompanyProfileInput {
  legal_name: string
  website: string
  work_email_ref?: string | null
  use_case: string
  expected_volume: string | null
  callback_urls: string[]
}

export interface OperationsRequestInput {
  app_name: string
  account_mode: AccountMode
  company: CompanyProfileInput
  requested_scope_policy: "minimum" | "recommended" | "maximum"
  execution_mode: ExecutionMode
  browser_provider: BrowserProvider
  credential_creation_policy: CredentialCreationPolicy
  // Optional app sign-in credentials for autonomous login. Injected into
  // the selected provider's secret boundary at session creation; never persisted.
  browser_login?: { email: string; password: string } | null
}

export interface IntegratorOutput {
  app_name: string
  app_slug: string
  readiness:
  | "credentials_ready"
  | "awaiting_provider"
  | "human_action_required"
  | "configuration_required"
  | "blocked"
  | "failed"
  api_type: string
  api_base_url?: string | null
  auth_scheme: string
  authorization_url?: string | null
  token_url?: string | null
  scopes: string[]
  callback_urls: string[]
  credential_refs: Record<string, string>
  access_route: AccessRoute
  provider_account_id?: string | null
  developer_app_id?: string | null
  evidence_urls: string[]
  operational_notes: string[]
  created_at: string
}

export interface RunOutputResponse {
  run_id: string
  integrator_bundle: IntegratorOutput
}

/** The browser backend the API actually has wired (api/models.py::BrowserProvider). */
export type BrowserProvider = "browser_use" | "playwright"

/** How the owner can watch, and possibly drive, a live browser session. */
export type LiveViewMode = "hosted_url" | "screenshot" | "interactive_remote" | "unavailable"

/**
 * Live view for a browser run. The viewer URL present depends on `mode`:
 * - `hosted_url`: a hosted provider (Browser Use) supplies a signed `live_url`,
 *   which the owner can interact with directly.
 * - `screenshot`: the self-hosted Playwright service has no hosted URL, so the
 *   client polls `screenshot_url` for masked PNG frames (cache-busted by
 *   `captured_at`). Frames are viewable only, so `interaction_available` is false.
 * - `interactive_remote`: the private browser service supplies a short-lived,
 *   signed grant. Server-only code validates and converts it to a same-origin
 *   path before it can enter client state. The stream can be view-only while
 *   automation runs; `interaction_available` truthfully reports control.
 * - `unavailable`: no viewer exists and no viewer URL is present.
 *
 * `screenshot_url` is a bounded same-origin relative API path. `interactive_url`
 * is an internal-only grant and must never be passed directly to browser code.
 */
export interface LiveViewResponse {
  run_id: string
  provider: BrowserProvider
  available: boolean
  mode: LiveViewMode
  live_url?: string | null
  screenshot_url?: string | null
  interactive_url?: string | null
  captured_at?: string | null
  interaction_available: boolean
  reason_code?: string | null
}

export type RunPhaseAction = "resume" | "poll-email" | "retry"
export type RetryCapability = "research" | "browser" | "email" | "validation"
export type BrowserVerificationInput =
  | { code: string; url?: never }
  | { code?: never; url: string }

export interface ActionReceipt {
  run_id: string
  action: "resume" | "poll_email" | "retry" | "send_outreach" | "cancel"
  status: "accepted" | "configuration_required" | "unavailable" | "no_change"
  detail?: string | null
  // Present only for an onboarding run: the phase the command landed in.
  onboarding?: OnboardingStateView | null
}

export interface PhaseConflict {
  code: string
  phase: string | null
  action: string | null
  available_in: string[]
  external_actions: boolean | null
  message?: string | null
}

export interface AppSearchItem {
  app_name: string
  app_slug: string
  category: string | null
  api_type: string | null
  access_route: AccessRoute | null
  auth_methods: string[]
  confidence: number | null
  buildability: string
  verification_status: string
}

export interface AppSearchResponse {
  query: string
  items: AppSearchItem[]
  total: number
}

export interface AppCatalogResponse {
  items: AppSearchItem[]
  total: number
}

export interface AppCapabilitiesResponse {
  app_slug: string
  account_creation_supported: boolean
  reason_code: "reviewed_signup_route" | "signup_route_unavailable"
}

export interface AppResearchResponse {
  app: AppSearchItem
  research: OperationalResearch
  provenance?: SnapshotHealth | null
}
