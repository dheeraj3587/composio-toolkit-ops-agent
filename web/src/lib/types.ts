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
export type AccountPolicy = "reuse_existing" | "create_if_missing"
export type DeveloperAppPolicy = "reuse_existing" | "create_if_missing"
export type CredentialPolicy = "reuse_existing" | "create_if_missing"
/** @deprecated Use CredentialPolicy. */
export type CredentialCreationPolicy = "reuse_only" | "create_if_missing"

export interface RunSummary {
  run_id: string
  thread_id: string
  app_name: string
  app_slug: string
  status: RunStatus
  access_route?: AccessRoute | null
  execution_mode: ExecutionMode
  browser_provider: BrowserProvider
  account_policy: AccountPolicy
  developer_app_policy: DeveloperAppPolicy
  credential_policy: CredentialPolicy
  /** @deprecated Transitional compatibility field from the API. */
  credential_creation_policy: CredentialCreationPolicy
  external_actions: boolean
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

/** Mirrors ops/models.py::OperationalUrlField exactly. */
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
  checkpoint_encryption?: string
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
}

export interface TimelineItem {
  event_id: number
  event_type: string
  summary: string
  status: "recorded" | "completed" | "blocked" | "failed"
  created_at: string
}

export interface TimelineResponse {
  run_id: string
  items: TimelineItem[]
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
}

export interface HealthResponse {
  status: "healthy" | "degraded"
  phase: string
  version: string
  snapshot: SnapshotHealth
  checks: HealthCheck[]
  providers?: ProviderStatus[]
}

export interface CompanyProfileInput {
  legal_name: string
  website: string
  work_email_ref: string
  use_case: string
  expected_volume: string | null
  callback_urls: string[]
}

export interface OperationsRequestInput {
  app_name: string
  company: CompanyProfileInput
  requested_scope_policy: "minimum" | "recommended" | "maximum"
  execution_mode: ExecutionMode
  browser_provider: BrowserProvider
  account_policy: AccountPolicy
  developer_app_policy: DeveloperAppPolicy
  credential_policy: CredentialPolicy
  outreach_recipient_override: string | null
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
 *   path before it can enter client state.
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

export interface ActionReceipt {
  run_id: string
  action: "resume" | "poll_email" | "retry"
  status: "accepted" | "configuration_required" | "unavailable" | "no_change"
  detail?: string | null
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

export interface AppResearchResponse {
  app: AppSearchItem
  research: OperationalResearch
  provenance?: SnapshotHealth | null
}
