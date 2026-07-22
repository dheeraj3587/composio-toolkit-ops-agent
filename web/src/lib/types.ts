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
  | "validating_credentials"
  | "credentials_ready"
  | "configuration_required"
  | "blocked"
  | "failed"
  | "completed"

export type ExecutionMode = "local_dry_run" | "operations"

export interface RunSummary {
  run_id: string
  thread_id: string
  app_name: string
  app_slug: string
  status: RunStatus
  access_route?: AccessRoute | null
  execution_mode: ExecutionMode
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
  scopes: ScopeRequirement[]
  developer_portal_url: string | null
  signup_url: string | null
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
  kind: "captcha" | "otp" | "legal_approval" | "billing" | "identity" | "manual_review" | "other"
  title: string
  instruction: string
  requested_at?: string | null
  expires_at?: string | null
}

export interface RouteDecision {
  route: AccessRoute
  reason_code: string
  explanation: string
  is_final?: boolean
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
}

export interface TimelineItem {
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
  status: "ready" | "configured" | "configuration_required" | "disabled" | "unavailable"
  detail: string
  live_tested?: boolean
}

export interface HealthResponse {
  status: "healthy" | "degraded" | "configuration_required"
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
  dry_run: true
  outreach_recipient_override: string | null
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
  evidence_urls: string[]
  operational_notes: string[]
  created_at: string
}

export interface RunOutputResponse {
  run_id: string
  integrator_bundle: IntegratorOutput
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

export interface AppResearchResponse {
  app: AppSearchItem
  research: OperationalResearch
  provenance?: SnapshotHealth | null
}
