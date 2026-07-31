import "server-only"

import { z } from "zod"

const MAX_URL_LENGTH = 2_048
const tokenBearingQuery = /^(?:access[_-]?token|api[_-]?key|auth(?:orization)?|client[_-]?(?:id|secret)|credentials?|key|secret|session(?:id)?|sig(?:nature)?|token)$/i

function safeHttpUrl(value: string): boolean {
  if (value.length > MAX_URL_LENGTH || /[\u0000-\u0020\u007f]/.test(value)) return false

  try {
    const parsed = new URL(value)
    if (!["http:", "https:"].includes(parsed.protocol)) return false
    if (parsed.username || parsed.password || !parsed.hostname) return false
    return [...parsed.searchParams.keys()].every((key) => !tokenBearingQuery.test(key))
  } catch {
    return false
  }
}

const boundedText = (maximum: number) => z.string().min(1).max(maximum)
const optionalText = (maximum: number) => z.string().max(maximum).nullable()
const nullableText = (maximum: number) => z.string().max(maximum).nullish().default(null)
const safeToken = z.string().regex(/^[a-z0-9][a-z0-9_.:-]{0,119}$/i)
const httpUrl = z.string().min(8).max(MAX_URL_LENGTH).refine(safeHttpUrl)
const nullableHttpUrl = httpUrl.nullish().default(null)
const nullableBoolean = z.boolean().nullish().default(null)
const isoTimestamp = z.string().max(80).refine((value) => !Number.isNaN(Date.parse(value)))
const runId = z.string().regex(/^run_[0-9a-f]{32}$/)
const appSlug = z.string().regex(/^[a-z0-9]+(?:-[a-z0-9]+)*$/)
const accessRoute = z.enum([
  "self_serve",
  "approval_required",
  "partner_gated",
  "hybrid",
  "blocked",
  "unknown",
])
const runStatus = z.enum([
  "created",
  "researching",
  "route_selected",
  "connection_required",
  "browser_running",
  "waiting_for_hitl",
  "outreach_sent",
  "waiting_for_reply",
  "credentials_ready",
  "configuration_required",
  "blocked",
  "failed",
  "completed",
])
// The wired browser backend and the view it can offer. Declared here because both
// the run-detail projection (BrowserUiState) and the live-view response use them.
export const browserProviderSchema = z.enum(["browser_use", "playwright"])
export const accountModeSchema = z.enum(["existing_account", "create_account"])
export const credentialCreationPolicySchema = z.enum(["reuse_only", "create_if_missing"])
export const routeKindSchema = z.enum(["managed_auth", "playwright", "gated"])
export const readinessTierSchema = z.enum([
  "managed_auth_ready",
  "browser_ready",
  "owner_submit_ready",
  "outreach_ready",
  "outreach_review_required",
])
export const primaryActionKindSchema = z.enum([
  "connect_account",
  "poll_connection",
  "open_browser",
  "submit_credentials",
  "review_outreach",
  "poll_reply",
  "none",
])
export const liveViewModeSchema = z.enum([
  "hosted_url",
  "screenshot",
  "interactive_remote",
  "unavailable",
])

const vaultReference = z
  .string()
  .min(12)
  .max(512)
  .regex(/^vault:\/\/[a-z0-9-]+\/[a-z0-9_-]+\/[A-Za-z0-9_-]+$/)

const scopeRequirement = z.strictObject({
  // Matches the backend ScopeRequirement bound (ops/core/models.py: max_length=300).
  name: boundedText(300),
  description: optionalText(2_000).optional(),
  required: z.boolean().nullable().optional(),
  source_url: httpUrl,
})

// Field-level evidence for the newer operational URLs (ops/core/models.py:
// OperationalUrlClaim). Defaults to an empty list on the backend.
const operationalUrlField = z.enum([
  "api_base_url",
  "authorization_url",
  "token_url",
  "developer_portal_url",
  "signup_url",
  "login_url",
  "credential_management_url",
  "contact_url",
])

const operationalUrlClaim = z.strictObject({
  field: operationalUrlField,
  url: httpUrl,
  source_url: httpUrl,
})

export { operationalUrlClaim, operationalUrlField }

export const operationalResearchSchema = z.strictObject({
  app_name: boundedText(200),
  app_slug: appSlug,
  api_available: nullableBoolean,
  api_type: boundedText(80),
  api_base_url: nullableHttpUrl,
  auth_methods: z.array(boundedText(120)).max(50),
  authorization_url: nullableHttpUrl,
  token_url: nullableHttpUrl,
  credential_fields: z.array(boundedText(120)).max(50),
  // Bounded, non-secret prose describing how to create the credential. Omitted
  // from the response when empty, so it defaults to an empty list here. Bounds
  // mirror ops/core/models.py (20 steps, 500 characters each).
  credential_creation_instructions: z.array(boundedText(500)).max(20).default([]),
  scopes: z.array(scopeRequirement).max(100),
  developer_portal_url: nullableHttpUrl,
  signup_url: nullableHttpUrl,
  login_url: nullableHttpUrl,
  credential_management_url: nullableHttpUrl,
  // Bound mirrors ops/core/models.py::OperationalResearch (max_length=32).
  operational_url_claims: z.array(operationalUrlClaim).max(32).default([]),
  access_route: accessRoute,
  production_approval_required: nullableBoolean,
  contact_email: nullableText(320),
  contact_url: nullableHttpUrl,
  evidence_urls: z.array(httpUrl).max(100),
  confidence: z.number().min(0).max(1),
  source: z.enum(["p1_snapshot", "official_enrichment", "combined", "unavailable"]).optional(),
  missing_fields: z.array(boundedText(120)).max(100).optional(),
})

export const runSummarySchema = z.strictObject({
  run_id: runId,
  thread_id: z.string().regex(/^[a-z0-9_-]{8,160}$/i),
  app_name: boundedText(200),
  app_slug: appSlug,
  status: runStatus,
  access_route: accessRoute.nullish(),
  created_at: isoTimestamp,
  updated_at: isoTimestamp,
  execution_mode: z.enum(["plan_only", "execute_when_configured"]),
  browser_provider: z.enum(["browser_use", "playwright"]),
  credential_creation_policy: credentialCreationPolicySchema.default("reuse_only"),
  recipe_version: boundedText(80).nullable().default(null),
  route_kind: routeKindSchema.nullable().default(null),
  readiness_tier: readinessTierSchema.nullable().default(null),
  attempt: z.number().int().nonnegative().default(0),
  phase: boundedText(120).default("legacy"),
  reason_code: safeToken.nullable().default(null),
  state_engine: z.enum(["canonical_v1", "legacy"]).default("legacy"),
  external_actions: z.boolean(),
  account_mode: accountModeSchema.nullish().default(null),
})

const primaryAction = z.strictObject({
  kind: primaryActionKindSchema,
  enabled: z.boolean(),
  reason_code: safeToken,
})

const phaseState = z.strictObject({
  key: safeToken.optional(),
  name: boundedText(80).optional(),
  phase: boundedText(40).optional(),
  status: safeToken.optional(),
  detail: optionalText(1_000).optional(),
  available: z.boolean().optional(),
  retryable: z.boolean().optional(),
  updated_at: isoTimestamp.nullable().optional(),
})

const phaseCollection = z.union([
  z.array(phaseState).max(20),
  z.record(safeToken, z.union([phaseState, safeToken, z.null()])),
  z.null(),
])

const securityState = z.strictObject({
  redaction: safeToken.optional(),
  secret_vault: safeToken.optional(), // pragma: allowlist secret
  operational_state_storage: safeToken.optional(),
  owner_only_storage: safeToken.optional(),
  live_vendor_email: safeToken.optional(),
  live_browser: safeToken.optional(),
  external_actions: z.boolean().optional(),
  raw_secrets_exposed: z.literal(false).optional(),
  notes: z.array(boundedText(500)).max(20).optional(),
})

const hitlRequest = z.strictObject({
  action_type: boundedText(120),
  message: boundedText(1_000),
  expected_completion_signal: boundedText(500),
  resumable: z.boolean(),
})

const routeDecision = z.strictObject({
  route: accessRoute,
  reason_code: safeToken,
  explanation: boundedText(1_000),
  is_final: z.boolean().optional(),
})

export const providerStatusSchema = z.strictObject({
  // The backend ProviderState status vocabulary (not_configured,
  // configured_not_verified, ready, disabled, schema_incompatible) is validated
  // as a bounded token rather than a fixed enum so new backend-reported states
  // render truthfully instead of being rejected as invalid responses.
  provider: safeToken,
  status: safeToken,
  detail: boundedText(500),
  reason_code: safeToken.nullish().default(null),
  checked_at: isoTimestamp.nullish().default(null),
  expires_at: isoTimestamp.nullish().default(null),
})

// Backend-authoritative browser capabilities (api/models.py::BrowserUiState).
// The interface renders these decisions; it never infers them from run.status.
export const browserLifecycleSchema = z.enum([
  "not_started",
  "running",
  "waiting_for_hitl",
  "credential_page_ready",
  "failed",
  "session_lost",
  "unavailable",
])

export const browserUiStateSchema = z.strictObject({
  provider: browserProviderSchema,
  lifecycle: browserLifecycleSchema,
  live_view_mode: liveViewModeSchema,
  live_view_available: z.boolean().default(false),
  interaction_available: z.boolean().default(false),
  screenshot_available: z.boolean().default(false),
  credential_page_verified: z.boolean().default(false),
  can_submit_login: z.boolean().default(false),
  can_submit_otp: z.boolean().default(false),
  can_resume: z.boolean().default(false),
  can_submit_credential: z.boolean().default(false),
  reason_code: z
    .string()
    .max(64)
    .regex(/^[a-z0-9][a-z0-9_:-]{0,63}$/)
    .nullish()
    .default(null),
})

// --- Onboarding projections (api/models.py, design LL-6.2) -------------------
// Every value below is a closed vocabulary, a digest, a bounded identifier, a
// counter, or a short decision-shaped label. There is no field for a prompt, a
// reasoning trace, or page content, so the sanitization boundary is mirrored
// here structurally rather than by review.

// A hex SHA-256 digest, exactly as the provider-profile digest produces it.
const sha256Digest = z.string().regex(/^[0-9a-f]{64}$/)
// A bounded, opaque identifier: run id, correlation id, browser session id, or
// the id segment of a vault reference. The class admits no whitespace.
const boundedIdentifier = z.string().regex(/^[A-Za-z0-9._-]{1,200}$/)
// A lowercase DNS hostname or registrable domain. Not a URL and not text.
const hostName = z
  .string()
  .min(4)
  .max(253)
  .regex(/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/)
// One allow-list entry: an exact host or a single-level vendor wildcard.
const hostPattern = z
  .string()
  .min(4)
  .max(255)
  .regex(/^(?:\*\.)?[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/)
// A discovery adapter's slug ("perplexity_search"), never its output.
const adapterName = z.string().regex(/^[a-z0-9][a-z0-9_-]{0,63}$/)
// A cited value: a URL, a registrable domain, or an enum member. The
// whitespace-free class is what keeps an excerpt out of the field.
const evidenceValue = z.string().min(1).max(2_000).regex(/^\S{1,2000}$/)

export const onboardingPhaseSchema = z.enum([
  "research",
  "vault_check",
  "awaiting_admission",
  "route_selected_login",
  "route_selected_signup",
  "signup",
  "email_verification",
  "authenticated",
  "developer_app",
  "credential_generation",
  "vault_storage",
  "credential_validation",
  "captcha_paused",
  "completed",
  "paused",
  "blocked",
  "cancelled",
])

export const retryableStepSchema = z.enum([
  "research",
  "signup",
  "email_verification",
  "developer_app",
  "credential_generation",
  "credential_validation",
])

export const approvalRequirementSchema = z.enum([
  "none",
  "manual_review",
  "invite_only",
  "unknown",
])
export const billingRequirementSchema = z.enum([
  "none",
  "card_required",
  "paid_plan_required",
  "unknown",
])
export const flowKindSchema = z.enum([
  "developer_app",
  "oauth",
  "api_key",
  "pat",
  "client_credentials",
])
export const credentialKindSchema = z.enum([
  "oauth_client_id",
  "oauth_client_secret",
  "api_key",
  "personal_access_token",
  "client_credentials_pair",
])
export const auxiliaryHostKindSchema = z.enum([
  "identity_provider",
  "static_assets",
  "email_link_host",
])
export const profileFieldSchema = z.enum([
  "registrable_domain",
  "developer_portal_url",
  "signup_url",
  "login_url",
  "developer_docs_url",
  "developer_app_flow",
  "oauth_flow",
  "api_key_flow",
  "pat_flow",
  "approval_requirement",
  "billing_requirement",
])

// api/models.py::OnboardingStateView. GET /api/runs/{id} does not exclude
// nulls, so every optional field is accepted as an explicit null.
export const onboardingStateSchema = z.strictObject({
  phase: onboardingPhaseSchema,
  phase_at_pause: onboardingPhaseSchema.nullish().default(null),
  profile_digest: sha256Digest,
  reason_code: safeToken.nullish().default(null),
  goal: z.string().max(200).default(""),
  step: z.string().max(200).default(""),
  // Decision-shaped ("Opening the developer portal"), never chain-of-thought.
  latest_decision: z.string().max(300).default(""),
  attempt: z.number().int().min(0).max(1_000),
  admission_prompts: z.number().int().min(0).max(1),
  captcha_prompts: z.number().int().min(0).max(1_000),
  correlation_id: boundedIdentifier,
})

// api/models.py::OnboardingControlsView. Each flag is a backend decision, so
// the console renders it rather than inferring availability from run status.
export const onboardingControlsSchema = z.strictObject({
  can_decide_admission: z.boolean().default(false),
  can_pause: z.boolean().default(false),
  can_resume: z.boolean().default(false),
  can_cancel: z.boolean().default(false),
  can_reset: z.boolean().default(false),
  can_retry_step: z.boolean().default(false),
  retryable_step: retryableStepSchema.nullish().default(null),
  reason_code: safeToken.nullish().default(null),
  resume_withheld_reason: safeToken.nullish().default(null),
})

// api/models.py::AutonomyOutcomeView, projected once the run is terminal.
export const autonomyOutcomeSchema = z.strictObject({
  verdict: z.enum(["fully_autonomous", "operator_assisted", "blocked", "cancelled"]),
  terminal_phase: onboardingPhaseSchema,
  reason_code: safeToken,
  admission_prompts: z.number().int().min(0).max(1),
  captcha_prompts: z.number().int().min(0).max(1_000),
  duration_seconds: z.number().int().min(0).max(86_400),
})

// --- Onboarding operator control responses (api/models.py, design LL-6.3) ----
// One response schema per control. Like the projections above, every field is a
// closed vocabulary, a digest, a bounded identifier, a counter, or a boolean, so
// the console can render an outcome without any free-text field existing.

export const admissionRouteSchema = z.enum(["login", "signup", "cancelled"])
export const admissionDeciderSchema = z.enum(["system", "operator"])
export const onboardingEffectSchema = z.enum([
  "signup_submit",
  "create_dev_app",
  "generate_credential",
])
export const expectedRestartRouteSchema = z.enum(["login", "signup", "undetermined"])

// api/models.py::AdmissionDecisionResponse — the decision as it was durably
// recorded. `replayed` means the run already held a decision and nothing was
// rewritten, which is what makes a double submit safe to render truthfully.
export const admissionDecisionResponseSchema = z.strictObject({
  run_id: boundedIdentifier,
  route: admissionRouteSchema,
  reason_code: safeToken,
  decided_by: admissionDeciderSchema,
  decided_at: isoTimestamp,
  replayed: z.boolean().default(false),
  onboarding: onboardingStateSchema,
})

// api/models.py::PauseResponse. `browser_session_released` is literally false:
// a pause keeps the authenticated session the operator returns to.
export const pauseResponseSchema = z.strictObject({
  run_id: boundedIdentifier,
  accepted: z.boolean(),
  pausing_after_phase: onboardingPhaseSchema,
  reason_code: safeToken,
  browser_session_released: z.literal(false).default(false),
  onboarding: onboardingStateSchema,
})

// api/models.py::ResetResponse — the four facts an operator needs to trust a
// reset, including the count of vault references it preserved.
export const resetResponseSchema = z.strictObject({
  run_id: boundedIdentifier,
  reason_code: safeToken,
  phase: onboardingPhaseSchema,
  browser_session_released: z.boolean(),
  workflow_state_cleared: z.boolean(),
  vault_references_preserved: z.number().int().min(0).max(64),
  expected_route_on_restart: expectedRestartRouteSchema,
})

// api/models.py::RetryStepResponse — what the retry re-attempted, and the
// effects the ledger proved it must skip.
export const retryStepResponseSchema = z.strictObject({
  run_id: boundedIdentifier,
  accepted: z.boolean(),
  phase: onboardingPhaseSchema,
  attempt: z.number().int().min(0).max(1_000),
  reason_code: safeToken,
  skipped_effects: z.array(onboardingEffectSchema).max(8).default([]),
})

// api/models.py::FlowSpecView — one credential-producing path on the
// provider's own site.
const flowSpec = z.strictObject({
  kind: flowKindSchema,
  supported: z.boolean(),
  entry_url: nullableHttpUrl,
  steps: z.array(boundedText(200)).max(8).default([]),
  produces: z.array(credentialKindSchema).max(4).default([]),
  requires_approval: z.boolean().default(false),
  requires_billing: z.boolean().default(false),
})

// api/models.py::FieldEvidenceView — why one profile field is believed. Carries
// the citation and its digest, never the cited excerpt.
const fieldEvidence = z.strictObject({
  field: profileFieldSchema,
  value: evidenceValue,
  source_url: httpUrl,
  source_digest: sha256Digest,
  adapters: z.array(adapterName).max(8),
  corroborations: z.number().int().min(1).max(64),
  confidence: z.number().min(0).max(1),
})

const auxiliaryHost = z.strictObject({ host: hostName, kind: auxiliaryHostKindSchema })

// api/models.py::ProviderProfileView, served by GET /api/runs/{id}/profile with
// nulls excluded, so an absent URL is omitted rather than sent as null.
export const providerProfileResponseSchema = z.strictObject({
  run_id: boundedIdentifier,
  profile_digest: sha256Digest,
  provider_name: z.string().max(200),
  app_slug: appSlug,
  registrable_domain: hostName,
  allowed_host_patterns: z.array(hostPattern).max(32),
  auxiliary_hosts: z.array(auxiliaryHost).max(16).default([]),
  developer_portal_url: nullableHttpUrl,
  signup_url: nullableHttpUrl,
  login_url: nullableHttpUrl,
  developer_docs_url: nullableHttpUrl,
  flows: z.array(flowSpec).max(5),
  approval_requirement: approvalRequirementSchema,
  billing_requirement: billingRequirementSchema,
  evidence: z.array(fieldEvidence).max(64),
  confidence: z.number().min(0).max(1),
  built_at: isoTimestamp,
})

export const runDetailResponseSchema = z.strictObject({
  run: runSummarySchema,
  research: operationalResearchSchema.nullable(),
  phases: phaseCollection,
  security: securityState.nullable(),
  route_decision: routeDecision.nullish(),
  hitl_request: hitlRequest.nullish(),
  missing_fields: z.array(boundedText(120)).max(100).optional(),
  provider_states: z.array(providerStatusSchema).max(30).optional(),
  // Optional so an older backend still parses; always sent by this API.
  browser: browserUiStateSchema.nullish().default(null),
  primary_action: primaryAction.nullish().default(null),
  // Onboarding projections. All three are absent (sent as null) on a legacy
  // run; autonomy is present only once the run reaches a terminal phase.
  onboarding: onboardingStateSchema.nullish().default(null),
  controls: onboardingControlsSchema.nullish().default(null),
  autonomy: autonomyOutcomeSchema.nullish().default(null),
})

const managedRedirectUrl = z.string().min(8).max(MAX_URL_LENGTH).refine((value) => {
  if (/[\u0000-\u0020\u007f]/.test(value)) return false
  try {
    const parsed = new URL(value)
    return parsed.protocol === "https:" && !parsed.username && !parsed.password && !!parsed.hostname
  } catch {
    return false
  }
})

export const managedConnectionResponseSchema = z.strictObject({
  run: runSummarySchema,
  connection_request_id: boundedText(200),
  state: z.enum(["pending", "active", "terminal"]),
  // This URL is consumed immediately by a server redirect. OAuth query values
  // may be opaque, so it intentionally uses a dedicated HTTPS-only validator.
  redirect_url: managedRedirectUrl.nullish().default(null),
  replayed: z.boolean().default(false),
})

export const runListResponseSchema = z.strictObject({
  items: z.array(runSummarySchema).max(100),
  total: z.number().int().nonnegative(),
  limit: z.number().int().min(1).max(100),
  offset: z.number().int().nonnegative(),
})

// api/models.py::TimelineCorrelation — the correlation set carried by every
// onboarding event. No vault reference value, no live URL, no page text.
const timelineCorrelation = z.strictObject({
  run_id: boundedIdentifier,
  correlation_id: boundedIdentifier,
  onboarding_phase: onboardingPhaseSchema,
  profile_digest: sha256Digest,
  attempt: z.number().int().min(0).max(1_000),
  reason_code: safeToken,
  browser_session_id: boundedIdentifier.nullish().default(null),
  vault_reference_id: boundedIdentifier.nullish().default(null),
})

// api/models.py::TimelineDetail — a closed union of non-secret detail fields.
// Every member is an enum, a host, an HTTPS URL, an identifier, a timestamp, or
// a counter, so the absence of free text is structural.
const timelineDetail = z.strictObject({
  adapters_engaged: z.array(adapterName).max(8).nullish().default(null),
  registrable_domain: hostName.nullish().default(null),
  evidence_count: z.number().int().min(0).max(64).nullish().default(null),
  credentials_present: z.boolean().nullish().default(null),
  decision: z.enum(["create_account", "cancel"]).nullish().default(null),
  decided_by: z.enum(["system", "operator"]).nullish().default(null),
  host: hostName.nullish().default(null),
  sender_domain: hostName.nullish().default(null),
  verification_kind: z.enum(["link", "code"]).nullish().default(null),
  developer_app_id: boundedIdentifier.nullish().default(null),
  credential_kind: credentialKindSchema.nullish().default(null),
  validation_endpoint: nullableHttpUrl,
  validation_http_status: z.number().int().min(100).max(599).nullish().default(null),
  checked_at: isoTimestamp.nullish().default(null),
  duration_seconds: z.number().int().min(0).max(86_400).nullish().default(null),
  verdict: z
    .enum(["fully_autonomous", "operator_assisted", "blocked", "cancelled"])
    .nullish()
    .default(null),
})

const loopStageSchema = z.enum([
  "observe",
  "candidates",
  "decide",
  "act",
  "verify",
  "gate",
  "exhausted",
])

const runProgressEventSchema = z.strictObject({
  step_index: z.number().int().min(1).max(100_000),
  stage: loopStageSchema,
  elapsed_ms: z.number().int().min(0).max(3_600_000),
  onboarding_phase: onboardingPhaseSchema,
  recorded_at: isoTimestamp,
})

export const timelineResponseSchema = z.strictObject({
  run_id: runId,
  items: z
    .array(
      z.strictObject({
        event_id: z.number().int().positive(),
        event_type: safeToken,
        summary: boundedText(500),
        status: z.enum(["recorded", "completed", "blocked", "failed"]),
        created_at: isoTimestamp,
        // Onboarding attribution. Both are absent on a legacy event, and the
        // timeline route serializes that absence as an explicit null.
        correlation: timelineCorrelation.nullish().default(null),
        detail: timelineDetail.nullish().default(null),
      }),
    )
    .max(1_000),
  progress: z.array(runProgressEventSchema).max(200).default([]),
})

const integratorBundle = z.strictObject({
  app_name: boundedText(200),
  app_slug: appSlug,
  readiness: z.enum([
    "credentials_ready",
    "awaiting_provider",
    "human_action_required",
    "configuration_required",
    "blocked",
    "failed",
  ]),
  api_type: boundedText(80),
  api_base_url: httpUrl.nullish(),
  auth_scheme: boundedText(120),
  authorization_url: httpUrl.nullish(),
  token_url: httpUrl.nullish(),
  scopes: z.array(boundedText(300)).max(100),
  callback_urls: z.array(httpUrl).max(20),
  credential_refs: z.record(z.string().regex(/^[A-Za-z0-9_-]{1,120}$/), vaultReference),
  access_route: accessRoute,
  provider_account_id: boundedText(200).nullish(),
  developer_app_id: boundedText(200).nullish(),
  evidence_urls: z.array(httpUrl).max(100),
  operational_notes: z.array(boundedText(1_000)).max(100),
  created_at: isoTimestamp,
})

export const runOutputResponseSchema = z.strictObject({
  run_id: runId,
  integrator_bundle: integratorBundle,
})

export const snapshotHealthSchema = z.strictObject({
  verified: z.boolean(),
  source_repository: boundedText(300).optional(),
  source_commit: z.string().regex(/^[0-9a-f]{40}$/).optional(),
  copied_at: isoTimestamp.optional(),
  results_sha256: z.string().regex(/^[0-9a-f]{64}$/).optional(),
  coverage_sha256: z.string().regex(/^[0-9a-f]{64}$/).optional(),
})

export const browserServiceHealthViewSchema = z.strictObject({
  state: safeToken,
  reason_code: safeToken,
  version: boundedText(40),
  chromium_installed: z.boolean(),
  context_launch_ok: z.boolean(),
  capacity_total: z.number().int().nonnegative(),
  capacity_in_use: z.number().int().nonnegative(),
  janitor_running: z.boolean(),
})

export const healthResponseSchema = z.strictObject({
  status: z.enum(["healthy", "degraded"]),
  phase: boundedText(40),
  version: boundedText(40),
  snapshot: snapshotHealthSchema,
  checks: z
    .array(
      z.strictObject({
        name: boundedText(120),
        status: z.enum(["pass", "fail", "configuration_required", "disabled"]),
        detail: optionalText(500).optional(),
      }),
    )
    .max(50),
  providers: z.array(providerStatusSchema).max(30).optional(),
  browser_service: browserServiceHealthViewSchema.nullish().default(null),
})

export const actionReceiptSchema = z.strictObject({
  run_id: runId,
  // `cancel` is additive: cancelling an onboarding run releases its browser
  // session and reports through this same receipt (design LL-6.3).
  action: z.enum(["resume", "poll_email", "retry", "send_outreach", "cancel"]),
  status: z.enum(["accepted", "configuration_required", "unavailable", "no_change"]),
  detail: optionalText(500).optional(),
  // Present only for an onboarding run, so the console learns the phase the
  // command landed in without re-reading the run.
  onboarding: onboardingStateSchema.nullish().default(null),
})

// A signed hosted live-view URL may carry an opaque signature query, so the
// token-bearing-query rejection is intentionally not applied here. It is a
// short-lived owner-only URL and is never persisted client-side.
const liveViewUrl = z
  .string()
  .min(8)
  .max(MAX_URL_LENGTH)
  .refine((value) => {
    if (/[\u0000-\u0020\u007f]/.test(value)) return false
    try {
      const parsed = new URL(value)
      return parsed.protocol === "https:" && !parsed.username && !parsed.password && !!parsed.hostname
    } catch {
      return false
    }
  })

// A bounded, same-origin RELATIVE viewer path (api/models.py::RelativeViewerPath).
// Deliberately NOT a URL: an absolute address — including the private
// browser-service/noVNC host on the internal network — is rejected outright, so
// the browser can only ever be pointed back at this origin.
const relativeViewerPath = (endpoint: "screenshot" | "interactive") =>
  z
    .string()
    .min(1)
    .max(300)
    .regex(new RegExp(`^/api/runs/[A-Za-z0-9_-]{1,180}/live-view/${endpoint}$`))

// The API-to-Next hop may carry one private, short-lived noVNC grant. This
// schema lives in a server-only module and accepts only the reviewed browser
// service endpoint with exactly one bounded session and token parameter. The
// value is converted to a same-origin path before any client state is created.
const privateInteractiveGrant = z.string().min(1).max(4_096).superRefine((value, context) => {
  let parsed: URL

  try {
    parsed = new URL(value)
  } catch {
    context.addIssue({ code: "custom", message: "The interactive grant URL is invalid." })
    return
  }

  const queryKeys = [...parsed.searchParams.keys()]
  const session = parsed.searchParams.get("session")
  const token = parsed.searchParams.get("token")
  const validEndpoint =
    parsed.protocol === "http:" &&
    parsed.hostname === "browser-worker" &&
    parsed.port === "8081" &&
    parsed.pathname === "/internal/browser/live-view/novnc" &&
    parsed.username === "" &&
    parsed.password === "" &&
    parsed.hash === ""
  const validQuery =
    queryKeys.length === 2 &&
    new Set(queryKeys).size === 2 &&
    queryKeys.includes("session") &&
    queryKeys.includes("token") &&
    session !== null &&
    /^[A-Za-z0-9_-]{1,180}$/.test(session) &&
    token !== null &&
    token.length > 0 &&
    token.length <= 2_048 &&
    !/[\u0000-\u001f\u007f]/.test(token)

  if (!validEndpoint || !validQuery) {
    context.addIssue({ code: "custom", message: "The interactive grant URL is not allowed." })
  }
})

// Provider- and mode-aware live view (api/models.py::LiveViewResponse). The
// mode-specific requirements are mirrored here so a drifting backend response is
// rejected as invalid rather than rendered as a broken viewer.
export const liveViewResponseSchema = z
  .strictObject({
    run_id: runId,
    provider: browserProviderSchema,
    available: z.boolean(),
    mode: liveViewModeSchema,
    live_url: liveViewUrl.nullish().default(null),
    screenshot_url: relativeViewerPath("screenshot").nullish().default(null),
    interactive_url: privateInteractiveGrant.nullish().default(null),
    captured_at: isoTimestamp.nullish().default(null),
    interaction_available: z.boolean(),
    reason_code: z
      .string()
      .max(64)
      .regex(/^[a-z0-9][a-z0-9_:-]{0,63}$/)
      .nullish()
      .default(null),
  })
  .superRefine((value, context) => {
    const viewerUrls = {
      hosted_url: { field: "live_url", url: value.live_url },
      screenshot: { field: "screenshot_url", url: value.screenshot_url },
      interactive_remote: { field: "interactive_url", url: value.interactive_url },
    } as const

    if (value.mode === "unavailable") {
      for (const { field, url } of Object.values(viewerUrls)) {
        if (url) {
          context.addIssue({
            code: "custom",
            path: [field],
            message: "An unavailable live view must not carry a viewer URL.",
          })
        }
      }
      if (value.available || value.interaction_available) {
        context.addIssue({
          code: "custom",
          path: ["available"],
          message: "An unavailable live view cannot be available or interactive.",
        })
      }
      return
    }

    if (!viewerUrls[value.mode].url) {
      context.addIssue({
        code: "custom",
        path: ["mode"],
        message: `Live view mode '${value.mode}' requires its matching viewer URL.`,
      })
    }
    if (!value.available) {
      context.addIssue({
        code: "custom",
        path: ["available"],
        message: `Live view mode '${value.mode}' must report available=true.`,
      })
    }
    // Masked frames can be viewed but not driven.
    if (value.mode === "screenshot" && value.interaction_available) {
      context.addIssue({
        code: "custom",
        path: ["interaction_available"],
        message: "A screenshot live view is not interactive.",
      })
    }
    // A Playwright remote stream may deliberately be view-only while autonomous
    // work is running. The signed grant and browser service enforce that mode;
    // this boolean controls only whether the UI exposes input affordances.
    // Screenshot routes remain bound to THIS run. Interactive grants are bound
    // by their signed browser-service session token and revalidated server-side.
    if (
      value.screenshot_url &&
      !value.screenshot_url.startsWith(`/api/runs/${value.run_id}/`)
    ) {
      context.addIssue({
        code: "custom",
        path: ["run_id"],
        message: "A viewer path must address this run on the same origin.",
      })
    }
  })

export const appSearchItemSchema = z.strictObject({
  app_name: boundedText(200),
  app_slug: appSlug,
  category: boundedText(120).nullable(),
  api_type: boundedText(80).nullable().default(null),
  access_route: accessRoute.nullable().default(null),
  auth_methods: z.array(boundedText(120)).max(50).default([]),
  confidence: z.number().min(0).max(1).nullable().default(null),
  buildability: safeToken,
  verification_status: safeToken,
})

export const appSearchResponseSchema = z.strictObject({
  query: z.string().max(200),
  items: z.array(appSearchItemSchema).max(100),
  total: z.number().int().nonnegative(),
})

export const appCatalogResponseSchema = z.strictObject({
  // The whole verified snapshot, so the bound is the catalog size rather than a
  // page of matches.
  items: z.array(appSearchItemSchema).max(500),
  total: z.number().int().nonnegative(),
})

export const appResearchResponseSchema = z.strictObject({
  app: appSearchItemSchema,
  research: operationalResearchSchema,
  provenance: snapshotHealthSchema.nullish(),
})
