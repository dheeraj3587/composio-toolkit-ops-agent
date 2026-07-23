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
const vaultReference = z
  .string()
  .min(12)
  .max(512)
  .regex(/^vault:\/\/[a-z0-9-]+\/[a-z0-9_-]+\/[A-Za-z0-9_-]+$/)

const scopeRequirement = z.strictObject({
  name: boundedText(200),
  description: optionalText(2_000).optional(),
  required: z.boolean().nullable().optional(),
  source_url: httpUrl,
})

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
  scopes: z.array(scopeRequirement).max(100),
  developer_portal_url: nullableHttpUrl,
  signup_url: nullableHttpUrl,
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
  external_actions: z.boolean(),
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
  checkpoint_encryption: safeToken.optional(),
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

const providerStatus = z.strictObject({
  // The backend ProviderState status vocabulary (not_configured,
  // configured_not_verified, ready, disabled, schema_incompatible) is validated
  // as a bounded token rather than a fixed enum so new backend-reported states
  // render truthfully instead of being rejected as invalid responses.
  provider: safeToken,
  status: safeToken,
  detail: boundedText(500),
})

export const runDetailResponseSchema = z.strictObject({
  run: runSummarySchema,
  research: operationalResearchSchema.nullable(),
  phases: phaseCollection,
  security: securityState.nullable(),
  route_decision: routeDecision.nullish(),
  hitl_request: hitlRequest.nullish(),
  missing_fields: z.array(boundedText(120)).max(100).optional(),
  provider_states: z.array(providerStatus).max(30).optional(),
})

export const runListResponseSchema = z.strictObject({
  items: z.array(runSummarySchema).max(100),
  total: z.number().int().nonnegative(),
  limit: z.number().int().min(1).max(100),
  offset: z.number().int().nonnegative(),
})

export const timelineResponseSchema = z.strictObject({
  run_id: runId,
  items: z
    .array(
      z.strictObject({
        event_type: safeToken,
        summary: boundedText(500),
        status: z.enum(["recorded", "completed", "blocked", "failed"]),
        created_at: isoTimestamp,
      }),
    )
    .max(1_000),
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
  providers: z.array(providerStatus).max(30).optional(),
})

export const actionReceiptSchema = z.strictObject({
  run_id: runId,
  action: z.enum(["resume", "poll_email", "retry"]),
  status: z.enum(["accepted", "configuration_required", "unavailable", "no_change"]),
  detail: optionalText(500).optional(),
})

// The signed Browser Use live-view URL may carry an opaque signature query, so
// the token-bearing-query rejection is intentionally not applied here. It is a
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

export const liveViewResponseSchema = z.strictObject({
  run_id: runId,
  available: z.boolean(),
  live_url: liveViewUrl.nullable().optional(),
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

export const appResearchResponseSchema = z.strictObject({
  app: appSearchItemSchema,
  research: operationalResearchSchema,
  provenance: snapshotHealthSchema.nullish(),
})
