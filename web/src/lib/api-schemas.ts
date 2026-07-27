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
  "self_serve_with_hitl",
  "approval_required",
  "partner_gated",
  "hybrid",
  "blocked",
  "unsupported",
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
// The wired browser backend and the view it can offer. Declared here because both
// the run-detail projection (BrowserUiState) and the live-view response use them.
export const browserProviderSchema = z.enum(["browser_use", "playwright"])
export const accountPolicySchema = z.enum(["reuse_existing", "create_if_missing"])
export const developerAppPolicySchema = z.enum(["reuse_existing", "create_if_missing"])
export const credentialPolicySchema = z.enum(["reuse_existing", "create_if_missing"])
export const credentialCreationPolicySchema = z.enum(["reuse_only", "create_if_missing"])
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
  // Matches the backend ScopeRequirement bound (ops/models.py: max_length=300).
  name: boundedText(300),
  description: optionalText(2_000).optional(),
  required: z.boolean().nullable().optional(),
  source_url: httpUrl,
})

// Field-level evidence for the newer operational URLs (ops/models.py:
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
  // mirror ops/models.py (20 steps, 500 characters each).
  credential_creation_instructions: z.array(boundedText(500)).max(20).default([]),
  scopes: z.array(scopeRequirement).max(100),
  developer_portal_url: nullableHttpUrl,
  signup_url: nullableHttpUrl,
  login_url: nullableHttpUrl,
  credential_management_url: nullableHttpUrl,
  // Bound mirrors ops/models.py::OperationalResearch (max_length=32).
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
  account_policy: accountPolicySchema.default("reuse_existing"),
  developer_app_policy: developerAppPolicySchema.default("reuse_existing"),
  credential_policy: credentialPolicySchema.default("reuse_existing"),
  credential_creation_policy: credentialCreationPolicySchema.default("reuse_only"),
  external_actions: z.boolean(),
})
