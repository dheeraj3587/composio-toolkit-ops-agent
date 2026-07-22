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
const httpUrl = z.string().min(8).max(MAX_URL_LENGTH).refine(safeHttpUrl)
const optionalHttpUrl = httpUrl.nullable()
const isoTimestamp = z.iso.datetime({ offset: true })
const runId = z.string().regex(/^run_[0-9a-f]{32}$/)
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
  description: optionalText(2_000),
  required: z.boolean().nullable(),
  source_url: httpUrl,
})

const operationalResearch = z.strictObject({
  app_name: boundedText(200),
  app_slug: z.string().regex(/^[a-z0-9]+(?:-[a-z0-9]+)*$/),
  api_available: z.boolean().nullable(),
  api_type: boundedText(80),
  api_base_url: optionalHttpUrl,
  auth_methods: z.array(boundedText(120)).max(50),
  authorization_url: optionalHttpUrl,
  token_url: optionalHttpUrl,
  credential_fields: z.array(boundedText(120)).max(50),
  scopes: z.array(scopeRequirement).max(100),
  developer_portal_url: optionalHttpUrl,
  signup_url: optionalHttpUrl,
  access_route: accessRoute,
  production_approval_required: z.boolean().nullable(),
  contact_email: optionalText(320),
  contact_url: optionalHttpUrl,
  evidence_urls: z.array(httpUrl).max(100),
  confidence: z.number().min(0).max(1),
})

const runSummary = z.strictObject({
  run_id: runId,
  thread_id: z.string().regex(/^local_[0-9a-f]{32}$/),
  app_name: boundedText(200),
  app_slug: z.string().regex(/^[a-z0-9]+(?:-[a-z0-9]+)*$/),
  status: runStatus,
  access_route: accessRoute.nullish(),
  created_at: isoTimestamp,
  updated_at: isoTimestamp,
  execution_mode: z.enum(["local_dry_run", "operations"]),
  external_actions: z.literal(false),
})

const phaseState = z.strictObject({
  key: z.enum(["research", "browser", "hitl", "email", "output"]),
  name: boundedText(80),
  phase: boundedText(20),
  status: z.enum(["ready", "waiting", "unavailable"]),
  detail: boundedText(1_000),
  available: z.boolean(),
})

const securityState = z.strictObject({
  redaction: z.literal("enabled"),
  secret_vault: z.literal("not_initialized"), // pragma: allowlist secret
  owner_only_storage: z.enum(["verified_owner_only", "verification_failed"]),
  live_vendor_email: z.literal("disabled_in_phase_2"),
  external_actions: z.literal(false),
  raw_secrets_exposed: z.literal(false),
  notes: z.array(boundedText(500)).max(20),
})

export const runDetailResponseSchema = z.strictObject({
  run: runSummary,
  research: operationalResearch.nullable(),
  phases: z.array(phaseState).max(8).nullable(),
  security: securityState.nullable(),
})

export const runListResponseSchema = z.strictObject({
  items: z.array(runSummary).max(100),
  total: z.number().int().nonnegative(),
  limit: z.number().int().min(1).max(100),
  offset: z.number().int().nonnegative(),
})

export const timelineResponseSchema = z.strictObject({
  run_id: runId,
  items: z
    .array(
      z.strictObject({
        event_type: boundedText(80),
        summary: boundedText(500),
        status: z.enum(["recorded", "completed", "blocked", "failed"]),
        created_at: isoTimestamp,
      }),
    )
    .max(1_000),
})

const integratorBundle = z.strictObject({
  app_name: boundedText(200),
  app_slug: z.string().regex(/^[a-z0-9]+(?:-[a-z0-9]+)*$/),
  readiness: z.enum([
    "credentials_ready",
    "awaiting_provider",
    "human_action_required",
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
  evidence_urls: z.array(httpUrl).max(100),
  operational_notes: z.array(boundedText(1_000)).max(100),
  created_at: isoTimestamp,
})

export const runOutputResponseSchema = z.strictObject({
  run_id: runId,
  integrator_bundle: integratorBundle,
})

const snapshotHealth = z.strictObject({
  verified: z.boolean(),
  source_repository: boundedText(300).optional(),
  source_commit: z.string().regex(/^[0-9a-f]{40}$/).optional(),
  copied_at: isoTimestamp.optional(),
  results_sha256: z.string().regex(/^[0-9a-f]{64}$/).optional(),
  coverage_sha256: z.string().regex(/^[0-9a-f]{64}$/).optional(),
})

export const healthResponseSchema = z.strictObject({
  status: z.enum(["healthy", "degraded"]),
  phase: z.literal("2"),
  version: z.literal("0.1.0"),
  snapshot: snapshotHealth,
  checks: z
    .array(
      z.strictObject({
        name: boundedText(120),
        status: z.enum(["pass", "fail"]),
      }),
    )
    .max(50),
})

export const actionReceiptSchema = z.strictObject({
  run_id: runId,
  action: z.enum(["resume", "poll_email"]),
  status: z.literal("accepted"),
})
