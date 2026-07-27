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

export const runDetailResponseSchema = z.strictObject({
  run: runSummarySchema,
  research: operationalResearchSchema.nullable(),
  phases: phaseCollection,
  security: securityState.nullable(),
  route_decision: routeDecision.nullish(),
  hitl_request: hitlRequest.nullish(),
  missing_fields: z.array(boundedText(120)).max(100).optional(),
  provider_states: z.array(providerStatus).max(30).optional(),
  // Optional so an older backend still parses; always sent by this API.
  browser: browserUiStateSchema.nullish().default(null),
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
        event_id: z.number().int().positive(),
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
    if (value.mode === "interactive_remote" && !value.interaction_available) {
      context.addIssue({
        code: "custom",
        path: ["interaction_available"],
        message: "An interactive remote view must allow interaction.",
      })
    }
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
