import "server-only"

import type { ZodType } from "zod"

import {
  actionReceiptSchema,
  admissionDecisionResponseSchema,
  appCatalogResponseSchema,
  appResearchResponseSchema,
  appSearchResponseSchema,
  healthResponseSchema,
  liveViewResponseSchema,
  managedConnectionResponseSchema,
  pauseResponseSchema,
  providerProfileResponseSchema,
  providerStatusSchema,
  resetResponseSchema,
  retryStepResponseSchema,
  runDetailResponseSchema,
  runListResponseSchema,
  runOutputResponseSchema,
  timelineResponseSchema,
} from "@/lib/api-schemas"
import type {
  ActionReceipt,
  AdmissionDecisionResponse,
  AdmissionInput,
  AppCatalogResponse,
  AppResearchResponse,
  AppSearchResponse,
  BrowserVerificationInput,
  CompanyProfileInput,
  HealthResponse,
  IntegratorOutput,
  LiveViewResponse,
  ManagedConnectionResponse,
  OnboardingPhase,
  OperationsRequestInput,
  PauseResponse,
  PhaseConflict,
  ProviderProfileView,
  ProviderStatus,
  ResetResponse,
  RetryStepResponse,
  RunDetailResponse,
  RunListResponse,
  RunPhaseAction,
  RetryCapability,
  TimelineResponse,
} from "@/lib/types"

const CREDENTIAL_FIELD_PATTERN = /^[a-z0-9][a-z0-9_-]{0,99}$/
const RUN_ID_PATTERN = /^run_[0-9a-f]{32}$/
const SHA256_DIGEST_PATTERN = /^[0-9a-f]{64}$/

const DEFAULT_API_ORIGIN = "http://127.0.0.1:8000"
const REQUEST_TIMEOUT_MS = 8_000
// execute_when_configured runs (and same-session resume) can drive a real
// browser task on the backend, which routinely exceeds the normal API bound.
function runActionTimeoutMs(): number {
  const parsed = Number.parseInt(process.env.OPS_RUN_ACTION_TIMEOUT_MS ?? "", 10)
  return Number.isFinite(parsed) && parsed >= 30_000 && parsed <= 600_000
    ? parsed
    : 330_000
}
const RUN_ACTION_TIMEOUT_MS = runActionTimeoutMs()
const CREDENTIAL_TIMEOUT_MS = 30_000
const PROVIDER_READINESS_TIMEOUT_MS = 35_000
const SCREENSHOT_TIMEOUT_MS = 10_000
const MAX_SCREENSHOT_BYTES = 5 * 1024 * 1024
const IDEMPOTENCY_KEY_PATTERN = /^idem_[0-9a-f]{32}$/
const PNG_SIGNATURE = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a] as const

export class ApiError extends Error {
  constructor(
    public readonly status: number,
    public readonly code: string,
    message = "The operations API did not complete the request.",
  ) {
    super(message)
    this.name = "ApiError"
  }
}

export class PhaseConflictError extends ApiError {
  constructor(public readonly conflict: PhaseConflict) {
    super(409, conflict.code, "This phase cannot run from the current state.")
    this.name = "PhaseConflictError"
  }
}

function apiOrigin(): string {
  const configured = process.env.OPS_API_URL?.trim() || DEFAULT_API_ORIGIN
  let parsed: URL

  try {
    parsed = new URL(configured)
  } catch {
    throw new ApiError(503, "INVALID_API_ORIGIN", "OPS_API_URL is not a valid origin.")
  }

  if (
    !["http:", "https:"].includes(parsed.protocol) ||
    parsed.pathname !== "/" ||
    parsed.search !== "" ||
    parsed.hash !== "" ||
    parsed.username !== "" ||
    parsed.password !== ""
  ) {
    throw new ApiError(503, "INVALID_API_ORIGIN", "OPS_API_URL must be an HTTP origin.")
  }

  return parsed.origin
}

function internalApiToken(): string {
  const token = process.env.OPS_INTERNAL_API_TOKEN?.trim()
  if (!token) {
    throw new ApiError(503, "INTERNAL_API_TOKEN_MISSING", "The operations API token is not configured.")
  }
  return token
}

function record(value: unknown): Record<string, unknown> | null {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null
}

function textField(value: unknown, fallback: string): string {
  return typeof value === "string" && value.length <= 80 ? value : fallback
}

function safeToken(value: unknown): string | null {
  return typeof value === "string" && /^[a-z0-9_-]{1,64}$/i.test(value) ? value : null
}

async function responseBody(response: Response): Promise<unknown> {
  const contentType = response.headers.get("content-type") ?? ""
  if (!contentType.includes("application/json")) return null
  return response.json().catch(() => null)
}

async function apiRequest<T>(
  path: string,
  schema: ZodType<T>,
  init?: RequestInit,
  timeoutMs: number = REQUEST_TIMEOUT_MS,
): Promise<T> {
  let response: Response

  try {
    response = await fetch(`${apiOrigin()}${path}`, {
      ...init,
      cache: "no-store",
      headers: {
        Accept: "application/json",
        "X-Ops-Internal-Token": internalApiToken(),
        ...(init?.body ? { "Content-Type": "application/json" } : {}),
        ...init?.headers,
      },
      signal: AbortSignal.timeout(timeoutMs),
    })
  } catch (error) {
    if (error instanceof ApiError) throw error
    throw new ApiError(503, "API_UNREACHABLE", "The operations API is not reachable.")
  }

  const body = await responseBody(response)

  if (!response.ok) {
    const envelope = record(body)
    const detail = record(envelope?.detail) ?? envelope
    const code = textField(detail?.code ?? detail?.error, `HTTP_${response.status}`)

    if (response.status === 409) {
      const availableIn = Array.isArray(detail?.available_in)
        ? detail.available_in.map(safeToken).filter((item): item is string => item !== null)
        : []
      throw new PhaseConflictError({
        code,
        phase: safeToken(detail?.phase),
        action: safeToken(detail?.action),
        available_in: availableIn,
        external_actions:
          typeof detail?.external_actions === "boolean" ? detail.external_actions : null,
        message: typeof detail?.message === "string" ? detail.message.slice(0, 240) : null,
      })
    }

    throw new ApiError(response.status, code)
  }

  const parsed = schema.safeParse(body)
  if (!parsed.success) {
    throw new ApiError(
      502,
      "INVALID_API_RESPONSE",
      "The operations API returned an invalid response.",
    )
  }
  return parsed.data
}

function runPath(runId: string, suffix = ""): string {
  return `/api/runs/${encodeURIComponent(runId)}${suffix}`
}

export function getHealth(): Promise<HealthResponse> {
  return apiRequest("/api/system/health", healthResponseSchema)
}

export function getSignupReadiness(): Promise<ProviderStatus> {
  return apiRequest(
    "/api/system/signup-readiness",
    providerStatusSchema,
    undefined,
    PROVIDER_READINESS_TIMEOUT_MS,
  )
}

export function searchApps(query: string): Promise<AppSearchResponse> {
  const normalized = query.trim().slice(0, 120)
  const search = new URLSearchParams({ q: normalized })
  return apiRequest(`/api/apps/search?${search}`, appSearchResponseSchema)
}

export function listApps(): Promise<AppCatalogResponse> {
  return apiRequest("/api/apps", appCatalogResponseSchema)
}

export function getAppResearch(slug: string): Promise<AppResearchResponse> {
  return apiRequest(
    `/api/apps/${encodeURIComponent(slug)}/research`,
    appResearchResponseSchema,
  )
}

export function listRuns(limit = 25, offset = 0): Promise<RunListResponse> {
  const query = new URLSearchParams({ limit: String(limit), offset: String(offset) })
  return apiRequest(`/api/runs?${query}`, runListResponseSchema)
}

export function getRun(runId: string): Promise<RunDetailResponse> {
  return apiRequest(runPath(runId), runDetailResponseSchema)
}

export function getTimeline(runId: string): Promise<TimelineResponse> {
  return apiRequest(runPath(runId, "/timeline"), timelineResponseSchema)
}

/**
 * The sanitized provider profile for one onboarding run. The backend answers 409
 * until a profile is committed, so callers treat a rejection as "not reported"
 * rather than fabricating profile state.
 */
export function getProviderProfile(runId: string): Promise<ProviderProfileView> {
  return apiRequest(runPath(runId, "/profile"), providerProfileResponseSchema)
}

export function connectManagedRun(runId: string): Promise<ManagedConnectionResponse> {
  return apiRequest(
    runPath(runId, "/connect"),
    managedConnectionResponseSchema,
    { method: "POST" },
    CREDENTIAL_TIMEOUT_MS,
  )
}

export function pollManagedConnection(runId: string): Promise<ManagedConnectionResponse> {
  return apiRequest(
    runPath(runId, "/poll-connection"),
    managedConnectionResponseSchema,
    { method: "POST" },
    CREDENTIAL_TIMEOUT_MS,
  )
}

export async function getRunOutput(runId: string): Promise<IntegratorOutput> {
  const response = await apiRequest(runPath(runId, "/output"), runOutputResponseSchema)
  return response.integrator_bundle
}

export function createRun(
  request: OperationsRequestInput,
  idempotencyKey: string,
): Promise<RunDetailResponse> {
  if (!IDEMPOTENCY_KEY_PATTERN.test(idempotencyKey)) {
    throw new ApiError(400, "INVALID_IDEMPOTENCY_KEY", "The run request is invalid.")
  }

  return apiRequest(
    "/api/runs",
    runDetailResponseSchema,
    {
      method: "POST",
      headers: { "Idempotency-Key": idempotencyKey },
      body: JSON.stringify(request),
    },
    RUN_ACTION_TIMEOUT_MS,
  )
}

export function performPhaseAction(
  runId: string,
  action: RunPhaseAction,
  capability?: RetryCapability,
): Promise<ActionReceipt> {
  const suffix = action === "poll-email" ? "/poll-email" : action === "retry" ? "/retry" : "/resume"
  // Resume drives a same-session browser task synchronously. Inbox verification
  // also performs bounded exponential polling on the API, so both need the
  // production action timeout rather than the short metadata-request timeout.
  const timeout = action === "retry" ? REQUEST_TIMEOUT_MS : RUN_ACTION_TIMEOUT_MS
  return apiRequest(
    runPath(runId, suffix),
    actionReceiptSchema,
    {
      method: "POST",
      body: JSON.stringify(action === "retry" ? { capability } : {}),
    },
    timeout,
  )
}

/**
 * Record the operator's one admission decision (`POST /api/runs/{id}/decision`).
 *
 * `profileDigest` is optimistic concurrency, not decoration: the backend refuses
 * a decision that names a profile the run has not committed, so the operator can
 * only ever decide about the profile they were actually shown.
 */
export function decideAdmission(
  runId: string,
  decision: AdmissionInput,
  profileDigest: string,
): Promise<AdmissionDecisionResponse> {
  if (!SHA256_DIGEST_PATTERN.test(profileDigest)) {
    throw new ApiError(400, "INVALID_PROFILE_DIGEST", "The profile reference is invalid.")
  }
  return apiRequest(
    runPath(runId, "/decision"),
    admissionDecisionResponseSchema,
    {
      method: "POST",
      body: JSON.stringify({ decision, profile_digest: profileDigest }),
    },
    CREDENTIAL_TIMEOUT_MS,
  )
}

/** Stop the run at its next safe boundary, keeping the browser session up. */
export function pauseOnboarding(runId: string): Promise<PauseResponse> {
  return apiRequest(
    runPath(runId, "/pause"),
    pauseResponseSchema,
    { method: "POST", body: JSON.stringify({}) },
    CREDENTIAL_TIMEOUT_MS,
  )
}

/**
 * Restart the walk at research. The backend requires `confirm: true`, so an
 * unconfirmed reset is a validation error before any session is released.
 */
export function resetOnboarding(runId: string): Promise<ResetResponse> {
  return apiRequest(
    runPath(runId, "/reset"),
    resetResponseSchema,
    { method: "POST", body: JSON.stringify({ confirm: true }) },
    CREDENTIAL_TIMEOUT_MS,
  )
}

/**
 * Re-attempt the run's current step. `expectedPhase` is an optimistic check, not
 * a choice of step: naming a phase the run is not standing in is refused.
 */
export function retryOnboardingStep(
  runId: string,
  expectedPhase: OnboardingPhase,
): Promise<RetryStepResponse> {
  return apiRequest(
    runPath(runId, "/retry"),
    retryStepResponseSchema,
    { method: "POST", body: JSON.stringify({ expected_phase: expectedPhase }) },
    CREDENTIAL_TIMEOUT_MS,
  )
}

/**
 * Resume or cancel a waiting onboarding run. `cancelled` releases the browser
 * session and reports through the same receipt (design LL-6.3).
 */
export function resumeOnboarding(
  runId: string,
  signal: "completed" | "cancelled",
): Promise<ActionReceipt> {
  return apiRequest(
    runPath(runId, "/resume"),
    actionReceiptSchema,
    { method: "POST", body: JSON.stringify({ signal }) },
    RUN_ACTION_TIMEOUT_MS,
  )
}

export function getLiveView(runId: string): Promise<LiveViewResponse> {
  return apiRequest(runPath(runId, "/live-view"), liveViewResponseSchema)
}

/**
 * Fetch the newest Playwright screenshot through the private FastAPI boundary.
 *
 * This helper is server-only: the internal API token and private API origin never
 * enter browser JavaScript. The public browser receives the bytes only from a
 * same-origin Next Route Handler.
 */
export async function getLiveScreenshotBinary(
  runId: string,
): Promise<{ bytes: Uint8Array; capturedAt: string | null }> {
  if (!RUN_ID_PATTERN.test(runId)) {
    throw new ApiError(400, "INVALID_RUN_ID", "The run reference is invalid.")
  }

  let response: Response
  try {
    response = await fetch(`${apiOrigin()}${runPath(runId, "/live-view/screenshot")}`, {
      method: "GET",
      cache: "no-store",
      headers: {
        Accept: "image/png",
        "X-Ops-Internal-Token": internalApiToken(),
      },
      signal: AbortSignal.timeout(SCREENSHOT_TIMEOUT_MS),
    })
  } catch (error) {
    if (error instanceof ApiError) throw error
    throw new ApiError(503, "SCREENSHOT_UNREACHABLE", "The browser screenshot is unavailable.")
  }

  if (!response.ok) {
    throw new ApiError(response.status, `HTTP_${response.status}`, "The browser screenshot is unavailable.")
  }

  const contentType = response.headers.get("content-type")?.split(";", 1)[0]?.trim()
  if (contentType !== "image/png") {
    throw new ApiError(502, "INVALID_SCREENSHOT_TYPE", "The browser returned an invalid screenshot.")
  }

  const declaredSize = Number(response.headers.get("content-length") ?? "0")
  if (Number.isFinite(declaredSize) && declaredSize > MAX_SCREENSHOT_BYTES) {
    throw new ApiError(502, "SCREENSHOT_TOO_LARGE", "The browser screenshot is too large.")
  }

  const bytes = new Uint8Array(await response.arrayBuffer())
  if (bytes.length === 0 || bytes.length > MAX_SCREENSHOT_BYTES) {
    throw new ApiError(502, "INVALID_SCREENSHOT_SIZE", "The browser screenshot is invalid.")
  }

  const hasPngSignature =
    bytes.length >= PNG_SIGNATURE.length
    && PNG_SIGNATURE.every((byte, index) => bytes[index] === byte)
  if (!hasPngSignature) {
    throw new ApiError(502, "INVALID_SCREENSHOT_DATA", "The browser screenshot is invalid.")
  }

  return {
    bytes,
    capturedAt: response.headers.get("x-captured-at"),
  }
}

export function resumeWithBrowserLogin(
  runId: string,
  email: string,
  password: string,
): Promise<ActionReceipt> {
  // Owner-submitted app login credentials leave this server-only client
  // immediately for the API and are consumed by the selected browser provider's
  // transient secret boundary. They are never persisted or returned.
  return apiRequest(
    runPath(runId, "/resume"),
    actionReceiptSchema,
    {
      method: "POST",
      body: JSON.stringify({ signal: "completed", browser_login: { email, password } }),
    },
    RUN_ACTION_TIMEOUT_MS,
  )
}

export function resumeWithBrowserVerification(
  runId: string,
  verification: BrowserVerificationInput,
): Promise<ActionReceipt> {
  // The one-time value is sent only through this server-side request and is
  // consumed by the browser provider's transient secret boundary. It is never
  // returned to client state or included in an action receipt.
  return apiRequest(
    runPath(runId, "/resume"),
    actionReceiptSchema,
    {
      method: "POST",
      body: JSON.stringify({
        signal: "completed",
        browser_verification: verification,
      }),
    },
    RUN_ACTION_TIMEOUT_MS,
  )
}

export function submitCredentials(
  runId: string,
  credentials: Record<string, string>,
  company: CompanyProfileInput,
): Promise<RunDetailResponse> {
  const fields = Object.keys(credentials)
  if (fields.length === 0 || fields.length > 20) {
    throw new ApiError(400, "INVALID_CREDENTIAL_FIELDS", "Provide one to twenty credential fields.")
  }
  for (const field of fields) {
    if (!CREDENTIAL_FIELD_PATTERN.test(field) || !credentials[field]) {
      throw new ApiError(400, "INVALID_CREDENTIAL_FIELD", "A credential field is invalid.")
    }
  }
  // Matches the existing required backend contract: company + credentials. The
  // raw values leave the server-only client immediately for the loopback API;
  // they are never logged, cached, or returned to the browser.
  return apiRequest(
    runPath(runId, "/credentials"),
    runDetailResponseSchema,
    {
      method: "POST",
      body: JSON.stringify({ company, credentials }),
    },
    CREDENTIAL_TIMEOUT_MS,
  )
}
