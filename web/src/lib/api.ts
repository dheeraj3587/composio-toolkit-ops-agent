import "server-only"

import type { ZodType } from "zod"

import {
  actionReceiptSchema,
  appResearchResponseSchema,
  appSearchResponseSchema,
  healthResponseSchema,
  liveViewResponseSchema,
  runDetailResponseSchema,
  runListResponseSchema,
  runOutputResponseSchema,
  timelineResponseSchema,
} from "@/lib/api-schemas"
import type {
  ActionReceipt,
  AppResearchResponse,
  AppSearchResponse,
  CompanyProfileInput,
  HealthResponse,
  IntegratorOutput,
  LiveViewResponse,
  OperationsRequestInput,
  PhaseConflict,
  RunDetailResponse,
  RunListResponse,
  RunPhaseAction,
  RetryCapability,
  TimelineResponse,
} from "@/lib/types"

const CREDENTIAL_FIELD_PATTERN = /^[a-z0-9][a-z0-9_-]{0,99}$/

const DEFAULT_API_ORIGIN = "http://127.0.0.1:8000"
const REQUEST_TIMEOUT_MS = 8_000
// execute_when_configured runs (and same-session resume) drive a real Browser
// Use session synchronously on the backend, which routinely exceeds 8s.
const RUN_ACTION_TIMEOUT_MS = 180_000
const CREDENTIAL_TIMEOUT_MS = 30_000
const IDEMPOTENCY_KEY_PATTERN = /^idem_[0-9a-f]{32}$/

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

export function searchApps(query: string): Promise<AppSearchResponse> {
  const normalized = query.trim().slice(0, 120)
  const search = new URLSearchParams({ q: normalized })
  return apiRequest(`/api/apps/search?${search}`, appSearchResponseSchema)
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
  // Resume drives a same-session browser task synchronously; allow the longer bound.
  const timeout = action === "resume" ? RUN_ACTION_TIMEOUT_MS : REQUEST_TIMEOUT_MS
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

export function getLiveView(runId: string): Promise<LiveViewResponse> {
  return apiRequest(runPath(runId, "/live-view"), liveViewResponseSchema)
}

export function resumeWithBrowserLogin(
  runId: string,
  email: string,
  password: string,
): Promise<ActionReceipt> {
  // Owner-submitted app login credentials. They leave this server-only client
  // immediately for the API, are injected into Browser Use as secure
  // placeholders for a single resume, and are never persisted or returned.
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
