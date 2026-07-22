import "server-only"

import type { ZodType } from "zod"

import {
  actionReceiptSchema,
  appResearchResponseSchema,
  appSearchResponseSchema,
  healthResponseSchema,
  runDetailResponseSchema,
  runListResponseSchema,
  runOutputResponseSchema,
  timelineResponseSchema,
} from "@/lib/api-schemas"
import type {
  ActionReceipt,
  AppResearchResponse,
  AppSearchResponse,
  HealthResponse,
  IntegratorOutput,
  OperationsRequestInput,
  PhaseConflict,
  RunDetailResponse,
  RunListResponse,
  RunPhaseAction,
  RetryCapability,
  TimelineResponse,
} from "@/lib/types"

const DEFAULT_API_ORIGIN = "http://127.0.0.1:8000"
const REQUEST_TIMEOUT_MS = 8_000
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

async function apiRequest<T>(path: string, schema: ZodType<T>, init?: RequestInit): Promise<T> {
  let response: Response

  try {
    response = await fetch(`${apiOrigin()}${path}`, {
      ...init,
      cache: "no-store",
      headers: {
        Accept: "application/json",
        ...(init?.body ? { "Content-Type": "application/json" } : {}),
        ...init?.headers,
      },
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
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

  return apiRequest("/api/runs", runDetailResponseSchema, {
    method: "POST",
    headers: { "Idempotency-Key": idempotencyKey },
    body: JSON.stringify(request),
  })
}

export function performPhaseAction(
  runId: string,
  action: RunPhaseAction,
  capability?: RetryCapability,
): Promise<ActionReceipt> {
  const suffix = action === "poll-email" ? "/poll-email" : action === "retry" ? "/retry" : "/resume"
  return apiRequest(runPath(runId, suffix), actionReceiptSchema, {
    method: "POST",
    body: JSON.stringify(action === "retry" ? { capability } : {}),
  })
}
