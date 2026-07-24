"use server"

import { createHash, randomBytes } from "node:crypto"

import { redirect } from "next/navigation"

import { ApiError, createRun } from "@/lib/api"
import type { OperationsRequestInput } from "@/lib/types"

export interface CreateRunFormState {
  error: string | null
  fields: string[]
  idempotencyKey: string | null
  requestFingerprint: string | null
}

function value(formData: FormData, name: string, maxLength = 500): string {
  const entry = formData.get(name)
  return typeof entry === "string" ? entry.trim().slice(0, maxLength) : ""
}

function validWebUrl(candidate: string): boolean {
  try {
    return ["http:", "https:"].includes(new URL(candidate).protocol)
  } catch {
    return false
  }
}

function callbackUrls(raw: string): string[] | null {
  const values = raw
    .split(/[\n,]/)
    .map((item) => item.trim())
    .filter(Boolean)
    .slice(0, 10)
  return values.every(validWebUrl) ? values : null
}

export async function createRunAction(
  previousState: CreateRunFormState,
  formData: FormData,
): Promise<CreateRunFormState> {
  const appName = value(formData, "app_name", 120)
  const legalName = value(formData, "legal_name", 180)
  const website = value(formData, "website", 500)
  const workEmailRef = value(formData, "work_email_ref", 512)
  const useCase = value(formData, "use_case", 2_000)
  const expectedVolume = value(formData, "expected_volume", 180)
  const callbacks = callbackUrls(value(formData, "callback_urls", 2_000))
  const outreachOverride = value(formData, "outreach_recipient_override", 320)
  const appLoginEmail = value(formData, "app_login_email", 320)
  const appLoginPassword = value(formData, "app_login_password", 400)
  const requestedPolicy = value(formData, "requested_scope_policy", 20)
  const policy = ["minimum", "recommended", "maximum"].includes(requestedPolicy)
    ? (requestedPolicy as OperationsRequestInput["requested_scope_policy"])
    : "maximum"
  const requestedExecutionMode = value(formData, "execution_mode", 40)
  const executionMode = ["plan_only", "execute_when_configured"].includes(requestedExecutionMode)
    ? (requestedExecutionMode as OperationsRequestInput["execution_mode"])
    : "execute_when_configured"

  const invalid: string[] = []
  if (appName.length < 2) invalid.push("app_name")
  if (legalName.length < 2) invalid.push("legal_name")
  if (!validWebUrl(website)) invalid.push("website")
  if (!/^vault:\/\/[a-z0-9-]+\/[a-z0-9_-]+\/[A-Za-z0-9_-]+$/.test(workEmailRef)) {
    invalid.push("work_email_ref")
  }
  if (useCase.length < 12) invalid.push("use_case")
  if (callbacks === null) invalid.push("callback_urls")

  if (invalid.length > 0) {
    return {
      error: "Review the marked fields. No run was created.",
      fields: invalid,
      idempotencyKey: null,
      requestFingerprint: null,
    }
  }

  const request: OperationsRequestInput = {
    app_name: appName,
    company: {
      legal_name: legalName,
      website,
      work_email_ref: workEmailRef,
      use_case: useCase,
      expected_volume: expectedVolume || null,
      callback_urls: callbacks ?? [],
    },
    requested_scope_policy: policy,
    execution_mode: executionMode,
    outreach_recipient_override: outreachOverride || null,
    browser_login:
      appLoginEmail && appLoginPassword
        ? { email: appLoginEmail, password: appLoginPassword }
        : null,
  }

  const requestFingerprint = createHash("sha256")
    .update(JSON.stringify(request))
    .digest("hex")
  const idempotencyKey =
    previousState.requestFingerprint === requestFingerprint && previousState.idempotencyKey
      ? previousState.idempotencyKey
      : `idem_${randomBytes(16).toString("hex")}`

  let runId: string
  try {
    const detail = await createRun(request, idempotencyKey)
    runId = detail.run.run_id
  } catch (error) {
    const unavailable = error instanceof ApiError && error.status >= 500
    return {
      error: unavailable
        ? "The operations API is unavailable. We could not confirm whether the run was persisted. Check the ledger before retrying."
        : "The backend rejected this run request. Review the request and try again.",
      fields: [],
      idempotencyKey,
      requestFingerprint,
    }
  }

  redirect(`/runs/${encodeURIComponent(runId)}`)
}
