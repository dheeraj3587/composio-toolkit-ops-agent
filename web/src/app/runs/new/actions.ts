"use server"

import { createHash, randomBytes } from "node:crypto"

import { redirect } from "next/navigation"

import { ApiError, PhaseConflictError, createRun } from "@/lib/api"
import type { OperationsRequestInput } from "@/lib/types"

/**
 * Why a run was refused, in the operator's words.
 *
 * The backend answers a refusal with a closed reason code and creates nothing.
 * Collapsing every one of those into "the backend rejected this request" was
 * the whole problem: the refusals below are each actionable, and the operator
 * could not tell "this app has no signup route" from "a key is missing".
 *
 * Codes are matched exactly. An unrecognized one falls through to the generic
 * sentence rather than being shown raw, so a new backend code can never leak
 * internal vocabulary into the page.
 */
const REFUSAL_REASONS: Record<string, string> = {
  reviewed_signup_recipe_not_available:
    "No signup route is available for this app. Its reviewed recipe has no signup page, and the agent could not find one on the app's own reviewed site, so there is nowhere to register. Choose “I have an account”, or pick another app.",
  playwright_required_for_reviewed_signup:
    "Creating an account uses the self-hosted Playwright engine. Select Playwright as the browser engine and try again.",
  playwright_configuration_required:
    "The self-hosted browser engine is not configured in this deployment, so no browser run can start.",
  gmail_signup_address_not_configured:
    "Creating an account needs a verified work inbox to receive the confirmation email, and none is configured for this deployment.",
  gmail_signup_preflight_failed:
    "The work inbox did not answer its readiness check, so the confirmation email could not be received. Check the inbox on the system health page and try again.",
  reviewed_recipe_required:
    "This app has no reviewed recipe, so the agent cannot run against it. It can still be researched in plan-only mode.",
  onboarding_driver_not_wired:
    "The autonomous onboarding driver is not wired to a browser in this deployment.",
  // Signing in with a submitted password is a browser route, and only a
  // browser route stages one. Every code above described creating an account;
  // an operator handing the agent their own credentials got none of them.
  reviewed_login_recipe_not_available:
    "This app's reviewed recipe has no browser sign-in for the agent to drive, so the password you entered would never be used. Start the run without one and connect the app through its own authorization flow instead.",
  existing_login_vault_required:
    "Signing in on your behalf requires the encrypted credential vault, and it is not configured in this deployment. The password was not stored. Configure the vault on the system health page and try again.",
}

function refusalMessage(error: unknown): string | null {
  // Supplying sign-in credentials at create time is an owner action, and the
  // backend answers a disabled or non-local caller with a plain 403 rather
  // than a phase conflict. That fell through to "the backend rejected this
  // run request", which sends the operator to check a request that is fine:
  // the server has autonomous sign-in switched off. Same sentence the resume
  // path already shows for the same refusal.
  if (error instanceof ApiError && error.status === 403) {
    return "Autonomous sign-in is disabled on this server (owner opt-in required), so a run cannot be started with an account password. Start the run without one and sign in when it asks, or enable the owner opt-in on the server."
  }
  if (!(error instanceof PhaseConflictError)) return null
  const reason = error.conflict.reason_code
  return (reason && REFUSAL_REASONS[reason]) ?? null
}

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

// A secret must never be silently altered: no trim, no truncation. Over-long
// input is rejected by the caller's validation rather than quietly cut.
function rawSecret(formData: FormData, name: string): string {
  const entry = formData.get(name)
  return typeof entry === "string" ? entry : ""
}

function validWebUrl(candidate: string): boolean {
  try {
    return new URL(candidate).protocol === "https:"
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
  const requestedAccountMode = value(formData, "account_mode", 40)
  const accountMode = ["existing_account", "create_account"].includes(requestedAccountMode)
    ? (requestedAccountMode as OperationsRequestInput["account_mode"])
    : null
  const legalName = value(formData, "legal_name", 180)
  const website = value(formData, "website", 500)
  const useCase = value(formData, "use_case", 2_000)
  const expectedVolume = value(formData, "expected_volume", 180)
  const callbacks = callbackUrls(value(formData, "callback_urls", 2_000))
  const appLoginEmail = value(formData, "app_login_email", 320)
  // Password is captured verbatim (leading/trailing spaces are legitimate and
  // must survive); it is validated for length below, never trimmed or truncated.
  const appLoginPassword = rawSecret(formData, "app_login_password")
  const requestedPolicy = value(formData, "requested_scope_policy", 20)
  const policy = ["minimum", "recommended", "maximum"].includes(requestedPolicy)
    ? (requestedPolicy as OperationsRequestInput["requested_scope_policy"])
    : null
  const requestedExecutionMode = value(formData, "execution_mode", 40)
  // Fail CLOSED: a missing/invalid execution mode defaults to plan_only (no
  // provider side effects), never to live execution.
  const executionMode = ["plan_only", "execute_when_configured"].includes(requestedExecutionMode)
    ? (requestedExecutionMode as OperationsRequestInput["execution_mode"])
    : "plan_only"
  // The self-hosted Playwright harness is the only backend, so this is a record
  // frozen onto the run rather than a choice. A form that posts anything else is
  // rejected rather than coerced: the value decides which backend a retry or
  // resume is allowed to run on.
  const requestedBrowserProvider = value(formData, "browser_provider", 40)
  const browserProvider = requestedBrowserProvider === "playwright" ? "playwright" : null
  // The pinned decision model is a preference, not a requirement: it is shape-
  // checked here and authoritatively validated by the backend against the
  // providers it actually has keys for. An unparseable value is dropped rather
  // than failing the run, which then proceeds on the deployment default.
  const requestedModel = value(formData, "decision_model", 120)
  const decisionModel = /^[a-z0-9_.-]+:[A-Za-z0-9_./:-]+$/i.test(requestedModel)
    ? requestedModel
    : null
  const requestedEffort = value(formData, "decision_effort", 20)
  const decisionEffort =
    decisionModel && ["instant", "low", "medium", "high"].includes(requestedEffort)
      ? requestedEffort
      : null

  const requestedCreationPolicy = value(formData, "credential_creation_policy", 40)
  const creationPolicy = ["reuse_only", "create_if_missing"].includes(
    requestedCreationPolicy,
  )
    ? (requestedCreationPolicy as OperationsRequestInput["credential_creation_policy"])
    : null

  const invalid: string[] = []
  if (appName.length < 2) invalid.push("app_name")
  if (accountMode === null) invalid.push("account_mode")
  if (legalName.length < 2) invalid.push("legal_name")
  if (!validWebUrl(website)) invalid.push("website")
  if (useCase.length < 12) invalid.push("use_case")
  if (callbacks === null) invalid.push("callback_urls")
  // Reject a partial login credential pair (one field without the other) instead
  // of silently dropping the whole login payload; require both or neither.
  if (
    accountMode === "existing_account" &&
    (appLoginEmail.length > 0) !== (appLoginPassword.length > 0)
  ) {
    invalid.push("app_login_password")
  }
  // A password this long is almost certainly an error/abuse; reject rather than
  // truncate (which would submit a wrong secret).
  if (appLoginPassword.length > 512) invalid.push("app_login_password")
  if (policy === null) invalid.push("requested_scope_policy")
  if (browserProvider === null) invalid.push("browser_provider")
  if (creationPolicy === null) invalid.push("credential_creation_policy")

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
    account_mode: accountMode ?? "existing_account",
    company: {
      legal_name: legalName,
      website,
      use_case: useCase,
      expected_volume: expectedVolume || null,
      callback_urls: callbacks ?? [],
    },
    requested_scope_policy: policy ?? "minimum",
    execution_mode: executionMode,
    browser_provider: browserProvider ?? "playwright",
    credential_creation_policy: creationPolicy ?? "reuse_only",
    browser_login:
      accountMode === "existing_account" && appLoginEmail && appLoginPassword
        ? { email: appLoginEmail, password: appLoginPassword }
        : null,
    decision_model: decisionModel,
    decision_effort: decisionEffort,
  }

  // This value is returned to client-side action state so it must not be
  // derived from the password. It only decides whether a retry may reuse the
  // same idempotency key; the backend remains the authority for replay safety.
  const idempotencyShape = {
    ...request,
    browser_login: request.browser_login
      ? { email: request.browser_login.email, password_supplied: true }
      : null,
  }
  const requestFingerprint = createHash("sha256")
    .update(JSON.stringify(idempotencyShape))
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
    const refused = refusalMessage(error)
    return {
      error: unavailable
        ? "The operations API is unavailable. We could not confirm whether the run was persisted. Check the ledger before retrying."
        : (refused ??
          "The backend rejected this run request. Review the request and try again."),
      fields: [],
      idempotencyKey,
      requestFingerprint,
    }
  }

  redirect(`/runs/${encodeURIComponent(runId)}`)
}
