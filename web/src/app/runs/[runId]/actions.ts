"use server"

import { revalidatePath } from "next/cache"
import { redirect } from "next/navigation"

import {
  ApiError,
  connectManagedRun,
  getLiveView,
  getRun,
  pollManagedConnection,
  performPhaseAction,
  PhaseConflictError,
  resumeWithBrowserLogin,
  resumeWithBrowserVerification,
  submitCredentials,
} from "@/lib/api"
import { sameOriginInteractivePath } from "@/lib/live-view-grant"
import type {
  BrowserProvider,
  BrowserVerificationInput,
  LiveViewMode,
  RetryCapability,
  RunPhaseAction,
} from "@/lib/types"

export interface ManagedConnectionActionState {
  message: string | null
  tone: "neutral" | "error"
  state: "pending" | "active" | "terminal" | null
}

export async function runManagedConnectionAction(
  _previousState: ManagedConnectionActionState,
  formData: FormData,
): Promise<ManagedConnectionActionState> {
  const runId = String(formData.get("run_id") ?? "").slice(0, 180)
  const operation = String(formData.get("managed_action") ?? "")
  if (!/^run_[0-9a-f]{32}$/.test(runId) || !["connect", "poll"].includes(operation)) {
    return { message: "The managed connection request is invalid.", tone: "error", state: null }
  }

  let result
  try {
    result = operation === "connect"
      ? await connectManagedRun(runId)
      : await pollManagedConnection(runId)
  } catch (error) {
    if (error instanceof PhaseConflictError) {
      return {
        message: "The backend no longer authorizes this managed connection action.",
        tone: "error",
        state: null,
      }
    }
    return {
      message:
        error instanceof ApiError
          ? "The managed connection provider did not accept this action."
          : "The managed connection action could not be completed.",
      tone: "error",
      state: null,
    }
  }

  revalidatePath(`/runs/${encodeURIComponent(runId)}`)
  if (operation === "connect" && result.redirect_url) {
    // The provider URL is schema-validated, used once, and never stored in page
    // data or run state. Next emits the redirect after this server action.
    redirect(result.redirect_url)
  }

  if (result.state === "active") {
    return {
      message: "Managed account connected. The run is ready to continue.",
      tone: "neutral",
      state: "active",
    }
  }
  if (result.state === "terminal") {
    return {
      message: "The provider closed this connection request. Start a new run to try again.",
      tone: "error",
      state: "terminal",
    }
  }
  return {
    message:
      operation === "poll"
        ? "The managed account is not active yet. Complete provider authorization, then poll again."
        : "The existing managed authorization request is still pending.",
    tone: "neutral",
    state: "pending",
  }
}

export interface PhaseActionState {
  message: string | null
  tone: "neutral" | "error"
  interactiveStateVersion?: string | null
}

export async function runPhaseAction(
  _previousState: PhaseActionState,
  formData: FormData,
): Promise<PhaseActionState> {
  const runId = String(formData.get("run_id") ?? "").slice(0, 180)
  const actionValue = String(formData.get("action") ?? "")
  const action: RunPhaseAction | null = ["resume", "poll-email", "retry"].includes(actionValue)
    ? (actionValue as RunPhaseAction)
    : null

  const capabilityValue = String(formData.get("capability") ?? "")
  const capability: RetryCapability | undefined = ["research", "browser", "email", "validation"].includes(capabilityValue)
    ? (capabilityValue as RetryCapability)
    : undefined

  if (!runId || !action || (action === "retry" && !capability)) {
    return { message: "The phase request is invalid.", tone: "error" }
  }

  try {
    const receipt = await performPhaseAction(runId, action, capability)
    const refreshed = action === "resume" && receipt.status === "accepted"
      ? await getRun(runId)
      : null
    const interactiveStateVersion =
      refreshed?.browser?.provider === "playwright" &&
      refreshed.browser.lifecycle === "waiting_for_hitl" &&
      refreshed.browser.interaction_available
        ? refreshed.run.updated_at
        : null
    revalidatePath(`/runs/${encodeURIComponent(runId)}`)
    return {
      message: receipt.detail ?? (receipt.status === "no_change" ? "Backend state did not change." : "Backend accepted the action."),
      tone: receipt.status === "configuration_required" ? "error" : "neutral",
      interactiveStateVersion,
    }
  } catch (error) {
    if (error instanceof PhaseConflictError) {
      const actionName = error.conflict.action?.replaceAll("-", " ")
      const available = error.conflict.available_in
        .map((status) => status.replaceAll("_", " "))
        .join(", ")
      return {
        message: actionName && available
          ? `Action held. ${actionName} is available in: ${available}.`
          : "Action held because this run is in a different phase.",
        tone: "error",
      }
    }
    if (error instanceof ApiError) {
      return { message: "The operations API did not accept this action.", tone: "error" }
    }
    return { message: "The action could not be completed.", tone: "error" }
  }
}

export interface LiveViewState {
  provider: BrowserProvider | null
  mode: LiveViewMode
  liveUrl: string | null
  screenshotUrl: string | null
  interactivePath: string | null
  capturedAt: string | null
  interactionAvailable: boolean
  message: string | null
  tone: "neutral" | "error"
}

function unavailableLiveView(message: string): LiveViewState {
  return {
    provider: null,
    mode: "unavailable",
    liveUrl: null,
    screenshotUrl: null,
    interactivePath: null,
    capturedAt: null,
    interactionAvailable: false,
    message,
    tone: "error",
  }
}

export async function openLiveView(
  _previousState: LiveViewState,
  formData: FormData,
): Promise<LiveViewState> {
  const runId = String(formData.get("run_id") ?? "").slice(0, 180)
  if (!/^run_[0-9a-f]{32}$/.test(runId)) {
    return unavailableLiveView("The run reference is invalid.")
  }

  try {
    const result = await getLiveView(runId)

    if (!result.available || result.mode === "unavailable") {
      return {
        ...unavailableLiveView("No live browser session is currently available for this run."),
        provider: result.provider,
      }
    }

    if (result.mode === "hosted_url" && result.live_url) {
      return {
        provider: result.provider,
        mode: result.mode,
        liveUrl: result.live_url,
        screenshotUrl: null,
        interactivePath: null,
        capturedAt: result.captured_at ?? null,
        interactionAvailable: result.interaction_available,
        message: "Interactive hosted browser session ready.",
        tone: "neutral",
      }
    }

    if (result.mode === "screenshot" && result.screenshot_url) {
      const version = encodeURIComponent(result.captured_at ?? Date.now().toString())
      return {
        provider: result.provider,
        mode: result.mode,
        liveUrl: null,
        screenshotUrl:
          `/api/control/runs/${encodeURIComponent(runId)}/live-view/screenshot?v=${version}`,
        interactivePath: null,
        capturedAt: result.captured_at ?? null,
        interactionAvailable: false,
        message: "Latest Playwright browser frame loaded. This view is read-only.",
        tone: "neutral",
      }
    }

    if (result.mode === "interactive_remote" && result.interactive_url) {
      return {
        provider: result.provider,
        mode: "interactive_remote",
        liveUrl: null,
        screenshotUrl: null,
        interactivePath: sameOriginInteractivePath(result.interactive_url),
        capturedAt: result.captured_at ?? null,
        interactionAvailable: result.interaction_available,
        message: result.interaction_available
          ? "Interactive Playwright session ready."
          : "Live Playwright session ready in view-only mode.",
        tone: "neutral",
      }
    }

    return {
      ...unavailableLiveView("The selected interactive browser view is not available in this control plane."),
      provider: result.provider,
    }
  } catch (error) {
    const message =
      error instanceof ApiError && error.status === 403
        ? "Live view is restricted to the authorized operator."
        : "The live browser view could not be retrieved."
    return unavailableLiveView(message)
  }
}

export interface BrowserLoginState {
  message: string | null
  tone: "neutral" | "error"
}

export interface BrowserVerificationState {
  message: string | null
  tone: "neutral" | "error"
}

const VERIFICATION_CODE_PATTERN = /^(?:\d{4,8}|[A-Z0-9]{5,8})$/

function verificationInput(formData: FormData): BrowserVerificationInput | null {
  const rawCode = String(formData.get("verification_code") ?? "")
  const code = rawCode.trim().replaceAll(" ", "").replaceAll("-", "").toUpperCase()
  const rawUrl = String(formData.get("verification_url") ?? "").trim()
  if (Boolean(code) === Boolean(rawUrl)) return null
  if (code) return VERIFICATION_CODE_PATTERN.test(code) ? { code } : null
  if (rawUrl.length > 2_048) return null
  try {
    const parsed = new URL(rawUrl)
    if (
      parsed.protocol !== "https:" ||
      !parsed.hostname ||
      parsed.username ||
      parsed.password
    ) {
      return null
    }
    return { url: rawUrl }
  } catch {
    return null
  }
}

export async function submitBrowserVerificationAction(
  _previousState: BrowserVerificationState,
  formData: FormData,
): Promise<BrowserVerificationState> {
  const runId = String(formData.get("run_id") ?? "").slice(0, 180)
  const verification = verificationInput(formData)
  if (!/^run_[0-9a-f]{32}$/.test(runId) || !verification) {
    return {
      message: "Enter one valid verification code or HTTPS magic link.",
      tone: "error",
    }
  }

  try {
    const receipt = await resumeWithBrowserVerification(runId, verification)
    revalidatePath(`/runs/${encodeURIComponent(runId)}`)
    return {
      message:
        receipt.status === "accepted"
          ? "The one-time verification value was handed directly to the browser session."
          : receipt.status === "no_change"
            ? "The verification value was consumed, but the run has not advanced yet."
            : "The browser session could not apply the verification value.",
      tone:
        receipt.status === "configuration_required" || receipt.status === "unavailable"
          ? "error"
          : "neutral",
    }
  } catch (error) {
    if (error instanceof PhaseConflictError) {
      return {
        message: "This run is no longer waiting for email verification.",
        tone: "error",
      }
    }
    if (error instanceof ApiError) {
      return {
        message: "The verification value could not be submitted.",
        tone: "error",
      }
    }
    return { message: "The verification submission failed.", tone: "error" }
  }
}

export async function submitBrowserLoginAction(
  _previousState: BrowserLoginState,
  formData: FormData,
): Promise<BrowserLoginState> {
  const runId = String(formData.get("run_id") ?? "").slice(0, 180)
  const email = String(formData.get("login_email") ?? "")
  const password = String(formData.get("login_password") ?? "")
  if (!runId || !email || !password) {
    return { message: "Enter both the account email/username and the password.", tone: "error" }
  }
  try {
    const receipt = await resumeWithBrowserLogin(runId, email, password)
    revalidatePath(`/runs/${encodeURIComponent(runId)}`)
    return {
      message:
        receipt.detail ??
        "Credentials handed to the selected browser provider for this one resume.",
      tone: receipt.status === "configuration_required" ? "error" : "neutral",
    }
  } catch (error) {
    if (error instanceof PhaseConflictError) {
      return { message: "This run is not waiting for a sign-in right now.", tone: "error" }
    }
    if (error instanceof ApiError) {
      return {
        message:
          error.status === 403
            ? "Autonomous sign-in is disabled on this server (owner opt-in required)."
            : "The sign-in credentials could not be submitted.",
        tone: "error",
      }
    }
    return { message: "The sign-in submission failed.", tone: "error" }
  }
}

export interface CredentialSubmitState {
  message: string | null
  tone: "neutral" | "error"
  status: string | null
}

export async function submitCredentialAction(
  _previousState: CredentialSubmitState,
  formData: FormData,
): Promise<CredentialSubmitState> {
  const runId = String(formData.get("run_id") ?? "").slice(0, 180)
  const fieldName = String(formData.get("field_name") ?? "").slice(0, 100) || "api_token"
  const value = String(formData.get("credential_value") ?? "")
  const callbackRaw = String(formData.get("callback_urls") ?? "").slice(0, 2048)
  const company = {
    legal_name: String(formData.get("legal_name") ?? "").slice(0, 200),
    website: String(formData.get("website") ?? "").slice(0, 2048),
    use_case: String(formData.get("use_case") ?? "").slice(0, 2000),
    expected_volume: null,
    callback_urls: callbackRaw
      .split(",")
      .map((item) => item.trim())
      .filter((item) => item.length > 0)
      .slice(0, 20),
  }
  if (!runId || !value) {
    return { message: "A run reference and credential value are required.", tone: "error", status: null }
  }
  if (!company.legal_name || !company.website || !company.use_case) {
    return {
      message: "Company legal name, website, and use case are required.",
      tone: "error",
      status: null,
    }
  }
  try {
    const detail = await submitCredentials(runId, { [fieldName]: value }, company)
    revalidatePath(`/runs/${encodeURIComponent(runId)}`)
    return {
      message:
        detail.run.status === "completed"
          ? "Credential validated. IntegratorBundle is ready in Output."
          : `Credential stored. Run status: ${detail.run.status.replaceAll("_", " ")}.`,
      tone: detail.run.status === "completed" ? "neutral" : "error",
      status: detail.run.status,
    }
  } catch (error) {
    if (error instanceof PhaseConflictError) {
      return { message: "The run is not ready to accept a credential yet.", tone: "error", status: null }
    }
    if (error instanceof ApiError) {
      return { message: "The credential could not be submitted.", tone: "error", status: null }
    }
    return { message: "The credential submission failed.", tone: "error", status: null }
  }
}
