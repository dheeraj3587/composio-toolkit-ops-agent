"use server"

import { revalidatePath } from "next/cache"
import { redirect } from "next/navigation"

import {
  ApiError,
  connectManagedRun,
  decideAdmission,
  getLiveView,
  getRun,
  pauseOnboarding,
  pollManagedConnection,
  performPhaseAction,
  PhaseConflictError,
  resetOnboarding,
  resumeOnboarding,
  resumeWithBrowserLogin,
  resumeWithBrowserVerification,
  retryOnboardingStep,
  submitCredentials,
} from "@/lib/api"
import { onboardingPhaseSchema } from "@/lib/api-schemas"
import { humanize } from "@/lib/format"
import { maskedScreenshotPath, SECRET_CAPTURE_BOUNDARY } from "@/lib/live-view"
import { sameOriginInteractivePath } from "@/lib/live-view-grant"
import type {
  AdmissionInput,
  AdmissionRoute,
  BrowserProvider,
  BrowserVerificationInput,
  LiveViewMode,
  OnboardingPhase,
  RetryCapability,
  RunPhaseAction,
} from "@/lib/types"

const RUN_ID_PATTERN = /^run_[0-9a-f]{32}$/
const ONBOARDING_CONTROLS = [
  "pause",
  "resume",
  "cancel",
  "reset",
  "retry-step",
] as const

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

// --- Onboarding operator controls (design LL-6.3) ----------------------------
//
// One action per decision surface, one action for the projected control strip.
// Every one of them refuses a request the backend has not projected as legal, so
// a control that is rendered is a control the backend named.

export interface AdmissionDecisionState {
  message: string | null
  tone: "neutral" | "error"
  route: AdmissionRoute | null
}

/**
 * Record the operator's one admission decision (Requirement 18.6, surface 1 of 2).
 *
 * The profile digest travels with the decision because the operator decides about
 * the profile they were shown: a digest the run has not committed is refused by
 * the backend rather than applied to a different profile.
 */
export async function decideAdmissionAction(
  _previousState: AdmissionDecisionState,
  formData: FormData,
): Promise<AdmissionDecisionState> {
  const runId = String(formData.get("run_id") ?? "").slice(0, 180)
  const decisionValue = String(formData.get("decision") ?? "")
  const decision: AdmissionInput | null =
    decisionValue === "create_account" || decisionValue === "cancel" ? decisionValue : null
  const profileDigest = String(formData.get("profile_digest") ?? "").slice(0, 64)

  if (!RUN_ID_PATTERN.test(runId) || !decision || !/^[0-9a-f]{64}$/.test(profileDigest)) {
    return { message: "The admission decision request is invalid.", tone: "error", route: null }
  }

  let recorded
  try {
    recorded = await decideAdmission(runId, decision, profileDigest)
  } catch (error) {
    if (error instanceof PhaseConflictError) {
      return {
        message: "This run is no longer waiting for an admission decision.",
        tone: "error",
        route: null,
      }
    }
    return {
      message:
        error instanceof ApiError
          ? "The admission decision was not accepted."
          : "The admission decision could not be recorded.",
      tone: "error",
      route: null,
    }
  }

  revalidatePath(`/runs/${encodeURIComponent(runId)}`)
  const outcome =
    recorded.route === "cancelled"
      ? "The run is cancelled and no account will be created."
      : recorded.route === "signup"
        ? "The agent will create an account on the provider."
        : "The agent will sign in with the existing account."
  return {
    message: recorded.replayed
      ? `This run already held a decision, so nothing was rewritten. ${outcome}`
      : `Decision recorded. ${outcome}`,
    tone: "neutral",
    route: recorded.route,
  }
}

export type OnboardingControl = "pause" | "resume" | "cancel" | "reset" | "retry-step"

export interface OnboardingControlState {
  message: string | null
  tone: "neutral" | "error"
  control: OnboardingControl | null
}

/**
 * Run one backend-projected onboarding control.
 *
 * Reset carries an explicit acknowledgement because it clears workflow state;
 * the backend refuses an unconfirmed reset as a validation error, and this action
 * refuses it before the request is even made.
 */
export async function runOnboardingControlAction(
  _previousState: OnboardingControlState,
  formData: FormData,
): Promise<OnboardingControlState> {
  const runId = String(formData.get("run_id") ?? "").slice(0, 180)
  const controlValue = String(formData.get("control") ?? "")
  const control = ONBOARDING_CONTROLS.includes(controlValue as OnboardingControl)
    ? (controlValue as OnboardingControl)
    : null

  if (!RUN_ID_PATTERN.test(runId) || !control) {
    return { message: "The onboarding control request is invalid.", tone: "error", control: null }
  }

  if (control === "reset" && String(formData.get("confirm") ?? "") !== "true") {
    return {
      message: "Confirm the reset first. It clears workflow state; vault references are preserved.",
      tone: "error",
      control,
    }
  }

  let expectedPhase: OnboardingPhase | null = null
  if (control === "retry-step") {
    const parsed = onboardingPhaseSchema.safeParse(String(formData.get("expected_phase") ?? ""))
    if (!parsed.success) {
      return { message: "The retry does not name a known phase.", tone: "error", control }
    }
    expectedPhase = parsed.data
  }

  let message: string
  try {
    if (control === "pause") {
      const paused = await pauseOnboarding(runId)
      message = paused.accepted
        ? `Pausing after ${humanize(paused.pausing_after_phase)}. The browser session stays open.`
        : "The backend did not accept a pause for this run."
    } else if (control === "reset") {
      const reset = await resetOnboarding(runId)
      message =
        `Reset to ${humanize(reset.phase)}. ${reset.vault_references_preserved} vault reference(s) preserved; ` +
        `expected route on restart: ${humanize(reset.expected_route_on_restart)}.`
    } else if (expectedPhase !== null) {
      const retried = await retryOnboardingStep(runId, expectedPhase)
      const skipped = retried.skipped_effects.map(humanize).join(", ")
      message =
        `Retrying ${humanize(retried.phase)} (attempt ${retried.attempt}).` +
        (skipped ? ` Already-completed effects are skipped: ${skipped}.` : "")
    } else {
      const receipt = await resumeOnboarding(runId, control === "cancel" ? "cancelled" : "completed")
      message =
        receipt.detail ??
        (control === "cancel"
          ? "Cancellation accepted; the browser session was released."
          : "Resume accepted on the same browser session.")
    }
  } catch (error) {
    if (error instanceof PhaseConflictError) {
      return {
        message: "The backend no longer authorizes this control for the run's current phase.",
        tone: "error",
        control,
      }
    }
    return {
      message:
        error instanceof ApiError
          ? "The operations API did not accept this control."
          : "The control could not be completed.",
      tone: "error",
      control,
    }
  }

  revalidatePath(`/runs/${encodeURIComponent(runId)}`)
  return { message, tone: "neutral", control }
}

/**
 * Re-render the run detail route so an autonomous phase change appears without a
 * reload. Reads nothing and grants nothing: revalidation only.
 */
export async function refreshRunDetailAction(runId: string): Promise<void> {
  if (!/^run_[0-9a-f]{32}$/.test(runId)) return
  revalidatePath(`/runs/${encodeURIComponent(runId)}`)
}

export interface LiveViewState {
  provider: BrowserProvider | null
  mode: LiveViewMode
  // There is no `liveUrl` here any more. It held a signed URL on a backend's own
  // origin, which the console embedded in a cross-origin iframe; the only backend
  // that issued one is gone, and every viewer below is served by this origin.
  screenshotUrl: string | null
  interactivePath: string | null
  capturedAt: string | null
  interactionAvailable: boolean
  // The backend's reason for the projected mode. The console reads it only to
  // separate "no embed right now" from the one closed-view case below.
  reasonCode: string | null
  message: string | null
  tone: "neutral" | "error"
}

function unavailableLiveView(message: string, reasonCode: string | null = null): LiveViewState {
  return {
    provider: null,
    mode: "unavailable",
    screenshotUrl: null,
    interactivePath: null,
    capturedAt: null,
    interactionAvailable: false,
    reasonCode,
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
      if (result.reason_code === SECRET_CAPTURE_BOUNDARY) {
        // Requirement 18.8: the view is closed, not masked. No screenshot is
        // requested here, so no frame of a credential surface can render.
        return {
          ...unavailableLiveView(
            "The live view is closed while this run is on a credential surface.",
            SECRET_CAPTURE_BOUNDARY,
          ),
          provider: result.provider,
        }
      }

      // Requirement 18.3: an unavailable embed degrades to the masked frame
      // rather than to a blank panel. The frame endpoint is independent of the
      // embed grant, and the panel reports the truth if it has nothing to serve.
      return {
        ...unavailableLiveView(
          "No live browser embed is available for this run; showing the latest masked frame instead.",
          result.reason_code ?? null,
        ),
        provider: result.provider,
        screenshotUrl: maskedScreenshotPath(runId, Date.now().toString()),
      }
    }

    if (result.mode === "screenshot" && result.screenshot_url) {
      return {
        provider: result.provider,
        mode: result.mode,
        screenshotUrl: maskedScreenshotPath(runId, result.captured_at ?? Date.now().toString()),
        interactivePath: null,
        capturedAt: result.captured_at ?? null,
        interactionAvailable: false,
        reasonCode: result.reason_code ?? null,
        message: "Latest Playwright browser frame loaded. This view is read-only.",
        tone: "neutral",
      }
    }

    if (result.mode === "interactive_remote" && result.interactive_url) {
      return {
        provider: result.provider,
        mode: "interactive_remote",
        screenshotUrl: null,
        interactivePath: sameOriginInteractivePath(result.interactive_url),
        capturedAt: result.captured_at ?? null,
        interactionAvailable: result.interaction_available,
        reasonCode: result.reason_code ?? null,
        message: result.interaction_available
          ? "Interactive Playwright session ready."
          : "Live Playwright session ready in view-only mode.",
        tone: "neutral",
      }
    }

    // A projected embed the console cannot render is still an unavailable embed,
    // so it degrades to the masked frame rather than to a blank panel (18.3).
    return {
      ...unavailableLiveView(
        "The projected live browser embed cannot be rendered here; showing the latest masked frame instead.",
        result.reason_code ?? null,
      ),
      provider: result.provider,
      screenshotUrl: maskedScreenshotPath(runId, Date.now().toString()),
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
