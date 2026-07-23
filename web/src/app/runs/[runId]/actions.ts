"use server"

import { revalidatePath } from "next/cache"

import {
  ApiError,
  getLiveView,
  performPhaseAction,
  PhaseConflictError,
  submitCredentials,
} from "@/lib/api"
import type { RetryCapability, RunPhaseAction } from "@/lib/types"

export interface PhaseActionState {
  message: string | null
  tone: "neutral" | "error"
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
    revalidatePath(`/runs/${encodeURIComponent(runId)}`)
    return {
      message: receipt.detail ?? (receipt.status === "no_change" ? "Backend state did not change." : "Backend accepted the action."),
      tone: receipt.status === "configuration_required" ? "error" : "neutral",
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
  liveUrl: string | null
  message: string | null
  tone: "neutral" | "error"
}

export async function openLiveView(
  _previousState: LiveViewState,
  formData: FormData,
): Promise<LiveViewState> {
  const runId = String(formData.get("run_id") ?? "").slice(0, 180)
  if (!runId) {
    return { liveUrl: null, message: "The run reference is invalid.", tone: "error" }
  }
  try {
    const result = await getLiveView(runId)
    if (!result.available || !result.live_url) {
      return {
        liveUrl: null,
        message: "No live browser session is currently available for this run.",
        tone: "error",
      }
    }
    return { liveUrl: result.live_url, message: "Live browser session ready.", tone: "neutral" }
  } catch (error) {
    const message =
      error instanceof ApiError && error.status === 403
        ? "Live view is restricted to the owner on localhost."
        : "The live browser URL could not be retrieved."
    return { liveUrl: null, message, tone: "error" }
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
    work_email_ref: String(formData.get("work_email_ref") ?? "").slice(0, 512),
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
  if (!company.legal_name || !company.website || !company.work_email_ref || !company.use_case) {
    return {
      message: "Company legal name, website, work email vault reference, and use case are required.",
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
