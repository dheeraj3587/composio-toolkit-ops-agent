"use server"

import { revalidatePath } from "next/cache"

import { ApiError, performPhaseAction, PhaseConflictError } from "@/lib/api"
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
