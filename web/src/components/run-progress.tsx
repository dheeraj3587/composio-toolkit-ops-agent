"use client"

import { useEffect, useTransition } from "react"
import { useRouter } from "next/navigation"
import { Check, Circle, LoaderCircle, Pause, RefreshCw, TriangleAlert } from "lucide-react"

import { Button } from "@/components/ui/button"
import { humanize } from "@/lib/format"
import type { AccountMode, ExecutionMode, RunStatus } from "@/lib/types"

const TERMINAL_STATUSES: ReadonlySet<RunStatus> = new Set([
  "completed",
  "failed",
  "blocked",
  "configuration_required",
])

/**
 * Which rail stage each durable phase belongs to.
 *
 * This replaces a regex over the phase string (`/credential|capture|validation/`
 * and friends). The backend's `OnboardingPhase` is a closed 17-value union, so
 * guessing from substrings could disagree with reality — `credential_validation`
 * and `vault_check` both contain neither an obvious stage word nor a unique one,
 * and a phase added later would silently fall through to "Prepare".
 *
 * An explicit table cannot drift silently: a new phase is absent here, hits the
 * `?? null` below, and falls back to the status mapping rather than being
 * mis-placed. Terminal phases are deliberately absent — status carries those.
 */
const PHASE_STAGE: Record<string, number> = {
  research: 0,
  vault_check: 0,
  awaiting_admission: 0,
  route_selected_signup: 1,
  route_selected_login: 1,
  signup: 1,
  email_verification: 2,
  authenticated: 2,
  developer_app: 3,
  credential_generation: 3,
  vault_storage: 3,
  credential_validation: 3,
}

function progressIndex(status: RunStatus, phase: string, hitlAction?: string | null): number {
  // Status wins where it is unambiguous about the whole run.
  if (status === "completed") return 4
  if (status === "credentials_ready") return 3
  if (hitlAction === "email_otp" || ["outreach_sent", "waiting_for_reply"].includes(status)) return 2

  // Then the durable phase, which is the backend's own answer.
  const fromPhase = PHASE_STAGE[phase] ?? null
  if (fromPhase !== null) return fromPhase

  // A paused or blocked run keeps the stage it reached; the rail shows position,
  // and the badge beside it already says the run stopped.
  if (["route_selected", "connection_required", "browser_running", "waiting_for_hitl"].includes(status)) return 1
  return 0
}

export function RunProgress({
  status,
  phase,
  executionMode,
  accountMode,
  hitlAction,
  intervalMs = 4_000,
}: {
  status: RunStatus
  phase: string
  executionMode: ExecutionMode
  accountMode?: AccountMode | null
  hitlAction?: string | null
  intervalMs?: number
}) {
  const router = useRouter()
  const [refreshing, startRefresh] = useTransition()
  const planOnly = executionMode === "plan_only"
  const terminal = planOnly || TERMINAL_STATUSES.has(status)
  const current = planOnly ? 4 : progressIndex(status, phase, hitlAction)
  const failed = !planOnly && ["failed", "blocked", "configuration_required"].includes(status)
  const recoverableConfiguration = !planOnly && status === "configuration_required"
  const stages = planOnly
    ? ["Prepare", "Research", "Select route", "Review plan", "Plan ready"]
    : accountMode === "create_account"
      ? ["Prepare", "Create account", "Verify email", "Secure credential", "Complete"]
      : accountMode === "existing_account"
        ? ["Prepare", "Sign in", "Open API settings", "Secure credential", "Complete"]
        : ["Prepare", "Access account", "Verification", "Secure credential", "Complete"]
  const percent = planOnly || status === "completed" ? 100 : Math.max(10, current * 25 + 12)

  useEffect(() => {
    if (terminal) return
    let cancelled = false
    let timer: ReturnType<typeof setTimeout> | undefined
    const schedule = () => {
      timer = setTimeout(() => {
        if (document.visibilityState === "visible") router.refresh()
        if (!cancelled) schedule()
      }, intervalMs)
    }
    const refreshWhenVisible = () => {
      if (document.visibilityState === "visible") router.refresh()
    }
    schedule()
    document.addEventListener("visibilitychange", refreshWhenVisible)
    return () => {
      cancelled = true
      if (timer) clearTimeout(timer)
      document.removeEventListener("visibilitychange", refreshWhenVisible)
    }
  }, [terminal, intervalMs, router])

  const refresh = () => startRefresh(() => router.refresh())
  const heading = planOnly
    ? "Planning is complete"
    : status === "completed"
      ? "Integration is ready"
      : failed
        ? "The run needs attention"
        : `In progress · ${humanize(status)}`

  return (
    <section aria-label="Run progress" className="panel overflow-hidden">
      <div className="flex flex-col gap-3 border-b border-border px-5 py-4 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <p className="eyebrow">{planOnly ? "Planning progress" : "Live progress"}</p>
          <h2 className="mt-1 text-lg font-medium">{heading}</h2>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <div
            className={`flex w-fit items-center gap-2 rounded-md border px-2.5 py-1.5 text-[11px] font-medium ${
              failed
                ? "border-l-[3px] border-foreground bg-secondary text-foreground"
                : terminal
                  ? "border-border bg-secondary text-muted-foreground"
                  : "border-[--line-live] bg-secondary text-foreground"
            }`}
            aria-live="polite"
          >
            {terminal ? (
              failed ? <TriangleAlert className="size-3.5" aria-hidden="true" /> : <Check className="size-3.5" aria-hidden="true" />
            ) : (
              // Ringed + pulsing rather than a filled dot: "live" reads as
              // motion, which survives the loss of colour.
              <span className="size-1.5 rounded-full ring-[1.5px] ring-current cot-marker-live" aria-hidden="true" />
            )}
            {terminal
              ? planOnly
                ? "Plan ready"
                : failed
                  ? "Paused safely"
                  : "Finished"
              : `Auto-updating every ${Math.round(intervalMs / 1_000)}s`}
          </div>
          {recoverableConfiguration ? (
            <Button type="button" variant="outline" size="sm" onClick={refresh} disabled={refreshing}>
              <RefreshCw className={refreshing ? "animate-spin motion-reduce:animate-none" : ""} aria-hidden="true" />
              {refreshing ? "Refreshing…" : "Refresh status"}
            </Button>
          ) : null}
        </div>
      </div>

      <div className="px-5 py-5">
        <div
          className="mb-5 h-1.5 overflow-hidden rounded-full bg-secondary"
          role="progressbar"
          aria-label="Run completion"
          aria-valuemin={0}
          aria-valuemax={100}
          aria-valuenow={percent}
          aria-valuetext={`${percent}% · ${stages[current] ?? stages.at(-1)}`}
        >
          <div
            className={`h-full rounded-full transition-[width] duration-500 ${failed ? "bg-muted-foreground" : "bg-foreground"}`}
            style={{ width: `${percent}%` }}
          />
        </div>

        <ol className="grid grid-cols-5 gap-2">
          {stages.map((stage, index) => {
            const complete = index < current || status === "completed" || planOnly
            const active = index === current && status !== "completed" && !planOnly
            return (
              <li key={stage} className="min-w-0" aria-current={active ? "step" : undefined}>
                <span
                  className={`mb-2 grid size-5 place-items-center rounded-full border ${
                    complete
                      ? // The one inverted treatment: a finished stage.
                        "border-foreground bg-foreground text-background"
                      : active
                        ? failed
                          ? "border-dashed border-muted-foreground bg-transparent text-foreground"
                          : "border-foreground bg-transparent text-foreground"
                        : "border-border bg-field text-muted-foreground/45"
                  }`}
                >
                  {complete ? (
                    <Check className="size-3" aria-hidden="true" />
                  ) : active ? (
                    failed ? <Pause className="size-2.5" aria-hidden="true" /> : <LoaderCircle className="size-2.5 animate-spin motion-reduce:animate-none" aria-hidden="true" />
                  ) : (
                    <Circle className="size-1.5" aria-hidden="true" />
                  )}
                </span>
                <span className={`block truncate text-[10px] sm:text-xs ${active || complete ? "text-foreground" : "text-muted-foreground"}`}>{stage}</span>
              </li>
            )
          })}
        </ol>
      </div>
    </section>
  )
}
