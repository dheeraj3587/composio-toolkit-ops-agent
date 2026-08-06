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

function progressIndex(
  status: RunStatus,
  phase: string,
  hitlAction?: string | null,
): number {
  if (status === "completed") return 4
  if (status === "credentials_ready") return 3
  if (
    hitlAction === "email_otp" ||
    ["outreach_sent", "waiting_for_reply"].includes(status)
  ) return 2
  if (
    ["route_selected", "connection_required", "browser_running", "waiting_for_hitl"].includes(status)
  ) return 1
  if (/credential|capture|validation|output/iu.test(phase)) return 3
  if (/email|verif/iu.test(phase)) return 2
  if (/browser|account|connect|auth/iu.test(phase)) return 1
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
        : `Agent is working · ${humanize(status)}`

  return (
    <section
      aria-label="Run progress"
      className="overflow-hidden rounded-2xl border border-brand-200 bg-gradient-to-br from-card via-card to-brand-50/70 shadow-[0_12px_40px_rgba(0,0,0,0.18)]"
    >
      <div className="flex flex-col gap-3 border-b border-brand-100 px-5 py-4 sm:flex-row sm:items-center sm:justify-between sm:px-6">
        <div>
          <p className="eyebrow">{planOnly ? "Planning progress" : "Live progress"}</p>
          <h2 className="mt-1 text-lg font-medium">{heading}</h2>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <div
            className={`flex w-fit items-center gap-2 rounded-full px-3 py-1.5 text-[11px] font-medium ${
              terminal ? "bg-secondary text-muted-foreground" : "bg-emerald-50 text-emerald-700 dark:bg-emerald-500/12 dark:text-emerald-300"
            }`}
            aria-live="polite"
          >
            {terminal ? (
              failed
                ? <TriangleAlert className="size-3.5" aria-hidden="true" />
                : <Check className="size-3.5" aria-hidden="true" />
            ) : (
              <>
                <span className="relative flex size-2" aria-hidden="true">
                  <span className="absolute inline-flex size-full animate-ping rounded-full bg-emerald-400 opacity-60" />
                  <span className="relative inline-flex size-2 rounded-full bg-emerald-500" />
                </span>
                Auto-updating every {Math.round(intervalMs / 1_000)}s
              </>
            )}
            {terminal
              ? planOnly
                ? "Plan ready"
                : failed
                  ? "Paused safely"
                  : "Finished"
              : null}
          </div>
          {recoverableConfiguration ? (
            <Button
              type="button"
              variant="outline"
              size="sm"
              onClick={refresh}
              disabled={refreshing}
              className="rounded-full"
            >
              <RefreshCw
                className={refreshing ? "animate-spin motion-reduce:animate-none" : ""}
                aria-hidden="true"
              />
              {refreshing ? "Refreshing…" : "Refresh status"}
            </Button>
          ) : null}
        </div>
      </div>

      <div className="px-5 py-5 sm:px-6">
        <div
          className="relative mb-5 h-2 overflow-hidden rounded-full bg-muted"
          role="progressbar"
          aria-label="Run completion"
          aria-valuemin={0}
          aria-valuemax={100}
          aria-valuenow={percent}
          aria-valuetext={`${percent}% · ${stages[current] ?? stages.at(-1)}`}
        >
          <div
            className={`h-full rounded-full transition-[width] duration-700 ${
              failed ? "bg-amber-400" : "bg-gradient-to-r from-brand-500 to-indigo-500"
            }`}
            style={{ width: `${percent}%` }}
          />
          {!terminal ? <div className="progress-shimmer absolute inset-y-0 w-24 bg-gradient-to-r from-transparent via-foreground/25 to-transparent" /> : null}
        </div>

        <ol className="grid grid-cols-5 gap-2">
          {stages.map((stage, index) => {
            const complete = index < current || status === "completed" || planOnly
            const active = index === current && status !== "completed" && !planOnly
            return (
              <li
                key={stage}
                className="min-w-0"
                aria-current={active ? "step" : undefined}
              >
                <span
                  className={`mb-2 grid size-6 place-items-center rounded-full border ${
                    complete
                      ? "border-brand-500 bg-brand-500 text-primary-foreground"
                      : active
                        ? failed
                          ? "border-amber-400 bg-amber-50 text-amber-700 dark:border-amber-500/45 dark:bg-amber-500/12 dark:text-amber-300"
                          : "border-brand-500 bg-brand-50 text-brand-700"
                        : "border-border bg-card text-muted-foreground/45"
                  }`}
                >
                  {complete ? (
                    <Check className="size-3.5" aria-hidden="true" />
                  ) : active ? (
                    failed ? <Pause className="size-3" aria-hidden="true" /> : <LoaderCircle className="size-3 animate-spin" aria-hidden="true" />
                  ) : (
                    <Circle className="size-2" aria-hidden="true" />
                  )}
                </span>
                <span className={`block truncate text-[10px] sm:text-xs ${active || complete ? "text-foreground" : "text-muted-foreground"}`}>
                  {stage}
                </span>
              </li>
            )
          })}
        </ol>
      </div>
    </section>
  )
}
