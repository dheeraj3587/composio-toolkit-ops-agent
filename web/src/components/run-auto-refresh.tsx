"use client"

import { useEffect } from "react"
import { useRouter } from "next/navigation"

import type { RunStatus } from "@/lib/types"

// Terminal states stop polling. Everything else is treated as in-flight.
const TERMINAL_STATUSES: ReadonlySet<RunStatus> = new Set<RunStatus>([
  "completed",
  "failed",
  "blocked",
  "configuration_required",
])

/**
 * Invisible poller for the server-rendered run detail view.
 *
 * While the run is non-terminal it triggers a soft server refresh on a fixed
 * interval, which re-fetches the run, timeline and output from the real API and
 * re-renders the page. It stops as soon as the backend reports a terminal
 * status. It renders nothing and holds no run data in client state.
 */
export function RunAutoRefresh({
  status,
  intervalMs = 2_500,
}: {
  status: RunStatus
  intervalMs?: number
}) {
  const router = useRouter()

  useEffect(() => {
    if (TERMINAL_STATUSES.has(status)) return

    const timer = setInterval(() => {
      router.refresh()
    }, intervalMs)

    return () => clearInterval(timer)
  }, [status, intervalMs, router])

  return null
}
