import { Badge } from "@/components/ui/badge"
import { humanize } from "@/lib/format"
import { cn } from "@/lib/utils"

// ---------------------------------------------------------------------------
// Status vocabulary — configuration, policy, verification, and run outcomes
// must use visually distinct treatments so they are never confused.
// ---------------------------------------------------------------------------

// Run outcomes — positive
const positive = new Set(["credentials_ready", "completed", "complete", "ready", "configured", "healthy", "pass", "self_serve"])
// Run outcomes — negative
const negative = new Set(["blocked", "failed", "fail"])
// Run outcomes — in-progress
const running = new Set(["researching", "route_selected", "browser_running", "running", "validating_credentials"])
// Run outcomes — gated
const gated = new Set(["gated", "approval_required", "partner_gated", "hybrid"])
// Unknown / absent
const unknown = new Set(["unknown", "not_reported", "unavailable", "not_available"])
// Policy — intentionally disabled by runtime configuration
const policy = new Set(["disabled"])
// Configuration — present but not verified through a live probe
const configPresent = new Set(["configured_not_verified"])
// Configuration — missing
const configMissing = new Set(["not_configured"])

function tone(status: string): string {
  // Policy: distinct indigo treatment — not a failure, not neutral
  if (policy.has(status)) return "border-indigo-300 bg-indigo-50 text-indigo-800"
  // Configuration present but unverified: distinct amber treatment
  if (configPresent.has(status)) return "border-amber-300 bg-amber-50 text-amber-800"
  // Configuration missing: distinct slate/orange treatment
  if (configMissing.has(status)) return "border-orange-300 bg-orange-50 text-orange-800"
  // Run-specific states
  if (status === "configuration_required") return "border-orange-300 bg-orange-50 text-orange-800"
  if (status === "waiting_for_reply" || status === "outreach_sent") return "border-sky-300 bg-sky-50 text-sky-800"
  if (status === "waiting_for_hitl" || status === "waiting") return "border-amber-300 bg-amber-50 text-amber-800"
  if (gated.has(status)) return "border-violet-300 bg-violet-50 text-violet-800"
  if (positive.has(status)) return "border-emerald-300 bg-emerald-50 text-emerald-800"
  if (negative.has(status)) return "border-red-300 bg-red-50 text-red-800"
  if (running.has(status)) return "border-blue-300 bg-blue-50 text-blue-800"
  if (unknown.has(status)) return "border-slate-300 bg-slate-50 text-slate-600"
  return "border-border bg-white text-muted-foreground"
}

export function StatusBadge({ status, className }: { status?: string | null; className?: string }) {
  const value = status ?? "not_reported"
  return (
    <Badge
      variant="outline"
      className={cn(
        "max-w-full rounded-md px-2 py-1 font-mono text-[9px] uppercase tracking-[0.1em]",
        tone(value),
        className,
      )}
    >
      <span className="size-1.5 shrink-0 rounded-full bg-current" aria-hidden="true" />
      {humanize(value)}
    </Badge>
  )
}
