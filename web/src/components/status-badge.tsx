import { Badge } from "@/components/ui/badge"
import { humanize } from "@/lib/format"
import { cn } from "@/lib/utils"

const positive = new Set([
  "credentials_ready",
  "completed",
  "complete",
  "ready",
  "configured",
  "healthy",
  "pass",
  "self_serve",
  "managed_auth_ready",
  "browser_ready",
  "owner_submit_ready",
  "outreach_ready",
])
const negative = new Set(["blocked", "failed", "fail"])
const running = new Set(["researching", "route_selected", "connection_required", "browser_running", "running", "validating_credentials"])
const gated = new Set(["gated", "managed_auth", "playwright", "approval_required", "partner_gated", "hybrid"])
const unknown = new Set(["unknown", "not_reported", "unavailable", "not_available", "not_started", "not_attempted"])
const policy = new Set(["disabled", "policy_unavailable"])
const configPresent = new Set(["configured_not_verified"])
const configMissing = new Set(["not_configured", "outreach_review_required"])

function tone(status: string): string {
  if (policy.has(status)) return "border-indigo-400/30 bg-indigo-400/10 text-indigo-300"
  if (configPresent.has(status)) return "border-sky-400/30 bg-sky-400/10 text-sky-300"
  if (configMissing.has(status)) return "border-orange-400/30 bg-orange-400/10 text-orange-300"
  if (status === "configuration_required") return "border-orange-400/30 bg-orange-400/10 text-orange-300"
  if (status === "waiting_for_reply" || status === "outreach_sent") return "border-sky-400/30 bg-sky-400/10 text-sky-300"
  if (status === "waiting_for_hitl" || status === "waiting") return "border-amber-400/30 bg-amber-400/10 text-amber-300"
  if (gated.has(status)) return "border-brand-400/30 bg-brand-400/10 text-brand-300"
  if (positive.has(status)) return "border-emerald-400/30 bg-emerald-400/10 text-emerald-300"
  if (negative.has(status)) return "border-red-400/30 bg-red-400/10 text-red-300"
  if (running.has(status)) return "border-blue-400/30 bg-blue-400/10 text-blue-300"
  if (unknown.has(status)) return "border-slate-400/25 bg-slate-400/10 text-slate-400"
  return "border-border bg-secondary text-muted-foreground"
}

export function StatusBadge({ status, className }: { status?: string | null; className?: string }) {
  const value = status ?? "not_reported"
  return (
    <Badge
      variant="outline"
      className={cn(
        "max-w-full px-2 py-1 font-mono text-[9px] uppercase tracking-[0.08em]",
        tone(value),
        className,
      )}
    >
      <span className="size-1.5 shrink-0 rounded-full bg-current" aria-hidden="true" />
      {humanize(value)}
    </Badge>
  )
}
