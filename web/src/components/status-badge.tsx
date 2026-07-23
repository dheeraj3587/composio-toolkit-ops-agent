import { Badge } from "@/components/ui/badge"
import { humanize } from "@/lib/format"
import { cn } from "@/lib/utils"

const positive = new Set(["credentials_ready", "completed", "complete", "ready", "configured", "healthy", "pass", "self_serve"])
const negative = new Set(["blocked", "failed", "fail"])
const running = new Set(["researching", "route_selected", "browser_running", "running", "validating_credentials"])
const gated = new Set(["gated", "approval_required", "partner_gated", "hybrid"])
const unknown = new Set(["unknown", "not_reported", "unavailable", "not_available"])

function tone(status: string): string {
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
