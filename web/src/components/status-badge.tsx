import { Badge } from "@/components/ui/badge"
import { humanize } from "@/lib/format"
import { cn } from "@/lib/utils"

const waiting = new Set(["waiting_for_hitl", "waiting_for_reply", "outreach_sent", "configuration_required"])
const positive = new Set(["credentials_ready", "completed", "complete", "ready", "configured", "healthy", "pass", "self_serve"])
const negative = new Set(["blocked", "failed", "fail"])
const running = new Set(["researching", "route_selected", "browser_running", "running", "validating_credentials"])

export function StatusBadge({ status, className }: { status?: string | null; className?: string }) {
  const value = status ?? "not_reported"
  return (
    <Badge
      variant="outline"
      className={cn(
        "max-w-full rounded-md px-2 py-1 font-mono text-[9px] uppercase tracking-[0.1em]",
        waiting.has(value) && "border-amber-300 bg-amber-50 text-amber-800",
        positive.has(value) && "border-emerald-300 bg-emerald-50 text-emerald-800",
        negative.has(value) && "border-red-300 bg-red-50 text-red-800",
        running.has(value) && "border-violet-300 bg-violet-50 text-violet-800",
        !waiting.has(value) &&
          !positive.has(value) &&
          !negative.has(value) &&
          !running.has(value) &&
          "border-border bg-white text-muted-foreground",
        className,
      )}
    >
      <span className="size-1.5 shrink-0 rounded-full bg-current" aria-hidden="true" />
      {humanize(status)}
    </Badge>
  )
}
