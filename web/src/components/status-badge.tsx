import { Badge } from "@/components/ui/badge"
import { humanize } from "@/lib/format"
import { cn } from "@/lib/utils"

const waiting = new Set(["waiting_for_hitl", "waiting_for_reply", "outreach_sent"])
const positive = new Set(["credentials_ready", "completed", "complete", "ready"])
const negative = new Set(["blocked", "failed"])
const running = new Set(["researching", "route_selected", "browser_running", "running"])

export function StatusBadge({ status, className }: { status?: string | null; className?: string }) {
  const value = status ?? "not_reported"
  return (
    <Badge
      variant="outline"
      className={cn(
        "rounded-none px-2 py-2 font-mono text-[9px] uppercase tracking-[0.12em]",
        waiting.has(value) && "border-rust/50 bg-rust/8 text-rust",
        positive.has(value) && "border-viridian/50 bg-viridian/8 text-viridian",
        negative.has(value) && "border-destructive/50 bg-destructive/8 text-destructive",
        running.has(value) && "border-ink/40 bg-ink/5 text-ink",
        !waiting.has(value) &&
          !positive.has(value) &&
          !negative.has(value) &&
          !running.has(value) &&
          "border-ink/20 text-muted-foreground",
        className,
      )}
    >
      <span className="size-1.5 bg-current" aria-hidden="true" />
      {humanize(status)}
    </Badge>
  )
}
