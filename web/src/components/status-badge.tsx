import { Badge } from "@/components/ui/badge"
import { humanize } from "@/lib/format"
import { cn } from "@/lib/utils"

/**
 * Status in monochrome: carried by FORM, never by hue.
 *
 * The palette has no accent colour, so the eight tones this component used to
 * emit would all resolve to the same grey. Form replaces them — and form is
 * also the accessible answer, since colour alone was never sufficient:
 *
 *   filled marker + inverted chip   settled and good (complete, ready, healthy)
 *   ringed marker + live border      the agent is working right now
 *   dashed marker + dashed border    stopped, waiting for a person
 *   double left rule                 blocked or failed — heaviest edge on screen
 *   hairline chip                    nothing has happened yet
 *
 * The vocabulary sets below are the backend's closed status vocabulary and are
 * unchanged; only their presentation moved from colour to shape.
 */

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
const running = new Set([
  "researching",
  "route_selected",
  "connection_required",
  "browser_running",
  "running",
  "validating_credentials",
])
const waiting = new Set([
  "waiting_for_hitl",
  "waiting",
  "waiting_for_reply",
  "outreach_sent",
  "paused",
])
const attention = new Set([
  "configuration_required",
  "not_configured",
  "outreach_review_required",
])
const gated = new Set([
  "gated",
  "managed_auth",
  "playwright",
  "approval_required",
  "partner_gated",
  "hybrid",
])
const idle = new Set([
  "unknown",
  "not_reported",
  "unavailable",
  "not_available",
  "not_started",
  "not_attempted",
  "disabled",
  "policy_unavailable",
  "configured_not_verified",
])

type Form = "settled" | "live" | "held" | "stopped" | "flagged" | "idle"

function form(status: string): Form {
  if (negative.has(status)) return "stopped"
  if (waiting.has(status)) return "held"
  if (running.has(status)) return "live"
  if (positive.has(status)) return "settled"
  if (attention.has(status)) return "flagged"
  if (gated.has(status)) return "idle"
  if (idle.has(status)) return "idle"
  return "idle"
}

const chip: Record<Form, string> = {
  // Inverted: the one place the palette flips, reserved for a finished run.
  settled: "border-transparent bg-foreground text-background",
  live: "border-[--line-live] bg-secondary text-foreground",
  held: "border-dashed border-muted-foreground bg-transparent text-foreground",
  // Heaviest edge available. Severity by weight, not by red.
  stopped: "border-foreground border-l-[3px] bg-secondary text-foreground",
  flagged: "border-muted-foreground bg-transparent text-foreground",
  idle: "border-border bg-transparent text-muted-foreground",
}

const marker: Record<Form, string> = {
  settled: "rounded-full bg-current",
  live: "rounded-full bg-transparent ring-[1.5px] ring-current cot-marker-live",
  held: "rounded-[1px] bg-transparent ring-1 ring-dashed ring-current",
  stopped: "rounded-none bg-current",
  flagged: "rounded-full bg-transparent ring-1 ring-current",
  idle: "rounded-full bg-transparent ring-1 ring-current",
}

export function StatusBadge({ status, className }: { status?: string | null; className?: string }) {
  const value = status ?? "not_reported"
  const shape = form(value)

  return (
    <Badge
      variant="outline"
      data-form={shape}
      className={cn(
        "max-w-full px-2 py-1 font-mono text-[9px] tracking-[0.08em] uppercase",
        chip[shape],
        className,
      )}
    >
      <span className={cn("size-1.5 shrink-0", marker[shape])} aria-hidden="true" />
      {humanize(value)}
    </Badge>
  )
}
