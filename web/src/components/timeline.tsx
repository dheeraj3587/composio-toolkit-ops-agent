import { Circle, TerminalSquare } from "lucide-react"

import { EmptyState } from "@/components/empty-state"
import { formatTimestamp } from "@/lib/format"
import type { TimelineItem } from "@/lib/types"

function summary(item: TimelineItem): string {
  if (item.summary) return item.summary.slice(0, 240)
  if (item.status) return `Status: ${item.status.replaceAll("_", " ")}`
  return "Sanitized event recorded."
}

export function Timeline({ items }: { items: TimelineItem[] }) {
  if (items.length === 0) {
    return <EmptyState title="No events recorded" description="The backend has not reported a sanitized timeline for this run." />
  }

  return (
    <ol className="border border-ink/25 bg-card/50" aria-label="Sanitized run timeline">
      {items.map((item) => (
        <li key={`${item.event_type}-${item.created_at}`} className="grid gap-4 border-b border-ink/15 px-5 py-5 last:border-0 sm:grid-cols-[150px_24px_1fr]">
          <time className="font-mono text-[10px] uppercase tracking-[0.08em] text-muted-foreground" dateTime={item.created_at}>
            {formatTimestamp(item.created_at)}
          </time>
          <span className="relative hidden justify-center sm:flex" aria-hidden="true">
            <span className="absolute bottom-[-21px] top-5 w-px bg-ink/15 last:hidden" />
            <Circle className="size-3 fill-rust text-rust" />
          </span>
          <div>
            <p className="flex items-center gap-2 font-mono text-[10px] uppercase tracking-[0.12em]">
              <TerminalSquare className="size-3.5 text-viridian" aria-hidden="true" />
              {item.event_type.replaceAll("_", " ")}
            </p>
            <p className="mt-2 text-sm leading-6 text-muted-foreground">{summary(item)}</p>
          </div>
        </li>
      ))}
    </ol>
  )
}
