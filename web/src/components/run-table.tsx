import Link from "next/link"
import { ArrowUpRight } from "lucide-react"

import { EmptyState } from "@/components/empty-state"
import { StatusBadge } from "@/components/status-badge"
import { Button } from "@/components/ui/button"
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"
import { formatTimestamp, humanize, relativeTimestamp } from "@/lib/format"
import type { RunSummary } from "@/lib/types"

export function RunTable({ runs }: { runs: RunSummary[] }) {
  if (runs.length === 0) {
    return (
      <EmptyState
        title="No integration runs yet"
        description="Start an integration to create the first backend-reported run."
        action
      />
    )
  }

  return (
    <div className="overflow-x-auto rounded-lg border border-border bg-card">
      <Table>
        <TableHeader>
          <TableRow className="border-border bg-secondary/45 hover:bg-secondary/45">
            <TableHead className="px-4 font-mono text-[10px] uppercase tracking-[0.12em] text-muted-foreground">Application</TableHead>
            <TableHead className="font-mono text-[10px] uppercase tracking-[0.12em] text-muted-foreground">Route</TableHead>
            <TableHead className="font-mono text-[10px] uppercase tracking-[0.12em] text-muted-foreground">Status</TableHead>
            <TableHead className="hidden font-mono text-[10px] uppercase tracking-[0.12em] text-muted-foreground lg:table-cell">
              Updated · UTC
            </TableHead>
            <TableHead className="w-16"><span className="sr-only">Open run</span></TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {runs.map((run) => (
            <TableRow key={run.run_id} className="border-border hover:bg-secondary/35">
              <TableCell className="px-4 py-3">
                <span className="block text-sm font-medium leading-tight">{run.app_name}</span>
                <span className="mt-1 block max-w-64 truncate font-mono text-[10px] text-muted-foreground">
                  {humanize(run.browser_provider)} · recipe {run.recipe_version ?? "legacy"}
                </span>
              </TableCell>
              <TableCell className="py-3">
                <span className="block font-mono text-[10px] uppercase tracking-[0.08em] text-muted-foreground">
                  {humanize(run.route_kind ?? run.access_route)}
                </span>
                <StatusBadge status={run.readiness_tier} className="mt-1" />
              </TableCell>
              <TableCell className="py-3"><StatusBadge status={run.status} /></TableCell>
              <TableCell className="hidden py-3 text-xs text-muted-foreground lg:table-cell" title={formatTimestamp(run.updated_at)}>
                {relativeTimestamp(run.updated_at)}
              </TableCell>
              <TableCell className="py-3 text-right">
                <Button asChild variant="ghost" size="icon" aria-label={`Open ${run.app_name} run`}>
                  <Link href={`/runs/${encodeURIComponent(run.run_id)}`}>
                    <ArrowUpRight aria-hidden="true" />
                  </Link>
                </Button>
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </div>
  )
}
