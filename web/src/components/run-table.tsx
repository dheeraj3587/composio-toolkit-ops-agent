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
import type { RunSummary } from "@/lib/types"
import { formatTimestamp, humanize, relativeTimestamp } from "@/lib/format"

export function RunTable({ runs }: { runs: RunSummary[] }) {
  if (runs.length === 0) {
    return (
      <EmptyState
        title="The ledger is blank"
        description="Create a local dry run to establish a sanitized record. No provider, browser, or email action will be implied."
        action
      />
    )
  }

  return (
    <div className="overflow-x-auto rounded-md border border-border bg-card">
      <Table>
        <TableHeader>
          <TableRow className="border-border bg-muted/45 hover:bg-muted/45">
            <TableHead className="font-mono text-[10px] uppercase tracking-[0.14em]">Application</TableHead>
            <TableHead className="font-mono text-[10px] uppercase tracking-[0.14em]">Route</TableHead>
            <TableHead className="font-mono text-[10px] uppercase tracking-[0.14em]">Status</TableHead>
            <TableHead className="hidden font-mono text-[10px] uppercase tracking-[0.14em] lg:table-cell">
              Updated · UTC
            </TableHead>
            <TableHead className="w-20"><span className="sr-only">Open run</span></TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {runs.map((run) => (
            <TableRow key={run.run_id} className="border-border hover:bg-violet-50/35">
              <TableCell>
                <span className="block text-sm font-semibold leading-tight">{run.app_name}</span>
                <span className="mt-1 block max-w-48 truncate font-mono text-[10px] text-muted-foreground">
                  {run.run_id}
                </span>
              </TableCell>
              <TableCell className="font-mono text-[10px] uppercase tracking-[0.1em] text-muted-foreground">
                {humanize(run.access_route)}
              </TableCell>
              <TableCell><StatusBadge status={run.status} /></TableCell>
              <TableCell className="hidden text-xs text-muted-foreground lg:table-cell" title={formatTimestamp(run.updated_at)}>
                {relativeTimestamp(run.updated_at)}
              </TableCell>
              <TableCell className="text-right">
                <Button asChild variant="ghost" size="icon" className="rounded-md" aria-label={`Open ${run.app_name} run`}>
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
