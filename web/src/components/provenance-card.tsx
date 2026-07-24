import { Check, FileWarning, GitCommitHorizontal } from "lucide-react"

import { Badge } from "@/components/ui/badge"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Separator } from "@/components/ui/separator"
import type { SnapshotHealth } from "@/lib/types"

function short(value?: string, length = 12): string {
  if (!value) return "Not reported"
  return value.length > length ? `${value.slice(0, length)}…` : value
}

export function ProvenanceCard({ snapshot }: { snapshot: SnapshotHealth | null }) {
  return (
    <Card className="h-full rounded-lg border-border bg-card py-0 shadow-none">
      <CardHeader className="border-b border-border px-5 py-4">
        <div className="flex items-center justify-between gap-3">
          <div>
            <p className="eyebrow">Input / immutable</p>
            <CardTitle className="mt-1 text-lg font-semibold">P1 snapshot provenance</CardTitle>
          </div>
          <Badge
            variant="outline"
            className="rounded-md border-border font-mono text-[9px] uppercase tracking-[0.1em]"
          >
            {snapshot?.verified ? <Check aria-hidden="true" /> : <FileWarning aria-hidden="true" />}
            {snapshot?.verified ? "Hash verified" : "Not verified"}
          </Badge>
        </div>
      </CardHeader>
      <CardContent className="space-y-4 px-5 py-5">
        <div>
          <span className="data-label">Source repository</span>
          <p className="mt-1 break-words font-mono text-xs">{snapshot?.source_repository ?? "Backend did not report a snapshot."}</p>
        </div>
        <Separator className="bg-border" />
        <div className="grid grid-cols-2 gap-4">
          <div>
            <span className="data-label">Commit</span>
            <p className="mt-1 flex items-center gap-1.5 font-mono text-xs">
              <GitCommitHorizontal className="size-3.5 text-brand-600" aria-hidden="true" />
              {short(snapshot?.source_commit)}
            </p>
          </div>
          <div>
            <span className="data-label">Copied</span>
            <p className="mt-1 font-mono text-xs">{short(snapshot?.copied_at, 20)}</p>
          </div>
        </div>
        <Separator className="bg-border" />
        <div className="grid grid-cols-2 gap-4">
          <div>
            <span className="data-label">Results SHA-256</span>
            <p className="mt-1 font-mono text-xs" title={snapshot?.results_sha256}>
              {short(snapshot?.results_sha256, 10)}
            </p>
          </div>
          <div>
            <span className="data-label">Coverage SHA-256</span>
            <p className="mt-1 font-mono text-xs" title={snapshot?.coverage_sha256}>
              {short(snapshot?.coverage_sha256, 10)}
            </p>
          </div>
        </div>
        <p className="border-l-2 border-brand-400 pl-3 text-xs leading-5 text-muted-foreground">
          Canonical P1 files remain read-only. Operational enrichment belongs to this ledger.
        </p>
      </CardContent>
    </Card>
  )
}
