import { Check, FileWarning, GitCommitHorizontal } from "lucide-react"

import { Badge } from "@/components/ui/badge"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Separator } from "@/components/ui/separator"
import type { SnapshotHealth } from "@/lib/types"

function short(value: string | undefined, length: number): string {
  if (!value) return "Not reported"
  return value.length > length ? `${value.slice(0, length)}…` : value
}

export function ProvenanceCard({ snapshot }: { snapshot: SnapshotHealth | null }) {
  const verified = snapshot?.verified ?? false
  return (
    <Card className="h-full rounded-lg border-border bg-card py-0 shadow-none">
      <CardHeader className="border-b border-border px-5 py-4">
        <div className="flex items-center justify-between gap-3">
          <div>
            <p className="eyebrow">Read-only input</p>
            <CardTitle className="mt-1 text-lg font-medium">Where the app list came from</CardTitle>
          </div>
          <Badge
            variant="outline"
            className="shrink-0 rounded-md border-border font-mono text-[11px] uppercase tracking-[0.1em]"
            title={
              verified
                ? "The copied files still hash to the values recorded when they were copied."
                : "The backend did not confirm the copied files against their recorded hashes."
            }
          >
            {verified ? <Check aria-hidden="true" /> : <FileWarning aria-hidden="true" />}
            {verified ? "Unchanged" : "Not confirmed"}
          </Badge>
        </div>
      </CardHeader>
      <CardContent className="space-y-4 px-5 py-5">
        <p className="text-xs leading-5 text-muted-foreground">
          The app catalog this console offers was copied from a separate research repository and
          is never edited here. Everything a run learns afterwards is stored separately.
        </p>
        <Separator className="bg-border" />
        <div>
          <span className="data-label">Repository</span>
          <p className="mt-1 break-words font-mono text-xs">
            {snapshot?.source_repository ?? "The backend did not report a source."}
          </p>
        </div>
        <div className="grid grid-cols-2 gap-4">
          <div>
            <span className="data-label">Commit</span>
            <p className="mt-1 flex items-center gap-1.5 font-mono text-xs">
              <GitCommitHorizontal className="size-3.5 text-brand-500" aria-hidden="true" />
              {short(snapshot?.source_commit, 12)}
            </p>
          </div>
          <div>
            <span className="data-label">Copied</span>
            <p className="mt-1 font-mono text-xs">{short(snapshot?.copied_at, 20)}</p>
          </div>
        </div>
        <div className="grid grid-cols-2 gap-4">
          <div>
            <span className="data-label">Results checksum</span>
            <p className="mt-1 font-mono text-xs" title={snapshot?.results_sha256}>
              {short(snapshot?.results_sha256, 10)}
            </p>
          </div>
          <div>
            <span className="data-label">Coverage checksum</span>
            <p className="mt-1 font-mono text-xs" title={snapshot?.coverage_sha256}>
              {short(snapshot?.coverage_sha256, 10)}
            </p>
          </div>
        </div>
      </CardContent>
    </Card>
  )
}
