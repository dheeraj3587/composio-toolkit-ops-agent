import { Skeleton } from "@/components/ui/skeleton"

export default function Loading() {
  return (
    <div className="space-y-8" aria-label="Loading operations ledger" aria-busy="true">
      <div className="space-y-4"><Skeleton className="h-3 w-40 rounded-none bg-ink/10" /><Skeleton className="h-20 max-w-3xl rounded-none bg-ink/10" /><Skeleton className="h-5 max-w-xl rounded-none bg-ink/10" /></div>
      <Skeleton className="h-px w-full rounded-none bg-ink/25" />
      <div className="grid gap-px bg-ink/15 sm:grid-cols-2 xl:grid-cols-4">{["a", "b", "c", "d"].map((key) => <Skeleton key={key} className="h-40 rounded-none bg-card/65" />)}</div>
      <Skeleton className="h-80 rounded-none bg-card/65" />
    </div>
  )
}
