import { Skeleton } from "@/components/ui/skeleton"

export default function Loading() {
  return (
    <div className="space-y-7" aria-label="Loading operations workspace" aria-busy="true">
      <div className="space-y-3">
        <Skeleton className="h-3 w-36" />
        <Skeleton className="h-10 max-w-xl" />
        <Skeleton className="h-4 max-w-lg" />
      </div>
      <div className="grid gap-px overflow-hidden rounded-lg border border-border bg-border sm:grid-cols-2 xl:grid-cols-4">
        {["a", "b", "c", "d"].map((key) => <Skeleton key={key} className="h-28 rounded-none bg-card" />)}
      </div>
      <Skeleton className="h-72 rounded-lg" />
    </div>
  )
}
