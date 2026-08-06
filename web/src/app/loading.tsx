import { Skeleton } from "@/components/ui/skeleton"

export default function Loading() {
  return (
    <div className="space-y-10" aria-label="Loading" aria-busy="true">
      <div className="space-y-4 border-b border-border pb-7">
        <Skeleton className="h-3 w-40 rounded-md" />
        <Skeleton className="h-9 max-w-xl rounded-md" />
        <Skeleton className="h-4 max-w-text rounded-md" />
      </div>
      <div className="grid gap-px overflow-hidden rounded-lg border border-border bg-border sm:grid-cols-2 xl:grid-cols-4">
        {["a", "b", "c", "d"].map((key) => (
          <Skeleton key={key} className="h-32 rounded-none" />
        ))}
      </div>
      <Skeleton className="h-80 rounded-lg" />
    </div>
  )
}
