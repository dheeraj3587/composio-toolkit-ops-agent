import { Skeleton } from "@/components/ui/skeleton"

export default function SystemLoading() {
  return (
    <div className="space-y-8" aria-label="Loading system status" aria-busy="true">
      <div className="space-y-3 border-b border-border pb-7"><Skeleton className="h-4 w-36 rounded-md" /><Skeleton className="h-11 w-96 max-w-full rounded-md" /><Skeleton className="h-5 w-[34rem] max-w-full rounded-md" /></div>
      <Skeleton className="h-64 rounded-md" />
      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">{[0, 1, 2].map((item) => <Skeleton key={item} className="h-48 rounded-md" />)}</div>
    </div>
  )
}
