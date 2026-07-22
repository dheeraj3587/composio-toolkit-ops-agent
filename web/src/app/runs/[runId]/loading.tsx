import { Skeleton } from "@/components/ui/skeleton"

export default function RunLoading() {
  return (
    <div className="space-y-8" aria-label="Loading run detail" aria-busy="true">
      <Skeleton className="h-8 w-28 rounded-md" />
      <div className="space-y-3 border-b border-border pb-7"><Skeleton className="h-4 w-40 rounded-md" /><Skeleton className="h-11 w-72 rounded-md" /><Skeleton className="h-3 w-80 rounded-md" /></div>
      <div className="grid gap-px bg-border sm:grid-cols-2 xl:grid-cols-5">{[0, 1, 2, 3, 4].map((item) => <Skeleton key={item} className="h-44 rounded-none" />)}</div>
      <div className="grid gap-5 xl:grid-cols-[1.25fr_0.75fr]"><Skeleton className="h-96 rounded-md" /><Skeleton className="h-96 rounded-md" /></div>
    </div>
  )
}
