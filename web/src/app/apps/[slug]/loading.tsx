import { Skeleton } from "@/components/ui/skeleton"

export default function AppResearchLoading() {
  return (
    <div className="space-y-7" aria-label="Loading app research" aria-busy="true">
      <Skeleton className="h-8 w-28 rounded-md" />
      <div className="space-y-3 border-b border-border pb-7"><Skeleton className="h-4 w-40 rounded-md" /><Skeleton className="h-11 w-72 rounded-md" /></div>
      <div className="grid gap-px bg-border sm:grid-cols-2 xl:grid-cols-4">{[0, 1, 2, 3].map((item) => <Skeleton key={item} className="h-28 rounded-none" />)}</div>
      <div className="grid gap-5 xl:grid-cols-[1.3fr_0.7fr]"><Skeleton className="h-96 rounded-md" /><Skeleton className="h-96 rounded-md" /></div>
    </div>
  )
}
