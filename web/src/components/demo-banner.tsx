import { FlaskConical } from "lucide-react"

export function DemoBanner({ enabled }: { enabled: boolean }) {
  if (!enabled) return null

  return (
    <div
      className="fixed inset-x-0 top-0 z-[70] flex h-8 items-center justify-center gap-2 border-b border-brand-300 bg-brand-100 px-4 font-mono text-[10px] font-semibold uppercase tracking-[0.14em] text-brand-950"
      role="status"
    >
      <FlaskConical className="size-3.5" aria-hidden="true" />
      Demo mode · fixture-backed states are labeled and never imply live provider execution
    </div>
  )
}
