import Link from "next/link"
import { ArrowUpRight, DatabaseZap } from "lucide-react"

import { Button } from "@/components/ui/button"

export function EmptyState({
  title,
  description,
  action = false,
}: {
  title: string
  description: string
  action?: boolean
}) {
  return (
    <div className="grid min-h-64 place-items-center border border-dashed border-ink/30 bg-card/40 px-6 py-12 text-center">
      <div className="max-w-md">
        <DatabaseZap className="mx-auto mb-5 size-7 text-rust" aria-hidden="true" />
        <h3 className="font-heading text-2xl">{title}</h3>
        <p className="mt-2 text-sm leading-6 text-muted-foreground">{description}</p>
        {action ? (
          <Button asChild className="mt-6 rounded-none bg-ink text-paper">
            <Link href="/runs/new">
              Compose first run <ArrowUpRight aria-hidden="true" />
            </Link>
          </Button>
        ) : null}
      </div>
    </div>
  )
}
