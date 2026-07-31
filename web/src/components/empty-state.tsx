import Link from "next/link"
import { ArrowRight, DatabaseZap } from "lucide-react"

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
    <div className="grid min-h-56 place-items-center rounded-lg border border-dashed border-border bg-card/55 px-6 py-10 text-center">
      <div className="max-w-md">
        <DatabaseZap className="mx-auto size-6 text-muted-foreground" aria-hidden="true" />
        <h3 className="mt-4 text-xl font-medium">{title}</h3>
        <p className="mt-2 text-sm leading-6 text-muted-foreground">{description}</p>
        {action ? (
          <Button asChild className="mt-5">
            <Link href="/runs/new">New integration <ArrowRight aria-hidden="true" /></Link>
          </Button>
        ) : null}
      </div>
    </div>
  )
}
