import Link from "next/link"
import { ArrowRight, Inbox } from "lucide-react"

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
    <div className="grid min-h-64 place-items-center rounded-lg border border-dashed border-border bg-card/40 px-6 py-12 text-center">
      <div className="max-w-md">
        <span className="mx-auto mb-5 grid size-10 place-items-center rounded-lg bg-secondary">
          <Inbox className="size-5 text-muted-foreground" aria-hidden="true" />
        </span>
        <h3 className="text-lg font-medium">{title}</h3>
        <p className="mt-2 text-sm leading-6 text-muted-foreground">{description}</p>
        {action ? (
          <Button asChild className="mt-6 rounded-md">
            <Link href="/runs/new">
              Start an integration <ArrowRight aria-hidden="true" />
            </Link>
          </Button>
        ) : null}
      </div>
    </div>
  )
}
