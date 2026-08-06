import Link from "next/link"
import { ArrowLeft, SearchX } from "lucide-react"

import { Button } from "@/components/ui/button"

export default function NotFound() {
  return (
    <div className="mx-auto grid min-h-[60vh] max-w-xl place-items-center text-center">
      <div>
        <span className="mx-auto grid size-11 place-items-center rounded-lg bg-secondary">
          <SearchX className="size-5 text-muted-foreground" aria-hidden="true" />
        </span>
        <h1 className="mt-6 text-2xl font-medium">There is nothing here</h1>
        <p className="mt-3 text-sm leading-6 text-muted-foreground">
          Either this address does not exist, or the backend has no matching run. Nothing
          was substituted in its place.
        </p>
        <Button asChild className="mt-7 rounded-md">
          <Link href="/">
            <ArrowLeft aria-hidden="true" /> Back to overview
          </Link>
        </Button>
      </div>
    </div>
  )
}
