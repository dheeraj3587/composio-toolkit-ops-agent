import Link from "next/link"
import { ArrowLeft, SearchX } from "lucide-react"

import { Button } from "@/components/ui/button"

export default function NotFound() {
  return (
    <div className="mx-auto grid min-h-[60vh] max-w-2xl place-items-center text-center">
      <div>
        <SearchX className="mx-auto size-7 text-muted-foreground" aria-hidden="true" />
        <p className="eyebrow mt-5">404 · Not found</p>
        <h1 className="mt-3 text-3xl">Nothing is recorded here.</h1>
        <p className="mt-3 text-sm leading-6 text-muted-foreground">The route does not exist or the backend has no matching run. No placeholder record was substituted.</p>
        <Button asChild className="mt-6"><Link href="/"><ArrowLeft aria-hidden="true" /> Return to overview</Link></Button>
      </div>
    </div>
  )
}
