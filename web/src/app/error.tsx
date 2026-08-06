"use client"

import { AlertTriangle, RotateCcw } from "lucide-react"

import { Button } from "@/components/ui/button"

export default function ErrorPage({
  unstable_retry,
}: {
  error: Error & { digest?: string }
  unstable_retry: () => void
}) {
  return (
    <div className="mx-auto grid min-h-[60vh] max-w-xl place-items-center text-center">
      <div>
        <span className="mx-auto grid size-11 place-items-center rounded-lg bg-destructive/10">
          <AlertTriangle className="size-5 text-destructive" aria-hidden="true" />
        </span>
        <h1 className="mt-6 text-2xl font-medium">This page could not be loaded</h1>
        <p className="mt-3 text-sm leading-6 text-muted-foreground">
          The detail is deliberately not shown here, because backend errors can carry
          sensitive context. Reloading is safe and repeats no action.
        </p>
        <Button onClick={() => unstable_retry()} className="mt-7 rounded-md">
          <RotateCcw aria-hidden="true" /> Try again
        </Button>
      </div>
    </div>
  )
}
