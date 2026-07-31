"use client"

import { AlertTriangle, RotateCcw } from "lucide-react"

import { Button } from "@/components/ui/button"

export default function ErrorPage({ unstable_retry }: { error: Error & { digest?: string }; unstable_retry: () => void }) {
  return (
    <div className="mx-auto grid min-h-[60vh] max-w-2xl place-items-center text-center">
      <div>
        <AlertTriangle className="mx-auto size-7 text-amber-300" aria-hidden="true" />
        <p className="eyebrow mt-5">Interface error</p>
        <h1 className="mt-3 text-3xl">This view could not be loaded.</h1>
        <p className="mt-3 text-sm leading-6 text-muted-foreground">Sensitive error details are withheld. Retry the server-rendered view.</p>
        <Button onClick={() => unstable_retry()} className="mt-6"><RotateCcw aria-hidden="true" /> Retry view</Button>
      </div>
    </div>
  )
}
