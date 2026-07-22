"use client"

import { AlertTriangle, RotateCcw } from "lucide-react"

import { Button } from "@/components/ui/button"

export default function ErrorPage({ unstable_retry }: { error: Error & { digest?: string }; unstable_retry: () => void }) {
  return (
    <div className="mx-auto grid min-h-[60vh] max-w-2xl place-items-center text-center">
      <div><AlertTriangle className="mx-auto size-8 text-rust" aria-hidden="true" /><p className="eyebrow mt-6">Interface / Error boundary</p><h1 className="mt-3 font-heading text-5xl">The view lost its place.</h1><p className="mt-4 text-sm leading-6 text-muted-foreground">No error detail is rendered because backend responses may contain sensitive context. Retry the server-rendered view.</p><Button onClick={() => unstable_retry()} className="mt-7 rounded-none bg-ink text-paper"><RotateCcw aria-hidden="true" /> Retry view</Button></div>
    </div>
  )
}
