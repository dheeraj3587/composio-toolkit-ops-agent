import type { Metadata } from "next"
import Link from "next/link"
import { ArrowLeft } from "lucide-react"

import { NewRunForm } from "@/components/new-run-form"
import { Button } from "@/components/ui/button"

export const metadata: Metadata = { title: "New dry run" }

export default function NewRunPage() {
  return (
    <div className="page-enter mx-auto max-w-6xl space-y-8">
      <Button asChild variant="ghost" className="-ml-3 rounded-none font-mono text-xs uppercase">
        <Link href="/"><ArrowLeft aria-hidden="true" /> Back to ledger</Link>
      </Button>
      <header className="grid gap-6 lg:grid-cols-[1fr_0.55fr] lg:items-end">
        <div><p className="eyebrow">New ledger entry / Dry-run</p><h1 className="mt-4 font-heading text-5xl leading-[0.95] tracking-[-0.04em] sm:text-7xl">Start with boundaries.</h1></div>
        <p className="border-l border-ink/25 pl-5 text-sm leading-6 text-muted-foreground">Define verified company facts and opaque references. This form never asks for a password, API key, token, cookie, or client secret.</p>
      </header>
      <div className="editorial-rule" />
      <NewRunForm />
    </div>
  )
}
