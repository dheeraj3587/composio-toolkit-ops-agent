import type { Metadata } from "next"
import Link from "next/link"
import { ArrowLeft, LockKeyhole } from "lucide-react"

import { NewRunForm } from "@/components/new-run-form"
import { Button } from "@/components/ui/button"

export const metadata: Metadata = { title: "New operations plan" }

export default async function NewRunPage({
  searchParams,
}: {
  searchParams: Promise<{ app?: string | string[] }>
}) {
  const rawApp = (await searchParams).app
  const defaultAppName = typeof rawApp === "string" && /^[\p{L}\p{N} .+&'()-]{1,120}$/u.test(rawApp)
    ? rawApp
    : ""

  return (
    <div className="page-enter page-stack mx-auto max-w-7xl">
      <Button asChild variant="ghost" size="sm" className="-ml-2 font-mono text-[10px] uppercase tracking-[0.1em]">
        <Link href="/"><ArrowLeft aria-hidden="true" /> Overview</Link>
      </Button>
      <header className="grid gap-6 border-b border-border pb-8 lg:grid-cols-2 lg:items-end">
        <div>
          <p className="eyebrow">New operations run</p>
          <h1 className="mt-3 text-3xl font-semibold tracking-[-0.035em] sm:text-4xl">Start with explicit boundaries</h1>
          <p className="mt-3 max-w-2xl text-sm leading-6 text-muted-foreground">
            Create a durable workflow from verified company facts. Plan-only mode remains offline-safe; execute mode requests only backend-approved provider actions.
          </p>
        </div>
        <div className="flex gap-3 rounded-md border border-brand-200 bg-brand-50/70 p-4 text-xs leading-5 text-brand-950">
          <LockKeyhole className="mt-0.5 size-4 shrink-0 text-brand-600" aria-hidden="true" />
          <p>Vault material stays reference-only. Optional app sign-in values use a secure owner flow and are never persisted in run state or displayed back to the operator.</p>
        </div>
      </header>
      <NewRunForm defaultAppName={defaultAppName} />
    </div>
  )
}
