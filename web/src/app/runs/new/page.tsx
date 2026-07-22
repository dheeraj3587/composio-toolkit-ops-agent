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
    <div className="page-enter mx-auto max-w-6xl space-y-7">
      <Button asChild variant="ghost" size="sm" className="-ml-2 font-mono text-[10px] uppercase tracking-[0.1em]">
        <Link href="/"><ArrowLeft aria-hidden="true" /> Overview</Link>
      </Button>
      <header className="grid gap-5 border-b border-border pb-7 lg:grid-cols-[1fr_0.65fr] lg:items-end">
        <div>
          <p className="eyebrow">New side-effect-free plan</p>
          <h1 className="mt-3 text-3xl font-semibold tracking-[-0.035em] sm:text-4xl">Start with explicit boundaries</h1>
          <p className="mt-3 max-w-2xl text-sm leading-6 text-muted-foreground">
            Create a durable dry-run workflow from verified company facts. Creation itself performs no browser, email, or provider side effect.
          </p>
        </div>
        <div className="flex gap-3 rounded-md border border-violet-200 bg-violet-50/70 p-4 text-xs leading-5 text-violet-950">
          <LockKeyhole className="mt-0.5 size-4 shrink-0 text-violet-600" aria-hidden="true" />
          <p>This interface accepts one profile vault reference. It never asks for passwords, tokens, API keys, cookies, or client secrets.</p>
        </div>
      </header>
      <NewRunForm defaultAppName={defaultAppName} />
    </div>
  )
}
