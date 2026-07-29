import type { Metadata } from "next"
import Link from "next/link"
import { ArrowLeft, LockKeyhole } from "lucide-react"

import { NewRunForm } from "@/components/new-run-form"
import { Button } from "@/components/ui/button"
import { getHealth, getSignupReadiness } from "@/lib/api"
import type { ProviderStatus } from "@/lib/types"

export const metadata: Metadata = { title: "Start an integration" }

export default async function NewRunPage({
  searchParams,
}: {
  searchParams: Promise<{ app?: string | string[] }>
}) {
  const rawApp = (await searchParams).app
  const defaultAppName = typeof rawApp === "string" && /^[\p{L}\p{N} .+&'()-]{1,120}$/u.test(rawApp)
    ? rawApp
    : ""
  const [healthResult, signupResult] = await Promise.allSettled([
    getHealth(),
    getSignupReadiness(),
  ])
  let providerStates: ProviderStatus[] =
    healthResult.status === "fulfilled" ? healthResult.value.providers ?? [] : []
  if (signupResult.status === "fulfilled") {
    providerStates = [
      ...providerStates.filter((provider) => provider.provider !== "gmail"),
      signupResult.value,
    ]
  }

  return (
    <div className="page-enter page-stack mx-auto max-w-6xl">
      <Button asChild variant="ghost" size="sm" className="-ml-2 font-mono text-[10px] uppercase tracking-[0.1em]">
        <Link href="/"><ArrowLeft aria-hidden="true" /> Overview</Link>
      </Button>
      <header className="grid gap-6 border-b border-border pb-8 lg:grid-cols-[1fr_0.8fr] lg:items-end">
        <div>
          <p className="eyebrow">New integration</p>
          <h1 className="mt-3 text-3xl font-semibold tracking-[-0.035em] sm:text-4xl">Let the agent set it up</h1>
          <p className="mt-3 max-w-2xl text-sm leading-6 text-muted-foreground">
            Choose an app, tell us whether an account exists, and follow the run live. The agent handles the routine browser and email steps.
          </p>
        </div>
        <div className="flex gap-3 rounded-xl border border-brand-200 bg-brand-50/70 p-4 text-xs leading-5 text-brand-950">
          <LockKeyhole className="mt-0.5 size-4 shrink-0 text-brand-600" aria-hidden="true" />
          <p>Vault destinations are created automatically. Sign-in values are passed through a one-time secure boundary and are never displayed back.</p>
        </div>
      </header>
      <NewRunForm defaultAppName={defaultAppName} providerStates={providerStates} />
    </div>
  )
}
