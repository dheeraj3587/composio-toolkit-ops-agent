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
  const [healthResult, signupResult] = await Promise.allSettled([getHealth(), getSignupReadiness()])
  let providerStates: ProviderStatus[] = healthResult.status === "fulfilled" ? healthResult.value.providers ?? [] : []
  if (signupResult.status === "fulfilled") {
    providerStates = [
      ...providerStates.filter((provider) => provider.provider !== "gmail"),
      signupResult.value,
    ]
  }

  return (
    <div className="page-enter page-stack mx-auto max-w-4xl">
      <Button asChild variant="ghost" size="sm" className="-ml-2 font-mono text-[10px] uppercase tracking-[0.1em]">
        <Link href="/"><ArrowLeft aria-hidden="true" /> Overview</Link>
      </Button>
      <header className="border-b border-border pb-7">
        <p className="eyebrow">New integration</p>
        <h1 className="mt-3 text-3xl tracking-[-0.035em] sm:text-4xl">Configure a new integration</h1>
        <p className="mt-3 max-w-2xl text-sm leading-6 text-muted-foreground">
          Select the app and account path, then provide only the operating context the run needs.
        </p>
        <div className="mt-5 flex max-w-2xl items-start gap-2.5 border-l border-brand-400/60 pl-3 text-xs leading-5 text-muted-foreground">
          <LockKeyhole className="mt-0.5 size-3.5 shrink-0 text-brand-300" aria-hidden="true" />
          <p>Sign-in values cross a one-time secure boundary and are never displayed back in the run.</p>
        </div>
      </header>
      <NewRunForm defaultAppName={defaultAppName} providerStates={providerStates} />
    </div>
  )
}
