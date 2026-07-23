import type { Metadata } from "next"
import Link from "next/link"
import { connection } from "next/server"
import { Activity, CheckCircle2, CircleOff, RefreshCw, ShieldCheck } from "lucide-react"

import { ProviderStateCard } from "@/components/provider-state-card"
import { ProvenanceCard } from "@/components/provenance-card"
import { StatusBadge } from "@/components/status-badge"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Button } from "@/components/ui/button"
import { getHealth } from "@/lib/api"
import { humanize } from "@/lib/format"
import type { HealthResponse } from "@/lib/types"

export const metadata: Metadata = { title: "System status" }

export default async function SystemPage() {
  await connection()
  let health: HealthResponse | null = null
  try {
    health = await getHealth()
  } catch {
    health = null
  }

  return (
    <div className="page-enter page-stack">
      <header className="flex flex-col gap-5 border-b border-border pb-7 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <div className="flex flex-wrap items-center gap-3"><p className="eyebrow">System status</p><StatusBadge status={health?.status ?? "unavailable"} /></div>
          <h1 className="mt-3 text-3xl font-semibold tracking-[-0.035em] sm:text-4xl">Runtime and security posture</h1>
          <p className="mt-3 max-w-2xl text-sm leading-6 text-muted-foreground">Configuration presence and verification state only. Environment values, database locations, provider payloads, and vault contents are never returned.</p>
        </div>
        <Button asChild variant="outline" className="w-fit rounded-md"><Link href="/system"><RefreshCw aria-hidden="true" /> Refresh state</Link></Button>
      </header>

      {!health ? (
        <Alert className="rounded-md border-red-200 bg-red-50 text-red-950">
          <CircleOff className="text-red-600" aria-hidden="true" />
          <AlertTitle>Health endpoint unavailable</AlertTitle>
          <AlertDescription>The control plane cannot verify runtime posture. No healthy state is inferred.</AlertDescription>
        </Alert>
      ) : null}

      <section aria-labelledby="core-checks">
        <div className="mb-3"><p className="eyebrow">Core controls</p><h2 id="core-checks" className="mt-1 text-xl font-semibold">Integrity checks</h2></div>
        {health?.checks.length ? (
          <div className="panel divide-y divide-border rounded-md">
            {health.checks.map((check) => (
              <div key={check.name} className="flex flex-col gap-3 px-5 py-4 sm:flex-row sm:items-center sm:justify-between">
                <div className="flex items-start gap-3">
                  {check.status === "pass" ? <CheckCircle2 className="mt-0.5 size-4 text-emerald-600" aria-hidden="true" /> : <CircleOff className="mt-0.5 size-4 text-amber-600" aria-hidden="true" />}
                  <div><p className="text-sm font-medium">{humanize(check.name)}</p>{check.detail ? <p className="mt-1 text-xs leading-5 text-muted-foreground">{check.detail}</p> : null}</div>
                </div>
                <StatusBadge status={check.status} />
              </div>
            ))}
          </div>
        ) : (
          <Unavailable copy="The backend did not report core integrity checks." />
        )}
      </section>

      <section aria-labelledby="provider-status">
        <div className="mb-3"><p className="eyebrow">Configuration and policy</p><h2 id="provider-status" className="mt-1 text-xl font-semibold">Runtime configuration and policy</h2></div>
        {health?.providers?.length ? (
          <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
            {health.providers.map((provider) => (
              <ProviderStateCard key={provider.provider} provider={provider} evidenceScope="system" />
            ))}
          </div>
        ) : (
          <Unavailable copy="Provider configuration state was not reported. No adapter is assumed ready." />
        )}
      </section>

      <section className="grid items-stretch gap-6 xl:grid-cols-2">
        <ProvenanceCard snapshot={health?.snapshot ?? null} />
        <div className="panel rounded-md bg-rail p-6 text-white">
          <div className="flex items-center gap-2 text-sm font-semibold"><ShieldCheck className="size-4 text-brand-300" aria-hidden="true" /> Frontend security contract</div>
          <div className="mt-6 grid gap-4 sm:grid-cols-2">
            <Boundary label="Data transfer" value="Sanitized DTOs" />
            <Boundary label="Browser storage" value="Not used" />
            <Boundary label="Credential controls" value="No reveal surface" />
            <Boundary label="Provider outcomes" value="Backend-reported only" />
          </div>
          <p className="mt-6 border-t border-white/10 pt-4 text-xs leading-5 text-white/45">This page intentionally omits environment variable names and values, filesystem paths, raw provider responses, and internal exception details.</p>
        </div>
      </section>
    </div>
  )
}

function Unavailable({ copy }: { copy: string }) {
  return <div className="grid min-h-36 place-items-center rounded-md border border-dashed border-border bg-card/50 p-6 text-center"><div><Activity className="mx-auto size-5 text-muted-foreground" aria-hidden="true" /><p className="mt-3 text-sm text-muted-foreground">{copy}</p></div></div>
}

function Boundary({ label, value }: { label: string; value: string }) {
  return <div className="border-b border-white/10 pb-3"><p className="font-mono text-[9px] uppercase tracking-[0.13em] text-white/40">{label}</p><p className="mt-1 text-sm text-white/85">{value}</p></div>
}
