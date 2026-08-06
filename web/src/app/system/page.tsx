import type { Metadata } from "next"
import Link from "next/link"
import { connection } from "next/server"
import { CheckCircle2, CircleOff, RefreshCw, ShieldCheck } from "lucide-react"

import { ProviderStateCard } from "@/components/provider-state-card"
import { ProvenanceCard } from "@/components/provenance-card"
import { StatusBadge } from "@/components/status-badge"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Button } from "@/components/ui/button"
import { getHealth } from "@/lib/api"
import { humanize } from "@/lib/format"
import type { HealthResponse } from "@/lib/types"

export const metadata: Metadata = { title: "System health" }

export default async function SystemPage() {
  await connection()
  let health: HealthResponse | null = null
  try {
    health = await getHealth()
  } catch {
    health = null
  }

  const checks = health?.checks ?? []
  const failing = checks.filter((check) => check.status !== "pass")
  const providers = health?.providers ?? []
  const unchecked = providers.filter((provider) => provider.status === "configured_not_verified")

  return (
    <div className="page-enter page-stack">
      <header className="flex flex-col gap-5 border-b border-border pb-7 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <div className="flex flex-wrap items-center gap-3">
            <p className="eyebrow">System health</p>
            <StatusBadge status={health?.status ?? "unavailable"} />
          </div>
          <h1 className="mt-3 text-3xl font-medium tracking-[-0.035em] sm:text-4xl">
            What is set up, and what has been checked
          </h1>
          <p className="mt-3 max-w-2xl text-sm leading-6 text-muted-foreground">
            This page reports whether each capability is configured and whether that has been
            confirmed by a live check. It never shows configuration values, file paths, provider
            responses, or anything held in the credential vault.
          </p>
        </div>
        <Button asChild variant="outline" className="w-fit rounded-md">
          <Link href="/system">
            <RefreshCw aria-hidden="true" /> Refresh
          </Link>
        </Button>
      </header>

      {!health ? (
        <Alert className="rounded-lg border-red-200 bg-red-50 text-red-950 dark:border-red-500/35 dark:bg-red-500/12 dark:text-red-200">
          <CircleOff className="text-red-600 dark:text-red-300" aria-hidden="true" />
          <AlertTitle>The backend did not respond</AlertTitle>
          <AlertDescription>
            Nothing below can be confirmed right now. No part of the system is assumed healthy
            in the meantime.
          </AlertDescription>
        </Alert>
      ) : (
        <Summary failing={failing.length} unchecked={unchecked.length} total={checks.length} />
      )}

      <section aria-labelledby="core-checks">
        <div className="mb-3">
          <p className="eyebrow">Startup</p>
          <h2 id="core-checks" className="mt-1 text-xl font-medium tracking-[-0.02em]">
            Integrity checks
          </h2>
          <p className="mt-2 max-w-2xl text-sm leading-6 text-muted-foreground">
            Run once when the control plane starts. A failure here means the deployment itself is
            not sound, not that a single integration is.
          </p>
        </div>
        {checks.length ? (
          <ul className="divide-y divide-border overflow-hidden rounded-lg border border-border bg-card">
            {checks.map((check) => (
              <li
                key={check.name}
                className="flex flex-col gap-3 px-5 py-4 sm:flex-row sm:items-center sm:justify-between"
              >
                <div className="flex items-start gap-3">
                  {check.status === "pass" ? (
                    <CheckCircle2
                      className="mt-0.5 size-4 shrink-0 text-emerald-600 dark:text-emerald-400"
                      aria-hidden="true"
                    />
                  ) : (
                    <CircleOff
                      className="mt-0.5 size-4 shrink-0 text-amber-600 dark:text-amber-400"
                      aria-hidden="true"
                    />
                  )}
                  <div>
                    <p className="text-sm font-medium">{humanize(check.name)}</p>
                    {check.detail ? (
                      <p className="mt-1 text-xs leading-5 text-muted-foreground">{check.detail}</p>
                    ) : null}
                  </div>
                </div>
                <StatusBadge status={check.status} className="shrink-0" />
              </li>
            ))}
          </ul>
        ) : (
          <Unavailable copy="The backend did not report any startup checks." />
        )}
      </section>

      <section aria-labelledby="capabilities">
        <div className="mb-3">
          <p className="eyebrow">Capabilities</p>
          <h2 id="capabilities" className="mt-1 text-xl font-medium tracking-[-0.02em]">
            What the agent can use
          </h2>
          <p className="mt-2 max-w-2xl text-sm leading-6 text-muted-foreground">
            Each capability reports two separate things: whether it is set up, and whether a live
            check has confirmed it works. The second never follows from the first.
          </p>
        </div>
        {providers.length ? (
          <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
            {providers.map((provider) => (
              <ProviderStateCard key={provider.provider} provider={provider} evidenceScope="system" />
            ))}
          </div>
        ) : (
          <Unavailable copy="No capability state was reported. Nothing is assumed ready." />
        )}
      </section>

      <section aria-labelledby="provenance" className="grid items-stretch gap-6 xl:grid-cols-2">
        <h2 id="provenance" className="sr-only">
          Build provenance and frontend boundary
        </h2>
        <ProvenanceCard snapshot={health?.snapshot ?? null} />
        <div className="panel rounded-lg bg-rail p-6 text-white">
          <div className="flex items-center gap-2 text-sm font-medium">
            <ShieldCheck className="size-4 text-brand-300" aria-hidden="true" /> What this console
            never does
          </div>
          <div className="mt-6 grid gap-4 sm:grid-cols-2">
            <Boundary label="Data it receives" value="Sanitized records only" />
            <Boundary label="Browser storage" value="None used" />
            <Boundary label="Credentials" value="Never displayed" />
            <Boundary label="Provider results" value="Reported, never inferred" />
          </div>
          <p className="mt-6 border-t border-white/10 pt-4 text-xs leading-5 text-white/45">
            Configuration names and values, file paths, raw provider responses, and internal error
            detail are deliberately left out of every page in this console.
          </p>
        </div>
      </section>
    </div>
  )
}

function Summary({
  failing,
  unchecked,
  total,
}: {
  failing: number
  unchecked: number
  total: number
}) {
  if (failing === 0 && unchecked === 0) {
    return (
      <Alert className="rounded-lg border-emerald-300 bg-emerald-50 text-emerald-950 dark:border-emerald-500/35 dark:bg-emerald-500/12 dark:text-emerald-200">
        <CheckCircle2 className="text-emerald-600 dark:text-emerald-400" aria-hidden="true" />
        <AlertTitle>Everything is set up and checked</AlertTitle>
        <AlertDescription>
          All {total} startup checks passed and every capability has been confirmed by a live
          check.
        </AlertDescription>
      </Alert>
    )
  }
  return (
    <Alert className="rounded-lg border-border bg-card">
      <ShieldCheck className="text-muted-foreground" aria-hidden="true" />
      <AlertTitle>
        {failing > 0
          ? `${failing} of ${total} startup checks did not pass`
          : `All ${total} startup checks passed`}
      </AlertTitle>
      <AlertDescription>
        {unchecked > 0
          ? `${unchecked} ${unchecked === 1 ? "capability is" : "capabilities are"} set up but not confirmed by a live check. That is expected for capabilities that are only exercised when a run uses them.`
          : "Every capability that is set up has been confirmed by a live check."}
      </AlertDescription>
    </Alert>
  )
}

function Unavailable({ copy }: { copy: string }) {
  return (
    <div className="grid min-h-36 place-items-center rounded-lg border border-dashed border-border bg-card/50 p-6 text-center">
      <p className="max-w-md text-sm text-muted-foreground">{copy}</p>
    </div>
  )
}

function Boundary({ label, value }: { label: string; value: string }) {
  return (
    <div className="border-b border-white/10 pb-3">
      <p className="font-mono text-[11px] uppercase tracking-[0.13em] text-white/40">{label}</p>
      <p className="mt-1 text-sm text-white/85">{value}</p>
    </div>
  )
}
