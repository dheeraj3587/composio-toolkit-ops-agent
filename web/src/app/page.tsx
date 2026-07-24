import Link from "next/link"
import { connection } from "next/server"
import {
  Activity,
  ArrowRight,
  Boxes,
  CheckCircle2,
  CircleOff,
  Database,
  LockKeyhole,
  RadioTower,
  ShieldCheck,
} from "lucide-react"

import { AppSearch } from "@/components/app-search"
import { EmptyState } from "@/components/empty-state"
import { ProvenanceCard } from "@/components/provenance-card"
import { RunTable } from "@/components/run-table"
import { StatusBadge } from "@/components/status-badge"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { getHealth, listRuns } from "@/lib/api"
import { humanize } from "@/lib/format"
import type { HealthResponse, RunListResponse } from "@/lib/types"

export default async function DashboardPage() {
  await connection()
  const [healthResult, runsResult] = await Promise.allSettled([getHealth(), listRuns()])
  const health: HealthResponse | null = healthResult.status === "fulfilled" ? healthResult.value : null
  const runs: RunListResponse | null = runsResult.status === "fulfilled" ? runsResult.value : null
  const unavailable = health === null || runs === null
  const externalActionCount = runs?.items.filter((run) => run.external_actions).length ?? null
  const passedChecks = health?.checks.filter((check) => check.status === "pass").length ?? null
  const waitingRuns = runs?.items.filter((run) =>
    ["waiting_for_hitl", "outreach_sent", "waiting_for_reply", "configuration_required"].includes(run.status),
  ).length ?? null

  return (
    <div className="page-enter page-stack">
      <header className="flex flex-col gap-5 border-b border-border pb-7 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <div className="flex flex-wrap items-center gap-3">
            <p className="eyebrow">Operations overview</p>
            <StatusBadge status={health?.status ?? "unavailable"} />
          </div>
          <h1 className="mt-3 text-3xl font-semibold tracking-[-0.035em] sm:text-4xl">Toolkit access control plane</h1>
          <p className="mt-3 max-w-2xl text-sm leading-6 text-muted-foreground">
            Coordinate verified research, deterministic access routing, human gates, and reference-only integrator output.
          </p>
        </div>
        <Button asChild className="h-10 w-fit rounded-md bg-primary px-4 text-primary-foreground">
          <Link href="/runs/new">Create operations plan <ArrowRight aria-hidden="true" /></Link>
        </Button>
      </header>

      {unavailable ? (
        <Alert className="rounded-md border-amber-300 bg-amber-50 text-amber-950">
          <RadioTower className="text-amber-700" aria-hidden="true" />
          <AlertTitle>Backend state is partially unavailable</AlertTitle>
          <AlertDescription>
            No run or health state is inferred while the backend is unavailable. Start the operations API configured by the server-only OPS_API_URL.
          </AlertDescription>
        </Alert>
      ) : null}

      <section aria-labelledby="system-pulse">
        <div className="mb-3 flex items-center justify-between gap-4">
          <h2 id="system-pulse" className="text-sm font-semibold">System pulse</h2>
          <Badge variant="outline" className="rounded-md font-mono text-[9px] uppercase tracking-[0.12em]">Backend reported</Badge>
        </div>
        <div className="grid overflow-hidden rounded-md border border-border bg-border sm:grid-cols-2 xl:grid-cols-4">
          <Metric icon={Database} label="Run records" value={runs ? String(runs.total) : "—"} note="Persisted ledger" />
          <Metric icon={Activity} label="System" value={health ? humanize(health.status) : "Unavailable"} note={health ? `API ${health.version}` : "No response"} />
          <Metric icon={ShieldCheck} label="Checks passing" value={passedChecks == null ? "—" : `${passedChecks}/${health?.checks.length ?? 0}`} note="Security and integrity" />
          <Metric icon={waitingRuns === 0 ? CheckCircle2 : CircleOff} label="Attention queue" value={waitingRuns == null ? "—" : String(waitingRuns)} note={externalActionCount == null ? "External state unavailable" : `${externalActionCount} with external actions`} />
        </div>
      </section>

      <AppSearch />

      <section className="grid items-stretch gap-6 xl:grid-cols-2">
        <ProvenanceCard snapshot={health?.snapshot ?? null} />
        <div className="panel grid sm:grid-cols-3">
          <PostureCard icon={Boxes} title="Research" status={health ? `phase_${health.phase}` : "unavailable"} copy="P1 evidence remains immutable; enrichment is stored separately." />
          <PostureCard icon={LockKeyhole} title="Security" status={health ? "backend_reported" : "unavailable"} copy="Credential values stay behind exact vault references." />
          <PostureCard icon={RadioTower} title="Providers" status={providerSummary(health)} copy="Provider availability is configuration-derived, never inferred from the UI." />
        </div>
      </section>

      <section aria-labelledby="recent-runs">
        <div className="mb-3 flex items-end justify-between gap-4">
          <div>
            <p className="eyebrow">Durable ledger</p>
            <h2 id="recent-runs" className="mt-1 text-xl font-semibold tracking-[-0.02em]">Recent runs</h2>
          </div>
          <Button asChild variant="ghost" size="sm" className="font-mono text-[10px] uppercase tracking-[0.1em]">
            <Link href="/runs/new">New run <ArrowRight aria-hidden="true" /></Link>
          </Button>
        </div>
        {runs ? <RunTable runs={runs.items} /> : <EmptyState title="Run register unavailable" description="The backend could not return the run list. No run data is inferred or fabricated." />}
      </section>
    </div>
  )
}

function providerSummary(health: HealthResponse | null): string {
  if (!health) return "unavailable"
  if (!health.providers?.length) return "not_reported"
  if (health.providers.some((provider) => provider.status === "configuration_required")) return "configuration_required"
  if (health.providers.every((provider) => ["ready", "configured"].includes(provider.status))) return "configured"
  return "partial"
}

function Metric({ icon: Icon, label, value, note }: { icon: typeof Database; label: string; value: string; note: string }) {
  return (
    <article className="min-h-32 bg-card p-5 [&:not(:last-child)]:border-b [&:not(:last-child)]:border-border sm:[&:not(:last-child)]:border-b-0 sm:[&:not(:last-child)]:border-r">
      <div className="flex items-center justify-between">
        <span className="data-label">{label}</span>
        <Icon className="size-4 text-brand-500" aria-hidden="true" />
      </div>
      <p className="metric-value mt-6">{value}</p>
      <p className="mt-1 text-xs text-muted-foreground">{note}</p>
    </article>
  )
}

function PostureCard({ icon: Icon, title, status, copy }: { icon: typeof Boxes; title: string; status: string; copy: string }) {
  return (
    <article className="flex min-h-56 flex-col justify-between border-b border-border p-5 last:border-0 sm:border-b-0 sm:border-r sm:last:border-r-0">
      <div className="flex items-start justify-between gap-3">
        <span className="grid size-8 place-items-center rounded-md bg-secondary"><Icon className="size-4" aria-hidden="true" /></span>
        <StatusBadge status={status} />
      </div>
      <div>
        <h3 className="text-base font-semibold">{title}</h3>
        <p className="mt-2 text-xs leading-5 text-muted-foreground">{copy}</p>
      </div>
    </article>
  )
}
