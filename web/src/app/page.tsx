import Link from "next/link"
import { connection } from "next/server"
import {
  ArrowRight,
  CheckCircle2,
  CircleOff,
  Database,
  RadioTower,
  ShieldCheck,
} from "lucide-react"

import { EmptyState } from "@/components/empty-state"
import { ProvenanceCard } from "@/components/provenance-card"
import { RunTable } from "@/components/run-table"
import { StatusBadge } from "@/components/status-badge"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent } from "@/components/ui/card"
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

  return (
    <div className="page-enter space-y-10">
      <section className="grid gap-8 lg:grid-cols-[minmax(0,1.35fr)_minmax(280px,0.65fr)] lg:items-end">
        <div>
          <div className="flex flex-wrap items-center gap-3">
            <p className="eyebrow">Private P2 / Control plane</p>
            <StatusBadge status={health?.status ?? "unavailable"} />
          </div>
          <h1 className="mt-5 max-w-4xl font-heading text-5xl leading-[0.92] tracking-[-0.045em] sm:text-7xl lg:text-[6.6rem]">
            Access work,
            <br />held to account.
          </h1>
          <p className="mt-6 max-w-2xl text-base leading-7 text-muted-foreground sm:text-lg">
            A sanitized operations ledger for research, access routing, human handoffs, and reference-only integrator output.
          </p>
        </div>
        <div className="border-l border-ink/25 pl-6">
          <p className="font-heading text-2xl leading-tight">The interface reports backend truth. It does not simulate provider progress.</p>
          <Button asChild size="lg" className="mt-6 h-11 rounded-none bg-rust px-5 text-paper hover:bg-rust/90">
            <Link href="/runs/new">Compose dry run <ArrowRight aria-hidden="true" /></Link>
          </Button>
        </div>
      </section>

      <div className="editorial-rule" />

      {unavailable ? (
        <Alert className="rounded-none border-rust/45 bg-rust/5">
          <RadioTower className="text-rust" aria-hidden="true" />
          <AlertTitle>Backend state is partially unavailable</AlertTitle>
          <AlertDescription>
            The dashboard remains read-only and honest. Start the operations API at the server-only OPS_API_URL to populate health and runs.
          </AlertDescription>
        </Alert>
      ) : null}

      <section aria-labelledby="ledger-pulse">
        <div className="mb-4 flex items-end justify-between gap-4">
          <div><p className="eyebrow">Now / Backend reported</p><h2 id="ledger-pulse" className="mt-2 font-heading text-3xl">Ledger pulse</h2></div>
          <Badge variant="outline" className="rounded-none font-mono text-[9px] uppercase tracking-[0.12em]">UTC timestamps</Badge>
        </div>
        <div className="grid gap-px overflow-hidden border border-ink/25 bg-ink/20 sm:grid-cols-2 xl:grid-cols-4">
          <Metric icon={Database} label="Run records" value={runs ? String(runs.total) : "—"} note="Persisted by backend" />
          <Metric icon={RadioTower} label="System state" value={health ? humanize(health.status) : "Unavailable"} note={health ? `API ${health.version}` : "No response"} />
          <Metric icon={ShieldCheck} label="Checks passing" value={passedChecks == null ? "—" : `${passedChecks}/${health?.checks.length ?? 0}`} note="Backend security gate" />
          <Metric icon={externalActionCount === 0 ? CircleOff : CheckCircle2} label="Visible external runs" value={externalActionCount == null ? "—" : String(externalActionCount)} note="Current result page" />
        </div>
      </section>

      <section className="grid gap-6 xl:grid-cols-[0.82fr_1.18fr]">
        <ProvenanceCard snapshot={health?.snapshot ?? null} />
        <div className="grid gap-px overflow-hidden border border-ink/25 bg-ink/20 sm:grid-cols-3">
          <ControlCard index="01" title="Research" status={health?.phase} copy="P1 evidence and operational enrichment remain separate." />
          <ControlCard index="02" title="Security" status={health ? "backend_reported" : null} copy="Vault references and sanitized events only; no reveal control." />
          <ControlCard index="03" title="External work" status="phase_unavailable" copy="Browser and email surfaces wait for explicit backend phase state." />
        </div>
      </section>

      <section aria-labelledby="recent-runs">
        <div className="mb-4 flex items-end justify-between gap-4">
          <div><p className="eyebrow">Ledger / Most recent</p><h2 id="recent-runs" className="mt-2 font-heading text-3xl">Run register</h2></div>
          <Button asChild variant="ghost" className="rounded-none font-mono text-xs uppercase"><Link href="/runs/new">New entry <ArrowRight aria-hidden="true" /></Link></Button>
        </div>
        {runs ? <RunTable runs={runs.items} /> : <EmptyState title="Run register unavailable" description="The backend could not return the run list. No placeholder records are shown." />}
      </section>
    </div>
  )
}

function Metric({ icon: Icon, label, value, note }: { icon: typeof Database; label: string; value: string; note: string }) {
  return (
    <Card className="min-h-40 rounded-none bg-card/90 py-0 ring-0">
      <CardContent className="flex h-full flex-col justify-between px-5 py-5">
        <div className="flex items-center justify-between"><span className="data-label">{label}</span><Icon className="size-4 text-rust" aria-hidden="true" /></div>
        <div><strong className="font-heading text-4xl font-normal">{value}</strong><p className="mt-1 font-mono text-[9px] uppercase tracking-[0.1em] text-muted-foreground">{note}</p></div>
      </CardContent>
    </Card>
  )
}

function ControlCard({ index, title, status, copy }: { index: string; title: string; status?: string | null; copy: string }) {
  return (
    <article className="flex min-h-64 flex-col justify-between bg-card/90 p-5">
      <div className="flex items-start justify-between"><span className="font-mono text-xs text-rust">{index}</span><StatusBadge status={status ?? "unavailable"} /></div>
      <div><h3 className="font-heading text-3xl">{title}</h3><p className="mt-2 text-xs leading-5 text-muted-foreground">{copy}</p></div>
    </article>
  )
}
