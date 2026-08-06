import Link from "next/link"
import { connection } from "next/server"
import { Activity, ArrowRight, CheckCircle2, Database, HandHelping, RadioTower, ShieldCheck } from "lucide-react"

import { AppSearch } from "@/components/app-search"
import { EmptyState } from "@/components/empty-state"
import { RunTable } from "@/components/run-table"
import { StatusBadge } from "@/components/status-badge"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Button } from "@/components/ui/button"
import { getHealth, listRuns } from "@/lib/api"
import { humanize } from "@/lib/format"
import type { HealthResponse, RunListResponse, RunSummary } from "@/lib/types"

// Runs in one of these statuses are stopped and will not move again until a
// person does something. They are the only thing on this page that is a task.
const NEEDS_YOU = new Set([
  "waiting_for_hitl",
  "configuration_required",
  "connection_required",
])

export default async function DashboardPage() {
  await connection()
  const [healthResult, runsResult] = await Promise.allSettled([getHealth(), listRuns()])
  const health: HealthResponse | null = healthResult.status === "fulfilled" ? healthResult.value : null
  const runs: RunListResponse | null = runsResult.status === "fulfilled" ? runsResult.value : null
  const unavailable = health === null || runs === null

  const waiting = runs?.items.filter((run) => NEEDS_YOU.has(run.status)) ?? []
  const active = runs?.items.filter((run) => run.external_actions).length ?? null
  const passedChecks = health?.checks.filter((check) => check.status === "pass").length ?? null
  const totalChecks = health?.checks.length ?? 0

  return (
    <div className="page-enter page-stack">
      <header className="flex flex-col gap-5 border-b border-border pb-7 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <div className="flex flex-wrap items-center gap-3">
            <p className="eyebrow">Overview</p>
            <StatusBadge status={health?.status ?? "unavailable"} />
          </div>
          <h1 className="mt-3 text-3xl font-medium tracking-[-0.035em] sm:text-4xl">
            Set up apps without the busywork
          </h1>
          <p className="mt-3 max-w-2xl text-sm leading-6 text-muted-foreground">
            Start an integration, watch the agent work in real time, and step in only when a
            website needs you.
          </p>
        </div>
        <Button asChild size="lg" className="h-11 w-fit rounded-md px-5">
          <Link href="/runs/new">
            Start an integration <ArrowRight aria-hidden="true" />
          </Link>
        </Button>
      </header>

      {unavailable ? (
        <Alert className="rounded-lg border-amber-300 bg-amber-50 text-amber-950 dark:border-amber-500/35 dark:bg-amber-500/12 dark:text-amber-200">
          <RadioTower className="text-amber-700 dark:text-amber-300" aria-hidden="true" />
          <AlertTitle>Some backend state could not be loaded</AlertTitle>
          <AlertDescription>
            Nothing on this page is guessed while the backend is unreachable. Counts and runs
            that could not be loaded are shown as unavailable rather than as zero.
          </AlertDescription>
        </Alert>
      ) : null}

      <section aria-labelledby="at-a-glance">
        <h2 id="at-a-glance" className="sr-only">
          At a glance
        </h2>
        <div className="grid gap-px overflow-hidden rounded-lg border border-border bg-border sm:grid-cols-2 xl:grid-cols-4">
          <Metric
            icon={HandHelping}
            label="Needs you"
            value={runs ? String(waiting.length) : "—"}
            note={waiting.length === 0 ? "Nothing is waiting on you" : "Runs stopped for a person"}
            emphasis={waiting.length > 0}
          />
          <Metric
            icon={Activity}
            label="Running now"
            value={active == null ? "—" : String(active)}
            note="Runs acting on a live website"
          />
          <Metric
            icon={Database}
            label="Integrations"
            value={runs ? String(runs.total) : "—"}
            note="Every run on record"
          />
          <Metric
            icon={passedChecks != null && passedChecks === totalChecks ? CheckCircle2 : ShieldCheck}
            label="System checks"
            value={passedChecks == null ? "—" : `${passedChecks}/${totalChecks}`}
            note={health ? `Backend ${humanize(health.status)} · ${health.version}` : "No response"}
          />
        </div>
      </section>

      {waiting.length > 0 ? (
        <section aria-labelledby="waiting-on-you">
          <div className="mb-3">
            <p className="eyebrow">Action required</p>
            <h2 id="waiting-on-you" className="mt-1 text-xl font-medium tracking-[-0.02em]">
              {waiting.length === 1 ? "One run is waiting on you" : `${waiting.length} runs are waiting on you`}
            </h2>
          </div>
          <ul className="divide-y divide-border overflow-hidden rounded-lg border border-border bg-card">
            {waiting.map((run) => (
              <WaitingRow key={run.run_id} run={run} />
            ))}
          </ul>
        </section>
      ) : null}

      <AppSearch />

      <section aria-labelledby="recent-runs">
        <div className="mb-3 flex items-end justify-between gap-4">
          <div>
            <p className="eyebrow">Recent activity</p>
            <h2 id="recent-runs" className="mt-1 text-xl font-medium tracking-[-0.02em]">
              Integration runs
            </h2>
          </div>
          <Button asChild variant="ghost" size="sm" className="rounded-md">
            <Link href="/runs/new">
              New integration <ArrowRight aria-hidden="true" />
            </Link>
          </Button>
        </div>
        {runs ? (
          <RunTable runs={runs.items} />
        ) : (
          <EmptyState
            title="Runs could not be loaded"
            description="The backend did not return the run list. Nothing is shown in its place rather than an empty list, which would read as 'no runs'."
          />
        )}
      </section>
    </div>
  )
}

function Metric({
  icon: Icon,
  label,
  value,
  note,
  emphasis = false,
}: {
  icon: typeof Database
  label: string
  value: string
  note: string
  emphasis?: boolean
}) {
  return (
    <article className="flex min-h-32 flex-col justify-between bg-card p-5">
      <div className="flex items-center justify-between">
        <span className="data-label">{label}</span>
        <Icon
          className={emphasis ? "size-4 text-amber-500" : "size-4 text-muted-foreground"}
          aria-hidden="true"
        />
      </div>
      <div>
        <p className={emphasis ? "metric-value text-amber-500" : "metric-value"}>{value}</p>
        <p className="mt-1 text-xs text-muted-foreground">{note}</p>
      </div>
    </article>
  )
}

function WaitingRow({ run }: { run: RunSummary }) {
  return (
    <li>
      <Link
        href={`/runs/${encodeURIComponent(run.run_id)}`}
        className="flex items-center justify-between gap-4 px-5 py-4 hover:bg-muted/40"
      >
        <div className="min-w-0">
          <p className="truncate text-sm font-medium">{run.app_name}</p>
          <p className="mt-1 truncate text-xs text-muted-foreground">
            {humanize(run.route_kind ?? run.access_route)} · {humanize(run.browser_provider)}
          </p>
        </div>
        <div className="flex shrink-0 items-center gap-3">
          <StatusBadge status={run.status} />
          <ArrowRight className="size-4 text-muted-foreground" aria-hidden="true" />
        </div>
      </Link>
    </li>
  )
}
