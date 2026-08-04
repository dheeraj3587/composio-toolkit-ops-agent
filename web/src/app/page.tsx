import Link from "next/link"
import { connection } from "next/server"
import { Activity, ArrowRight, CheckCircle2, CircleOff, Database, RadioTower } from "lucide-react"

import { AgentTrace } from "@/components/agent-trace"
import { AppSearch } from "@/components/app-search"
import { EmptyState } from "@/components/empty-state"
import { RunTable } from "@/components/run-table"
import { StatusBadge } from "@/components/status-badge"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { getHealth, getTimeline, listRuns } from "@/lib/api"
import { humanize } from "@/lib/format"
import type { HealthResponse, RunListResponse } from "@/lib/types"

/** Statuses that mean the agent is mid-walk rather than finished or parked. */
const LIVE_STATUSES = new Set([
  "researching",
  "route_selected",
  "browser_running",
  "waiting_for_hitl",
  "outreach_sent",
  "waiting_for_reply",
])

export default async function DashboardPage() {
  await connection()
  const [healthResult, runsResult] = await Promise.allSettled([getHealth(), listRuns()])
  const health: HealthResponse | null = healthResult.status === "fulfilled" ? healthResult.value : null
  const runs: RunListResponse | null = runsResult.status === "fulfilled" ? runsResult.value : null
  const unavailable = health === null || runs === null

  // The workspace's subject is an agent mid-walk, so the page leads with the one
  // it is walking now — its actual reasoning — rather than counts. `listRuns`
  // returns newest first, so the first live run is the most recent one.
  const featured = runs?.items.find((run) => LIVE_STATUSES.has(run.status)) ?? null
  const featuredTimeline = featured ? await getTimeline(featured.run_id).catch(() => null) : null
  const passedChecks = health?.checks.filter((check) => check.status === "pass").length ?? null
  const attentionRuns = runs?.items.filter((run) =>
    ["waiting_for_hitl", "outreach_sent", "waiting_for_reply", "configuration_required", "blocked", "failed"].includes(run.status),
  ).length ?? null
  const activeRuns = runs?.items.filter((run) =>
    run.execution_mode !== "plan_only" &&
    !["completed", "failed", "blocked", "configuration_required"].includes(run.status),
  ).length ?? null

  return (
    <div className="page-enter page-stack">
      <header className="flex flex-col gap-5 border-b border-border pb-7 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <div className="flex flex-wrap items-center gap-3">
            <p className="eyebrow">Integration workspace</p>
            <StatusBadge status={health?.status ?? "unavailable"} />
          </div>
          <h1 className="mt-3 text-3xl tracking-[-0.035em] sm:text-4xl">Integration operations</h1>
          <p className="mt-3 max-w-2xl text-sm leading-6 text-muted-foreground">
            Create, monitor, and hand off secure app setup from one focused workspace.
          </p>
        </div>
        <Button asChild className="h-10 w-fit px-4">
          <Link href="/runs/new">New integration <ArrowRight aria-hidden="true" /></Link>
        </Button>
      </header>

      {unavailable ? (
        // Emphasis by form, not hue: a left rule marks the one thing on this page
        // that is not simply reported state.
        <Alert className="border-l-[3px] border-l-foreground">
          <RadioTower aria-hidden="true" />
          <AlertTitle>Backend state is partially unavailable</AlertTitle>
          <AlertDescription>
            Run and health state remain unreported until the operations API is available.
          </AlertDescription>
        </Alert>
      ) : null}

      {featured && featuredTimeline && featuredTimeline.boundaries.length > 0 ? (
        <section aria-labelledby="live-run" className="panel p-5 sm:p-6">
          <div className="flex flex-wrap items-start justify-between gap-4">
            <div>
              <p className="eyebrow">Working now</p>
              <h2 id="live-run" className="mt-2 text-2xl tracking-[-0.03em]">
                {featured.app_name}
              </h2>
              <p className="mt-1.5 font-mono text-[10px] tracking-[0.06em] text-muted-foreground">
                {featured.run_id}
              </p>
            </div>
            <div className="flex flex-col items-end gap-2">
              <StatusBadge status={featured.status} />
              <Button asChild variant="outline" size="sm">
                <Link href={`/runs/${featured.run_id}`}>
                  Open run <ArrowRight aria-hidden="true" />
                </Link>
              </Button>
            </div>
          </div>
          <AgentTrace
            boundaries={featuredTimeline.boundaries}
            progress={featuredTimeline.progress}
            attempts={featuredTimeline.attempts}
            research={featuredTimeline.research}
            className="mt-6"
          />
        </section>
      ) : null}

      <section aria-labelledby="workspace-summary">
        <div className="mb-3 flex items-center justify-between gap-4">
          <h2 id="workspace-summary" className="text-sm font-medium">Workspace summary</h2>
          <Button asChild variant="ghost" size="sm" className="font-mono text-[10px] uppercase tracking-[0.1em]">
            <Link href="/system">System details <ArrowRight aria-hidden="true" /></Link>
          </Button>
        </div>
        <div className="grid overflow-hidden rounded-lg border border-border bg-border sm:grid-cols-2 xl:grid-cols-4">
          <Metric icon={Database} label="Integrations" value={runs ? String(runs.total) : "—"} note="Recorded runs" />
          <Metric icon={Activity} label="Recent active" value={activeRuns == null ? "—" : String(activeRuns)} note={runs ? `Live runs among latest ${runs.items.length}` : "Live runs in current page"} />
          <Metric icon={attentionRuns === 0 ? CheckCircle2 : CircleOff} label="Needs attention" value={attentionRuns == null ? "—" : String(attentionRuns)} note="Human or configuration step" />
          <Metric icon={RadioTower} label="Ready checks" value={passedChecks == null ? "—" : `${passedChecks}/${health?.checks.length ?? 0}`} note={health ? `API ${health.version} · ${humanize(health.status)}` : "No response"} />
        </div>
      </section>

      <section aria-labelledby="recent-runs">
        <div className="mb-3 flex items-end justify-between gap-4">
          <div>
            <p className="eyebrow">Recent activity</p>
            <h2 id="recent-runs" className="mt-1 text-xl font-medium tracking-[-0.02em]">Integration runs</h2>
          </div>
          <Badge variant="outline" className="font-mono text-[9px] uppercase tracking-[0.1em]">Backend reported</Badge>
        </div>
        {runs ? <RunTable runs={runs.items} /> : <EmptyState title="Run register unavailable" description="The backend could not return the run list. No run data is inferred or fabricated." />}
      </section>

      <AppSearch />
    </div>
  )
}

function Metric({ icon: Icon, label, value, note }: { icon: typeof Database; label: string; value: string; note: string }) {
  return (
    <article className="bg-card p-4 [&:not(:last-child)]:border-b [&:not(:last-child)]:border-border sm:[&:not(:last-child)]:border-b-0 sm:[&:not(:last-child)]:border-r">
      <div className="flex items-center justify-between gap-3">
        <span className="data-label">{label}</span>
        <Icon className="size-3.5 text-muted-foreground" aria-hidden="true" />
      </div>
      <p className="metric-value mt-4">{value}</p>
      <p className="mt-1 text-xs text-muted-foreground">{note}</p>
    </article>
  )
}
