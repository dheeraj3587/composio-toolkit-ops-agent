import type { Metadata } from "next"
import Link from "next/link"
import { notFound } from "next/navigation"
import { connection } from "next/server"
import { ArrowLeft, CircleOff, Clock3, Fingerprint, Globe2, Mail, Route, Settings2 } from "lucide-react"

import { HitlLiveControls } from "@/components/hitl-live-controls"
import { PhaseActionForm } from "@/components/phase-action-form"
import { ProviderStateCard } from "@/components/provider-state-card"
import { RunAutoRefresh } from "@/components/run-auto-refresh"
import {
  CapabilityPanel,
  HitlPanel,
  OutputPanel,
  PhaseGrid,
  ResearchPanel,
  SecurityPanel,
  phaseMap,
} from "@/components/run-detail-panels"
import { StatusBadge } from "@/components/status-badge"
import { Timeline } from "@/components/timeline"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { ApiError, getRun, getRunOutput, getTimeline } from "@/lib/api"
import { formatTimestamp, humanize } from "@/lib/format"
import type { PhaseCollection, PhaseState, RetryCapability } from "@/lib/types"

export const metadata: Metadata = { title: "Run detail" }

export default async function RunDetailPage({ params }: { params: Promise<{ runId: string }> }) {
  await connection()
  const { runId } = await params
  let detail
  try {
    detail = await getRun(runId)
  } catch (error) {
    if (error instanceof ApiError && error.status === 404) notFound()
    return <BackendUnavailable />
  }

  const [timelineResult, outputResult] = await Promise.allSettled([getTimeline(runId), getRunOutput(runId)])
  const timeline = timelineResult.status === "fulfilled" ? timelineResult.value.items : []
  const timelineUnavailable = timelineResult.status === "rejected"
  const output = outputResult.status === "fulfilled" ? outputResult.value : null
  const isPlanOnly = detail.run.execution_mode === "plan_only"
  const displayPhases = isPlanOnly ? planOnlyPhases(detail.phases) : detail.phases
  const phases = phaseMap(displayPhases)
  const browserPhase = phases.get("browser")
  const emailPhase = phases.get("email")
  const outputPhase = phases.get("output")
  const researchPhase = phases.get("research")
  const canResume =
    detail.run.status === "waiting_for_hitl" && detail.hitl_request?.resumable === true
  const hasBrowserSession = !isPlanOnly && ["waiting_for_hitl", "browser_running"].includes(detail.run.status)
  const canPoll = !isPlanOnly && ["outreach_sent", "waiting_for_reply"].includes(detail.run.status)
  const missingFields = Array.from(new Set([
    ...(detail.missing_fields ?? []),
    ...(detail.research?.missing_fields ?? []),
  ]))

  return (
    <div className="page-enter page-stack">
      <RunAutoRefresh status={detail.run.status} />
      <Button asChild variant="ghost" size="sm" className="-ml-2 font-mono text-[10px] uppercase tracking-[0.1em]"><Link href="/"><ArrowLeft aria-hidden="true" /> Overview</Link></Button>

      <header className="flex flex-col gap-6 border-b border-border pb-7 xl:flex-row xl:items-end xl:justify-between">
        <div>
          <div className="flex flex-wrap items-center gap-3"><p className="eyebrow">Run · {detail.run.app_slug}</p><StatusBadge status={detail.run.status} /></div>
          <h1 className="mt-3 text-3xl font-semibold tracking-[-0.035em] sm:text-4xl">{detail.run.app_name}</h1>
          <p className="mt-3 break-all font-mono text-[10px] uppercase tracking-[0.1em] text-muted-foreground">{detail.run.run_id}</p>
        </div>
        <div className="grid overflow-hidden rounded-md border border-border bg-border sm:grid-cols-2 xl:min-w-[720px] xl:grid-cols-4">
          <Meta icon={Fingerprint} label="Access route" value={humanize(detail.run.access_route)} />
          <Meta icon={Settings2} label="Execution mode" value={humanize(detail.run.execution_mode)} />
          <Meta icon={Clock3} label="Updated · UTC" value={formatTimestamp(detail.run.updated_at)} />
          <Meta icon={CircleOff} label="External actions" value={detail.run.external_actions ? "Enabled" : "Off"} />
        </div>
      </header>

      {isPlanOnly ? (
        <Alert className="rounded-md border-sky-300 bg-sky-50 text-sky-950">
          <AlertTitle>Planning completed</AlertTitle>
          <AlertDescription>
            Browser, email, HITL, and credential validation were not attempted. Create a new run with Execute when configured to request approved provider actions.
          </AlertDescription>
        </Alert>
      ) : null}

      {missingFields.length ? (
        <Alert className="rounded-md border-amber-300 bg-amber-50 text-amber-950">
          <AlertTitle>{isPlanOnly ? "Baseline planning completed" : "Configuration or evidence is incomplete"}</AlertTitle>
          <AlertDescription>
            {isPlanOnly
              ? `Operational fields were not enriched in Plan Only mode: ${missingFields.map(humanize).join(", ")}.`
              : `Missing fields: ${missingFields.map(humanize).join(", ")}. The interface does not mark blocked capabilities as successful.`}
          </AlertDescription>
        </Alert>
      ) : null}

      <section aria-labelledby="phase-map">
        <div className="mb-3 flex items-end justify-between gap-4"><div><p className="eyebrow">Durable workflow</p><h2 id="phase-map" className="mt-1 text-xl font-semibold">Operational phases</h2></div><Badge variant="outline" className="rounded-md font-mono text-[9px] uppercase tracking-[0.1em]">Backend state</Badge></div>
        <PhaseGrid phases={displayPhases} />
      </section>

      <section className="grid items-stretch gap-6 xl:grid-cols-2">
        <ResearchPanel research={detail.research} />
        <div className="grid gap-6">
          <RouteCard decision={detail.route_decision ?? null} fallbackRoute={detail.run.access_route ?? null} />
          <SecurityPanel security={detail.security} />
        </div>
      </section>

      <section aria-labelledby="execution-surfaces">
        <div className="mb-3"><p className="eyebrow">Execution surfaces</p><h2 id="execution-surfaces" className="mt-1 text-xl font-semibold">Provider and human gates</h2></div>
        <div className={hasBrowserSession ? "grid gap-6 lg:grid-cols-2" : "grid gap-6 lg:grid-cols-3"}>
          <div className={hasBrowserSession ? "lg:col-span-2" : "h-full"}>
            <CapabilityPanel title="Browser onboarding" icon={Globe2} phase={browserPhase}>
              {hasBrowserSession ? (
                <HitlLiveControls
                  runId={runId}
                  fieldName={detail.research?.credential_fields?.[0] ?? "api_token"}
                  fieldLabel={humanize(detail.research?.credential_fields?.[0] ?? "API token")}
                />
              ) : isRetryable(browserPhase) ? (
                <PhaseActionForm runId={runId} action="retry" capability="browser" label="Retry browser phase" />
              ) : (
                <ControlUnavailable />
              )}
            </CapabilityPanel>
          </div>
          <HitlPanel request={isPlanOnly ? null : detail.hitl_request} action={canResume ? <PhaseActionForm runId={runId} action="resume" label="Resume after human action" /> : undefined} />
          <CapabilityPanel title="Provider email" icon={Mail} phase={emailPhase}>
            {canPoll ? <PhaseActionForm runId={runId} action="poll-email" label="Poll controlled inbox" /> : isRetryable(emailPhase) ? <PhaseActionForm runId={runId} action="retry" capability="email" label="Retry email phase" /> : <ControlUnavailable />}
          </CapabilityPanel>
        </div>
      </section>

      {detail.provider_states?.length ? (
        <section aria-labelledby="run-providers">
          <div className="mb-3"><p className="eyebrow">Configuration and policy</p><h2 id="run-providers" className="mt-1 text-xl font-semibold">Run-level configuration and policy</h2></div>
          <div className="grid gap-4 md:grid-cols-2 2xl:grid-cols-3">
            {detail.provider_states.map((provider) => (
              <ProviderStateCard key={provider.provider} provider={provider} evidenceScope="run" />
            ))}
          </div>
        </section>
      ) : null}

      <section className="grid items-stretch gap-6 lg:grid-cols-2">
        <OutputPanel output={output} />
        <div className="panel rounded-md p-5">
          <p className="eyebrow">Bounded controls</p>
          <h2 className="mt-1 text-lg font-semibold">Retry authority</h2>
          <p className="mt-2 text-xs leading-5 text-muted-foreground">Retries are idempotent backend commands. A configuration-required or no-change receipt is shown as such, never as success.</p>
          <div className="mt-5 space-y-3 border-t border-border pt-4">
            <RetryControl label="Research" runId={runId} capability="research" enabled={!isPlanOnly && isRetryable(researchPhase)} />
            <RetryControl label="Credential validation" runId={runId} capability="validation" enabled={!isPlanOnly && isRetryable(outputPhase)} />
          </div>
        </div>
      </section>

      <section aria-labelledby="timeline">
        <div className="mb-3"><p className="eyebrow">Sanitized audit</p><h2 id="timeline" className="mt-1 text-xl font-semibold">Run timeline</h2></div>
        {timelineUnavailable ? (
          <Alert className="rounded-md border-amber-300 bg-amber-50"><AlertTitle>Timeline unavailable</AlertTitle><AlertDescription>The backend could not return sanitized events. This is not treated as an empty timeline.</AlertDescription></Alert>
        ) : <Timeline items={timeline} />}
      </section>
    </div>
  )
}

function planOnlyPhases(phases: PhaseCollection): PhaseState[] {
  const existing = phaseMap(phases)
  const research = existing.get("research") ?? {
    key: "research",
    name: "Research",
    phase: "2",
    status: "ready",
    detail: "Verified P1 research and deterministic access routing are available.",
    available: true,
  }

  return [
    research,
    { key: "browser", name: "Browser", phase: "5/6", status: "not_attempted", detail: "Not attempted in Plan Only mode.", available: false },
    { key: "hitl", name: "HITL", phase: "3", status: "not_attempted", detail: "No human action was requested in Plan Only mode.", available: false },
    { key: "email", name: "Email", phase: "4", status: "not_attempted", detail: "Not attempted in Plan Only mode.", available: false },
    { key: "output", name: "Output", phase: "3+", status: "not_attempted", detail: "Credential validation and output generation were not attempted in Plan Only mode.", available: false },
  ]
}

function isRetryable(phase: PhaseState | undefined): boolean {
  return phase?.retryable === true || ["configuration_required", "blocked", "failed"].includes(phase?.status ?? "")
}

function RetryControl({ label, runId, capability, enabled }: { label: string; runId: string; capability: RetryCapability; enabled: boolean }) {
  return <div className="flex items-center justify-between gap-3"><span className="text-xs font-medium">{label}</span>{enabled ? <PhaseActionForm runId={runId} action="retry" capability={capability} label={`Retry ${label.toLowerCase()}`} /> : <StatusBadge status="not_available" />}</div>
}

function ControlUnavailable() {
  return <p className="font-mono text-[9px] uppercase tracking-[0.1em] text-muted-foreground">No action available in current state</p>
}

function Meta({ icon: Icon, label, value }: { icon: typeof Fingerprint; label: string; value: string }) {
  return <div className="bg-card p-4 [&:not(:last-child)]:border-b [&:not(:last-child)]:border-border sm:[&:not(:last-child)]:border-b-0 sm:[&:not(:last-child)]:border-r"><span className="flex items-center gap-1.5 data-label"><Icon className="size-3 text-brand-600" aria-hidden="true" />{label}</span><p className="mt-2 text-xs leading-5">{value}</p></div>
}

function RouteCard({ decision, fallbackRoute }: { decision: { route: string; reason_code: string; explanation: string; is_final?: boolean } | null; fallbackRoute: string | null }) {
  const reportedRoute = decision?.route ?? fallbackRoute ?? "unknown"
  return (
    <div className="panel rounded-md p-5">
      <div className="flex items-start justify-between gap-3">
        <span className="grid size-8 place-items-center rounded-md bg-secondary"><Route className="size-4 text-brand-600" aria-hidden="true" /></span>
        <div className="flex flex-wrap justify-end gap-2">
          <StatusBadge status={reportedRoute} />
          <Badge variant="outline" className="rounded-md font-mono text-[9px] uppercase tracking-[0.1em]">
            {decision?.is_final ? "Final decision" : "Evidence input"}
          </Badge>
        </div>
      </div>
      <p className="mt-5 data-label">Deterministic route</p>
      <h3 className="mt-1 text-base font-semibold">{humanize(reportedRoute)}</h3>
      <p className="mt-2 text-xs leading-5 text-muted-foreground">{decision?.explanation ?? "The backend has not reported a final route decision."}</p>
      {decision?.reason_code ? <p className="mt-3 font-mono text-[9px] uppercase tracking-[0.1em] text-muted-foreground">Route reason code · {humanize(decision.reason_code)}</p> : null}
    </div>
  )
}

function BackendUnavailable() {
  return (
    <div className="mx-auto grid min-h-[65vh] max-w-xl place-items-center text-center"><div><CircleOff className="mx-auto size-6 text-muted-foreground" aria-hidden="true" /><p className="eyebrow mt-4">Run unavailable</p><h1 className="mt-2 text-2xl font-semibold">The ledger could not read this run.</h1><p className="mt-3 text-sm leading-6 text-muted-foreground">No run state is fabricated. Confirm the server-only API origin and retry.</p><Button asChild variant="outline" className="mt-6 rounded-md"><Link href="/"><ArrowLeft aria-hidden="true" /> Overview</Link></Button></div></div>
  )
}
