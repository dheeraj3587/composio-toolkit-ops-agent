import type { Metadata } from "next"
import Link from "next/link"
import { notFound } from "next/navigation"
import { connection } from "next/server"
import { ArrowLeft, CircleOff, Clock3, Fingerprint, PauseCircle } from "lucide-react"

import { PhaseActionForm } from "@/components/phase-action-form"
import { PhaseGrid, OutputPanel, ResearchPanel, SecurityPanel } from "@/components/run-detail-panels"
import { StatusBadge } from "@/components/status-badge"
import { Timeline } from "@/components/timeline"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Separator } from "@/components/ui/separator"
import { ApiError, getRun, getRunOutput, getTimeline } from "@/lib/api"
import { formatTimestamp, humanize } from "@/lib/format"

export const metadata: Metadata = { title: "Run detail" }

export default async function RunDetailPage({ params }: { params: Promise<{ runId: string }> }) {
  await connection()
  const { runId } = await params
  let detail
  try {
    detail = await getRun(runId)
  } catch (error) {
    if (error instanceof ApiError && error.status === 404) notFound()
    return <BackendUnavailable runId={runId} />
  }

  const [timelineResult, outputResult] = await Promise.allSettled([
    getTimeline(runId),
    getRunOutput(runId),
  ])
  const timeline = timelineResult.status === "fulfilled" ? timelineResult.value.items : []
  const timelineUnavailable = timelineResult.status === "rejected"
  const output = outputResult.status === "fulfilled" ? outputResult.value : null
  const canResume = detail.run.status === "waiting_for_hitl"
  const canPoll = ["outreach_sent", "waiting_for_reply"].includes(detail.run.status)

  return (
    <div className="page-enter space-y-10">
      <Button asChild variant="ghost" className="-ml-3 rounded-none font-mono text-xs uppercase"><Link href="/"><ArrowLeft aria-hidden="true" /> Back to ledger</Link></Button>

      <header className="grid gap-7 xl:grid-cols-[1fr_auto] xl:items-end">
        <div>
          <div className="flex flex-wrap items-center gap-3"><p className="eyebrow">Run / {detail.run.app_slug}</p><StatusBadge status={detail.run.status} /></div>
          <h1 className="mt-4 font-heading text-5xl leading-[0.95] tracking-[-0.04em] sm:text-7xl">{detail.run.app_name}</h1>
          <p className="mt-4 break-all font-mono text-[10px] uppercase tracking-[0.1em] text-muted-foreground">{detail.run.run_id}</p>
        </div>
        <div className="grid gap-3 border border-ink/25 bg-card/50 p-4 sm:grid-cols-3 xl:min-w-[560px]">
          <Meta icon={Fingerprint} label="Route" value={humanize(detail.run.access_route)} />
          <Meta icon={Clock3} label="Updated · UTC" value={formatTimestamp(detail.run.updated_at)} />
          <Meta icon={CircleOff} label="External actions" value={detail.run.external_actions ? "Backend reports active" : "Off"} />
        </div>
      </header>

      <div className="editorial-rule" />

      <section aria-labelledby="phase-map"><div className="mb-4"><p className="eyebrow">State machine / Read-only map</p><h2 id="phase-map" className="mt-2 font-heading text-3xl">Operational phases</h2></div><PhaseGrid phases={detail.phases} /></section>

      <section className="grid gap-6 xl:grid-cols-[1.25fr_0.75fr]">
        <ResearchPanel research={detail.research} />
        <SecurityPanel security={detail.security} />
      </section>

      <section className="grid gap-6 lg:grid-cols-[1fr_0.7fr]">
        <OutputPanel output={output} />
        <div className="border border-ink/25 bg-card/50 p-5">
          <p className="eyebrow">Bounded actions / Backend validated</p>
          <h2 className="mt-2 font-heading text-2xl">Phase controls</h2>
          <p className="mt-2 text-xs leading-5 text-muted-foreground">Actions are sent server-to-server. HTTP 409 responses are treated as state conflicts, not success.</p>
          <Separator className="my-5 bg-ink/15" />
          <div className="space-y-5">
            {canResume ? <PhaseActionForm runId={runId} action="resume" label="Resume after HITL" /> : <DisabledAction label="Resume after HITL" />}
            {canPoll ? <PhaseActionForm runId={runId} action="poll-email" label="Check controlled inbox" /> : <DisabledAction label="Check controlled inbox" />}
          </div>
        </div>
      </section>

      <section aria-labelledby="timeline">
        <div className="mb-4"><p className="eyebrow">Audit / Sanitized events</p><h2 id="timeline" className="mt-2 font-heading text-3xl">Run timeline</h2></div>
        {timelineUnavailable ? (
          <Alert className="rounded-none border-rust/45 bg-rust/5">
            <AlertTitle>Timeline unavailable</AlertTitle>
            <AlertDescription>The backend could not return sanitized audit events. This is not treated as an empty timeline.</AlertDescription>
          </Alert>
        ) : (
          <Timeline items={timeline} />
        )}
      </section>
    </div>
  )
}

function Meta({ icon: Icon, label, value }: { icon: typeof Fingerprint; label: string; value: string }) {
  return <div><span className="flex items-center gap-1.5 data-label"><Icon className="size-3 text-rust" aria-hidden="true" />{label}</span><p className="mt-2 text-xs leading-5">{value}</p></div>
}

function DisabledAction({ label }: { label: string }) {
  return <div className="flex items-center justify-between gap-3"><span className="text-sm">{label}</span><Badge variant="outline" className="rounded-none font-mono text-[9px] uppercase"><PauseCircle aria-hidden="true" />Unavailable in current state</Badge></div>
}

function BackendUnavailable({ runId }: { runId: string }) {
  return (
    <div className="mx-auto max-w-3xl space-y-6 py-16">
      <p className="eyebrow">Run / Unavailable</p><h1 className="font-heading text-5xl">The ledger could not read this run.</h1>
      <Alert className="rounded-none border-rust/45 bg-rust/5"><AlertTitle>Backend unavailable</AlertTitle><AlertDescription>No run state is fabricated for {runId}. Confirm OPS_API_URL and retry.</AlertDescription></Alert>
      <Button asChild variant="outline" className="rounded-none"><Link href="/"><ArrowLeft aria-hidden="true" /> Return to ledger</Link></Button>
    </div>
  )
}
