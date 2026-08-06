import type { Metadata } from "next"
import Link from "next/link"
import { notFound } from "next/navigation"
import { connection } from "next/server"
import { ArrowLeft, CircleOff, Clock3, Cpu, Fingerprint, Globe2, Mail, Route, Settings2 } from "lucide-react"

import { AgentTrace } from "@/components/agent-trace"
import { HitlLiveControls, OnboardingControlBar } from "@/components/hitl-live-controls"
import { CanonicalPrimaryAction } from "@/components/canonical-primary-action"
import { PhaseActionForm } from "@/components/phase-action-form"
import { ProviderStateCard } from "@/components/provider-state-card"
import { RunProgress } from "@/components/run-progress"
import {
  CapabilityPanel,
  HitlPanel,
  OnboardingFocusPanel,
  OutputPanel,
  PhaseGrid,
  ProviderProfilePanel,
  ResearchPanel,
  SecurityPanel,
} from "@/components/run-detail-panels"
import { StatusBadge } from "@/components/status-badge"
import { Timeline } from "@/components/timeline"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { ApiError, getProviderProfile, getRun, getRunOutput, getTimeline } from "@/lib/api"
import { formatTimestamp, humanize } from "@/lib/format"
import { phaseMap } from "@/lib/phases"
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

  // The profile route answers 409 until a profile is committed, so it is only
  // requested for a run the backend reports as an onboarding run, and a
  // rejection is rendered as "not reported" rather than filled in.
  const onboarding = detail.onboarding ?? null
  const [timelineResult, outputResult, profileResult] = await Promise.allSettled([
    getTimeline(runId),
    getRunOutput(runId),
    onboarding ? getProviderProfile(runId) : Promise.resolve(null),
  ])
  const timeline = timelineResult.status === "fulfilled" ? timelineResult.value.items : []
  // Loop-progress events (Requirement 4.2) ride on the same timeline response.
  // They are the granular, live steps the agent is taking and were previously
  // fetched but never surfaced in the UI.
  const liveProgress =
    timelineResult.status === "fulfilled" ? timelineResult.value.progress ?? [] : []
  // The reasoning the model authored for each of those steps, plus every source
  // the run actually recorded. Both ride the same response; neither is fetched
  // separately and neither is reconstructed client-side.
  const decisions =
    timelineResult.status === "fulfilled" ? timelineResult.value.decisions ?? [] : []
  const citations =
    timelineResult.status === "fulfilled" ? timelineResult.value.citations ?? [] : []
  const decisionModel =
    timelineResult.status === "fulfilled" ? timelineResult.value.decision_model ?? null : null
  const decisionEffort =
    timelineResult.status === "fulfilled" ? timelineResult.value.decision_effort ?? null : null
  const timelineUnavailable = timelineResult.status === "rejected"
  const output = outputResult.status === "fulfilled" ? outputResult.value : null
  const profile = profileResult.status === "fulfilled" ? profileResult.value : null
  const isPlanOnly = detail.run.execution_mode === "plan_only"
  const displayPhases = isPlanOnly ? planOnlyPhases(detail.phases) : detail.phases
  const phases = phaseMap(displayPhases)
  const browserPhase = phases.get("browser")
  const emailPhase = phases.get("email")
  const outputPhase = phases.get("output")
  const researchPhase = phases.get("research")
  const browser = detail.browser ?? null
  const primaryAction = detail.primary_action ?? null
  // Backend-projected onboarding capability. Present only for an onboarding run,
  // and the sole authority for that run's controls (Requirement 18.4): the
  // status-derived controls below stay in place for legacy runs only.
  const controls = detail.controls ?? null

  // The backend owns every browser permission. A run status alone does not prove
  // that a session is live, a credential page is verified, or a resume is legal.
  const hasBrowserSession =
    !isPlanOnly &&
    (browser
      ? ["running", "waiting_for_hitl", "credential_page_ready"].includes(browser.lifecycle)
      : ["waiting_for_hitl", "browser_running"].includes(detail.run.status))

  // Interactive Playwright HITL has priority over generic controls.
  const interactivePlaywrightResume = Boolean(
    browser?.can_resume &&
    browser.provider === "playwright" &&
    browser.lifecycle === "waiting_for_hitl" &&
    browser.interaction_available,
  )

  // Do not show generic Resume beside interactive Playwright HITL
  // or another specific credential action.
  const canResume = browser
    ? Boolean(
        browser.can_resume &&
          !interactivePlaywrightResume &&
          !browser.can_submit_login &&
          !browser.can_submit_otp,
      )
    : detail.run.status === "waiting_for_hitl" &&
      detail.hitl_request?.resumable === true

  // Status-derived controls are the legacy path. An onboarding run takes every
  // control from `controls` instead, so none of them is offered twice.
  const legacyControls = controls === null
  const verificationPending =
    legacyControls &&
    !isPlanOnly &&
    detail.run.status === "waiting_for_hitl" &&
    detail.hitl_request?.action_type === "email_otp"
  const canPollOutreach =
    legacyControls &&
    !primaryAction &&
    !isPlanOnly &&
    ["outreach_sent", "waiting_for_reply"].includes(detail.run.status)
  const canPoll = canPollOutreach
  const missingFields = Array.from(new Set([
    ...(detail.missing_fields ?? []),
    ...(detail.research?.missing_fields ?? []),
  ]))

  return (
    <div className="page-enter page-stack">
      <Button asChild variant="ghost" size="sm" className="-ml-2 font-mono text-[12px] uppercase tracking-[0.1em]"><Link href="/"><ArrowLeft aria-hidden="true" /> Overview</Link></Button>

      <header className="flex flex-col gap-6 border-b border-border pb-7 xl:flex-row xl:items-end xl:justify-between">
        <div>
          <div className="flex flex-wrap items-center gap-3">
            <p className="eyebrow">Run · {detail.run.app_slug}</p>
            <StatusBadge status={detail.run.status} />
            <Badge variant="outline" className="rounded-md font-mono text-[11px] uppercase tracking-[0.1em]">
              {isPlanOnly ? "Plan only" : "Live run"}
            </Badge>
            {onboarding ? (
              <Badge variant="outline" className="rounded-md font-mono text-[11px] uppercase tracking-[0.1em]">
                Phase · {humanize(onboarding.phase)}
              </Badge>
            ) : null}
          </div>
          <h1 className="mt-3 text-3xl font-semibold tracking-[-0.035em] sm:text-4xl">{detail.run.app_name}</h1>
          <p className="mt-3 break-all font-mono text-[12px] uppercase tracking-[0.1em] text-muted-foreground">{detail.run.run_id}</p>
        </div>
        <div className="grid overflow-hidden rounded-xl border border-border bg-border sm:grid-cols-2 xl:min-w-[660px] xl:grid-cols-3">
          <Meta icon={Route} label="Access route" value={humanize(detail.run.route_kind ?? detail.run.access_route)} />
          <Meta icon={Settings2} label="Account" value={detail.run.account_mode ? humanize(detail.run.account_mode) : "Not reported"} />
          <Meta icon={Globe2} label="Browser" value={humanize(detail.run.browser_provider)} />
          <Meta icon={Clock3} label="Updated · UTC" value={formatTimestamp(detail.run.updated_at)} />
          <Meta
            icon={Cpu}
            label="Decision model"
            value={
              decisionModel
                ? decisionEffort
                  ? `${decisionModel} · ${decisionEffort}`
                  : decisionModel
                : "Deployment default"
            }
          />
        </div>
      </header>

      <RunProgress
        status={detail.run.status}
        phase={detail.run.phase}
        executionMode={detail.run.execution_mode}
        accountMode={detail.run.account_mode}
        hitlAction={detail.hitl_request?.action_type}
      />

      {onboarding ? (
        <section aria-labelledby="onboarding-console">
          <div className="mb-3 flex items-end justify-between gap-4">
            <div>
              <p className="eyebrow">Autonomous onboarding</p>
              <h2 id="onboarding-console" className="mt-1 text-xl font-semibold">What the agent is doing now</h2>
            </div>
            <Badge variant="outline" className="rounded-md font-mono text-[11px] uppercase tracking-[0.1em]">Backend projection</Badge>
          </div>
          <div className="grid items-stretch gap-6 xl:grid-cols-2">
            <OnboardingFocusPanel state={onboarding} />
            <ProviderProfilePanel profile={profile} />
          </div>
          {controls ? (
            <div className="mt-6">
              <OnboardingControlBar
                runId={runId}
                state={onboarding}
                controls={controls}
                providerName={profile?.provider_name ?? detail.run.app_name}
              />
            </div>
          ) : null}
        </section>
      ) : null}

      {isPlanOnly ? (
        <Alert className="rounded-md border-sky-300 bg-sky-50 text-sky-950 dark:border-sky-500/35 dark:bg-sky-500/12 dark:text-sky-200">
          <AlertTitle>Planning completed</AlertTitle>
          <AlertDescription>
            Browser, email, HITL, and credential validation were not attempted. Create a new run with Execute when configured to request approved provider actions.
          </AlertDescription>
        </Alert>
      ) : null}

      {missingFields.length ? (
        <Alert className="rounded-md border-amber-300 bg-amber-50 text-amber-950 dark:border-amber-500/35 dark:bg-amber-500/12 dark:text-amber-200">
          <AlertTitle>{isPlanOnly ? "Baseline planning completed" : "Configuration or evidence is incomplete"}</AlertTitle>
          <AlertDescription>
            {isPlanOnly
              ? `Operational fields were not enriched in Plan Only mode: ${missingFields.map(humanize).join(", ")}.`
              : `Missing fields: ${missingFields.map(humanize).join(", ")}. The interface does not mark blocked capabilities as successful.`}
          </AlertDescription>
        </Alert>
      ) : null}

      {primaryAction ? (
        <CanonicalPrimaryAction runId={runId} action={primaryAction} />
      ) : null}

      <section aria-labelledby="phase-map">
        <div className="mb-3 flex items-end justify-between gap-4"><div><p className="eyebrow">Durable workflow</p><h2 id="phase-map" className="mt-1 text-xl font-semibold">Operational phases</h2></div><Badge variant="outline" className="rounded-md font-mono text-[11px] uppercase tracking-[0.1em]">Backend state</Badge></div>
        <PhaseGrid phases={displayPhases} />
      </section>

      <section className="grid items-stretch gap-6 xl:grid-cols-2">
        <ResearchPanel research={detail.research} />
        <div className="grid gap-6">
          <RouteCard decision={detail.route_decision ?? null} fallbackRoute={detail.run.access_route ?? null} />
          <SecurityPanel security={detail.security} />
        </div>
      </section>

      <section id="browser-session" aria-labelledby="execution-surfaces" className="scroll-mt-6">
        <div className="mb-3"><p className="eyebrow">Execution surfaces</p><h2 id="execution-surfaces" className="mt-1 text-xl font-semibold">Provider and human gates</h2></div>
        <div className={hasBrowserSession ? "grid gap-6 lg:grid-cols-2" : "grid gap-6 lg:grid-cols-3"}>
          <div className={hasBrowserSession ? "lg:col-span-2" : "h-full"}>
            <CapabilityPanel title="Browser onboarding" icon={Globe2} phase={browserPhase}>
              {hasBrowserSession ? (
                <div id="credential-submission" className="scroll-mt-6">
                  <HitlLiveControls
                    runId={runId}
                    browser={browser}
                    browserStateVersion={detail.run.updated_at}
                    canResumeInteractive={interactivePlaywrightResume}
                    fieldName={detail.research?.credential_fields?.[0] ?? "api_token"}
                    fieldLabel={humanize(detail.research?.credential_fields?.[0] ?? "API token")}
                    onboarding={onboarding}
                    controls={controls}
                  />
                </div>
              ) : legacyControls && !primaryAction && isRetryable(browserPhase) ? (
                <PhaseActionForm runId={runId} action="retry" capability="browser" label="Retry browser phase" />
              ) : (
                <ControlUnavailable />
              )}
            </CapabilityPanel>
          </div>
          <HitlPanel
            request={isPlanOnly ? null : detail.hitl_request}
            action={
              !legacyControls
                ? undefined
                : verificationPending
                  ? <PhaseActionForm runId={runId} action="poll-email" label="Check verification email" />
                  : canResume && !interactivePlaywrightResume
                    ? <PhaseActionForm runId={runId} action="resume" label="Resume after human action" />
                    : undefined
            }
          />
          <div id="outreach-review" className="h-full scroll-mt-6">
            <CapabilityPanel title={verificationPending ? "Verification inbox" : "Provider email"} icon={Mail} phase={emailPhase}>
              {verificationPending ? (
                <p className="text-xs leading-5 text-muted-foreground">
                  The connected inbox is being checked automatically. Use the verification action beside the live browser to check immediately.
                </p>
              ) : canPoll ? (
                <PhaseActionForm
                  runId={runId}
                  action="poll-email"
                  label="Check controlled inbox"
                />
              ) : legacyControls && !primaryAction && isRetryable(emailPhase) ? (
                <PhaseActionForm runId={runId} action="retry" capability="email" label="Retry email phase" />
              ) : (
                <ControlUnavailable />
              )}
            </CapabilityPanel>
          </div>
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

      <section className={primaryAction || !legacyControls ? "grid items-stretch gap-6" : "grid items-stretch gap-6 lg:grid-cols-2"}>
        <OutputPanel output={output} />
        {legacyControls && !primaryAction ? <div className="panel rounded-md p-5">
          <p className="eyebrow">Bounded controls</p>
          <h2 className="mt-1 text-lg font-semibold">Retry authority</h2>
          <p className="mt-2 text-xs leading-5 text-muted-foreground">Retries are idempotent backend commands. A configuration-required or no-change receipt is shown as such, never as success.</p>
          <div className="mt-5 space-y-3 border-t border-border pt-4">
            <RetryControl label="Research" runId={runId} capability="research" enabled={!isPlanOnly && isRetryable(researchPhase)} />
            <RetryControl label="Credential validation" runId={runId} capability="validation" enabled={!isPlanOnly && isRetryable(outputPhase)} />
          </div>
        </div> : null}
      </section>

      <section aria-labelledby="timeline">
        <div className="mb-3"><p className="eyebrow">Sanitized audit</p><h2 id="timeline" className="mt-1 text-xl font-semibold">Run timeline</h2></div>
        {timelineUnavailable ? (
          <Alert className="rounded-md border-amber-300 bg-amber-50 dark:border-amber-500/35 dark:bg-amber-500/12 dark:text-amber-200"><AlertTitle>Timeline unavailable</AlertTitle><AlertDescription>The backend could not return sanitized events. This is not treated as an empty timeline.</AlertDescription></Alert>
        ) : <Timeline items={timeline} />}
      </section>

      <AgentTrace
        progress={liveProgress}
        decisions={decisions}
        citations={citations}
        decisionModel={decisionModel}
        decisionEffort={decisionEffort}
      />
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
  return <p className="font-mono text-[11px] uppercase tracking-[0.1em] text-muted-foreground">No action available in current state</p>
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
          <Badge variant="outline" className="rounded-md font-mono text-[11px] uppercase tracking-[0.1em]">
            {decision?.is_final ? "Final decision" : "Evidence input"}
          </Badge>
        </div>
      </div>
      <p className="mt-5 data-label">Deterministic route</p>
      <h3 className="mt-1 text-base font-semibold">{humanize(reportedRoute)}</h3>
      <p className="mt-2 text-xs leading-5 text-muted-foreground">{decision?.explanation ?? "The backend has not reported a final route decision."}</p>
      {decision?.reason_code ? <p className="mt-3 font-mono text-[11px] uppercase tracking-[0.1em] text-muted-foreground">Route reason code · {humanize(decision.reason_code)}</p> : null}
    </div>
  )
}

function BackendUnavailable() {
  return (
    <div className="mx-auto grid min-h-[65vh] max-w-xl place-items-center text-center"><div><CircleOff className="mx-auto size-6 text-muted-foreground" aria-hidden="true" /><p className="eyebrow mt-4">Run unavailable</p><h1 className="mt-2 text-2xl font-semibold">The ledger could not read this run.</h1><p className="mt-3 text-sm leading-6 text-muted-foreground">No run state is fabricated. Confirm the server-only API origin and retry.</p><Button asChild variant="outline" className="mt-6 rounded-md"><Link href="/"><ArrowLeft aria-hidden="true" /> Overview</Link></Button></div></div>
  )
}
