import type { Metadata } from "next"
import Link from "next/link"
import { notFound } from "next/navigation"
import { connection } from "next/server"
import {
  ArrowLeft,
  ChevronDown,
  CircleOff,
  Clock3,
  Globe2,
  Mail,
  Route,
  Settings2,
  type LucideIcon,
} from "lucide-react"

import { CanonicalPrimaryAction } from "@/components/canonical-primary-action"
import { HitlLiveControls, OnboardingControlBar } from "@/components/hitl-live-controls"
import { PhaseActionForm } from "@/components/phase-action-form"
import { ProviderStateCard } from "@/components/provider-state-card"
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
import { RunProgress } from "@/components/run-progress"
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

  const onboarding = detail.onboarding ?? null
  const [timelineResult, outputResult, profileResult] = await Promise.allSettled([
    getTimeline(runId),
    getRunOutput(runId),
    onboarding ? getProviderProfile(runId) : Promise.resolve(null),
  ])
  const timeline = timelineResult.status === "fulfilled" ? timelineResult.value.items : []
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
  const controls = detail.controls ?? null

  const hasBrowserSession =
    !isPlanOnly &&
    (browser
      ? ["running", "waiting_for_hitl", "credential_page_ready"].includes(browser.lifecycle)
      : ["waiting_for_hitl", "browser_running"].includes(detail.run.status))

  const interactivePlaywrightResume = Boolean(
    browser?.can_resume &&
    browser.provider === "playwright" &&
    browser.lifecycle === "waiting_for_hitl" &&
    browser.interaction_available,
  )

  const canResume = browser
    ? Boolean(
        browser.can_resume &&
          !interactivePlaywrightResume &&
          !browser.can_submit_login &&
          !browser.can_submit_otp,
      )
    : detail.run.status === "waiting_for_hitl" && detail.hitl_request?.resumable === true

  const legacyControls = controls === null
  const verificationPending =
    legacyControls &&
    !isPlanOnly &&
    detail.run.status === "waiting_for_hitl" &&
    detail.hitl_request?.action_type === "email_otp"
  const canPoll =
    legacyControls &&
    !primaryAction &&
    !isPlanOnly &&
    ["outreach_sent", "waiting_for_reply"].includes(detail.run.status)
  const missingFields = Array.from(new Set([
    ...(detail.missing_fields ?? []),
    ...(detail.research?.missing_fields ?? []),
  ]))
  const retryControlsVisible = legacyControls && !primaryAction
  const researchRetryAvailable = retryControlsVisible && !isPlanOnly && isRetryable(researchPhase)
  const validationRetryAvailable = retryControlsVisible && !isPlanOnly && isRetryable(outputPhase)
  const retryActionAvailable = researchRetryAvailable || validationRetryAvailable

  return (
    <div className="page-enter page-stack">
      <Button asChild variant="ghost" size="sm" className="-ml-2 font-mono text-[10px] uppercase tracking-[0.1em]">
        <Link href="/"><ArrowLeft aria-hidden="true" /> Overview</Link>
      </Button>

      <header className="flex flex-col gap-6 border-b border-border pb-7 xl:flex-row xl:items-end xl:justify-between">
        <div>
          <div className="flex flex-wrap items-center gap-2.5">
            <p className="eyebrow">Run · {detail.run.app_slug}</p>
            <StatusBadge status={detail.run.status} />
            <Badge variant="outline" className="font-mono text-[9px] uppercase tracking-[0.08em]">
              {isPlanOnly ? "Plan only" : "Live run"}
            </Badge>
            {onboarding ? (
              <Badge variant="outline" className="font-mono text-[9px] uppercase tracking-[0.08em]">
                Phase · {humanize(onboarding.phase)}
              </Badge>
            ) : null}
          </div>
          <h1 className="mt-3 text-3xl tracking-[-0.035em] sm:text-4xl">{detail.run.app_name}</h1>
          <p className="mt-3 break-all font-mono text-[10px] uppercase tracking-[0.08em] text-muted-foreground">{detail.run.run_id}</p>
        </div>
        <div className="grid overflow-hidden rounded-lg border border-border bg-border sm:grid-cols-2 xl:min-w-[620px] xl:grid-cols-4">
          <Meta icon={Route} label="Access route" value={humanize(detail.run.route_kind ?? detail.run.access_route)} />
          <Meta icon={Settings2} label="Account" value={detail.run.account_mode ? humanize(detail.run.account_mode) : "Not reported"} />
          <Meta icon={Globe2} label="Browser" value={humanize(detail.run.browser_provider)} />
          <Meta icon={Clock3} label="Updated · UTC" value={formatTimestamp(detail.run.updated_at)} />
        </div>
      </header>

      <RunProgress
        status={detail.run.status}
        phase={detail.run.phase}
        executionMode={detail.run.execution_mode}
        accountMode={detail.run.account_mode}
        hitlAction={detail.hitl_request?.action_type}
      />

      {isPlanOnly ? (
        <Alert className="border-brand-400/25 bg-brand-400/[0.07]">
          <AlertTitle>Planning completed</AlertTitle>
          <AlertDescription>
            Browser, email, HITL, and credential validation were not attempted. Start an execute-mode run to request approved provider actions.
          </AlertDescription>
        </Alert>
      ) : null}

      {missingFields.length ? (
        <Alert className="border-amber-400/30 bg-amber-400/[0.08] text-amber-950">
          <AlertTitle>{isPlanOnly ? "Baseline planning completed" : "Configuration or evidence is incomplete"}</AlertTitle>
          <AlertDescription className="text-amber-800">
            {isPlanOnly
              ? `Operational fields were not enriched in Plan Only mode: ${missingFields.map(humanize).join(", ")}.`
              : `Missing fields: ${missingFields.map(humanize).join(", ")}. Blocked capabilities are not presented as successful.`}
          </AlertDescription>
        </Alert>
      ) : null}

      {primaryAction ? <CanonicalPrimaryAction runId={runId} action={primaryAction} /> : null}

      {onboarding ? (
        <section aria-labelledby="onboarding-console">
          <div className="mb-3 flex items-end justify-between gap-4">
            <div>
              <p className="eyebrow">Current activity</p>
              <h2 id="onboarding-console" className="mt-1 text-xl font-medium">What is happening now</h2>
            </div>
            <Badge variant="outline" className="font-mono text-[9px] uppercase tracking-[0.08em]">Backend projection</Badge>
          </div>
          <OnboardingFocusPanel state={onboarding} />
          {controls?.can_decide_admission ? (
            <div className="mt-4 space-y-3">
              <div>
                <p className="eyebrow">Review before approval</p>
                <h3 className="mt-1 text-base font-medium">Committed provider profile</h3>
                <p className="mt-1 text-xs leading-5 text-muted-foreground">
                  Admission is bound to this exact profile digest. Review it before choosing an account path.
                </p>
              </div>
              <ProviderProfilePanel profile={profile} />
            </div>
          ) : null}
          {controls ? (
            <div className="mt-4">
              <OnboardingControlBar
                runId={runId}
                state={onboarding}
                controls={controls}
                providerName={profile?.provider_name ?? detail.run.app_name}
                admissionProfileAvailable={profile?.profile_digest === onboarding.profile_digest}
              />
            </div>
          ) : null}
        </section>
      ) : null}

      {!isPlanOnly ? (
        <section id="browser-session" aria-labelledby="execution-surfaces" className="scroll-mt-6">
          <div className="mb-3">
            <p className="eyebrow">Live execution</p>
            <h2 id="execution-surfaces" className="mt-1 text-xl font-medium">Browser and human handoff</h2>
          </div>
          <div className={hasBrowserSession ? "grid gap-4 lg:grid-cols-2" : "grid gap-4 lg:grid-cols-3"}>
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
              request={detail.hitl_request}
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
                    The connected inbox is checked automatically. Use the verification action to check immediately.
                  </p>
                ) : canPoll ? (
                  <PhaseActionForm runId={runId} action="poll-email" label="Check controlled inbox" />
                ) : legacyControls && !primaryAction && isRetryable(emailPhase) ? (
                  <PhaseActionForm runId={runId} action="retry" capability="email" label="Retry email phase" />
                ) : (
                  <ControlUnavailable />
                )}
              </CapabilityPanel>
            </div>
          </div>
        </section>
      ) : null}

      {output ? (
        <section aria-labelledby="validated-output">
          <div className="mb-3">
            <p className="eyebrow">Validated output</p>
            <h2 id="validated-output" className="mt-1 text-xl font-medium">Integration result</h2>
          </div>
          <OutputPanel output={output} />
        </section>
      ) : null}

      <DetailDisclosure
        eyebrow="Workflow context"
        title="Workflow and evidence"
        description="Operational phases, reviewed research, and the deterministic route decision."
      >
        <div className="space-y-6">
          <section aria-labelledby="phase-map">
            <div className="mb-3 flex items-center justify-between gap-4">
              <h3 id="phase-map" className="text-sm font-medium">Operational phases</h3>
              <Badge variant="outline" className="font-mono text-[9px] uppercase tracking-[0.08em]">Backend state</Badge>
            </div>
            <PhaseGrid phases={displayPhases} />
          </section>
          <div className="grid items-stretch gap-4 xl:grid-cols-2">
            <ResearchPanel research={detail.research} />
            <RouteCard decision={detail.route_decision ?? null} fallbackRoute={detail.run.access_route ?? null} />
          </div>
        </div>
      </DetailDisclosure>

      <DetailDisclosure
        eyebrow="Configuration context"
        title="Providers and security"
        description="Sanitized provider profile, security controls, and run-scoped configuration state."
      >
        <div className="space-y-6">
          <div className={`grid items-stretch gap-4 ${onboarding && !controls?.can_decide_admission ? "xl:grid-cols-2" : ""}`}>
            <SecurityPanel security={detail.security} />
            {onboarding && !controls?.can_decide_admission ? <ProviderProfilePanel profile={profile} /> : null}
          </div>
          {detail.provider_states?.length ? (
            <section aria-labelledby="run-providers">
              <h3 id="run-providers" className="mb-3 text-sm font-medium">Run-level configuration</h3>
              <div className="grid gap-3 md:grid-cols-2 2xl:grid-cols-3">
                {detail.provider_states.map((provider) => (
                  <ProviderStateCard key={provider.provider} provider={provider} evidenceScope="run" />
                ))}
              </div>
            </section>
          ) : null}
        </div>
      </DetailDisclosure>

      {retryControlsVisible || !output ? (
        <DetailDisclosure
          eyebrow="Bounded operations"
          title="Output and retry authority"
          description={retryActionAvailable
            ? "A backend-authorized recovery action is available. Expand to review and retry."
            : "Reference-only output state and idempotent backend retry commands."}
          initiallyOpen={retryActionAvailable}
        >
          <div className={retryControlsVisible ? "grid items-stretch gap-4 lg:grid-cols-2" : "grid gap-4"}>
            {!output ? <OutputPanel output={null} /> : null}
            {retryControlsVisible ? (
              <div className="panel p-5">
                <p className="eyebrow">Bounded controls</p>
                <h3 className="mt-1 text-lg font-medium">Retry authority</h3>
                <p className="mt-2 text-xs leading-5 text-muted-foreground">
                  Retries are idempotent backend commands. A no-change receipt is never presented as success.
                </p>
                <div className="mt-5 space-y-3 border-t border-border pt-4">
                  <RetryControl label="Research" runId={runId} capability="research" enabled={researchRetryAvailable} />
                  <RetryControl label="Credential validation" runId={runId} capability="validation" enabled={validationRetryAvailable} />
                </div>
              </div>
            ) : null}
          </div>
        </DetailDisclosure>
      ) : null}

      <DetailDisclosure
        eyebrow="Sanitized audit"
        title="Run timeline"
        description={timelineUnavailable
          ? "Sanitized audit events are currently unavailable. Expand for details."
          : "Backend-reported events with sensitive values removed."}
        initiallyOpen={timelineUnavailable}
      >
        {timelineUnavailable ? (
          <Alert className="border-amber-400/30 bg-amber-400/[0.08]">
            <AlertTitle>Timeline unavailable</AlertTitle>
            <AlertDescription>The backend could not return sanitized events. This is not treated as an empty timeline.</AlertDescription>
          </Alert>
        ) : (
          <Timeline items={timeline} />
        )}
      </DetailDisclosure>
    </div>
  )
}

function DetailDisclosure({
  eyebrow,
  title,
  description,
  initiallyOpen = false,
  children,
}: {
  eyebrow: string
  title: string
  description: string
  initiallyOpen?: boolean
  children: React.ReactNode
}) {
  return (
    <details className="disclosure group" open={initiallyOpen || undefined}>
      <summary>
        <div>
          <p className="eyebrow">{eyebrow}</p>
          <h2 className="mt-1 text-base font-medium">{title}</h2>
          <p className="mt-1 text-xs leading-5 text-muted-foreground">{description}</p>
        </div>
        <ChevronDown className="size-4 shrink-0 text-muted-foreground transition-transform group-open:rotate-180" aria-hidden="true" />
      </summary>
      <div className="disclosure-body">{children}</div>
    </details>
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
  return (
    <div className="flex items-center justify-between gap-3">
      <span className="text-xs font-medium">{label}</span>
      {enabled ? <PhaseActionForm runId={runId} action="retry" capability={capability} label={`Retry ${label.toLowerCase()}`} /> : <StatusBadge status="not_available" />}
    </div>
  )
}

function ControlUnavailable() {
  return <p className="font-mono text-[9px] uppercase tracking-[0.08em] text-muted-foreground">No action available in current state</p>
}

function Meta({ icon: Icon, label, value }: { icon: LucideIcon; label: string; value: string }) {
  return (
    <div className="bg-card p-3.5 [&:not(:last-child)]:border-b [&:not(:last-child)]:border-border sm:[&:not(:last-child)]:border-b-0 sm:[&:not(:last-child)]:border-r">
      <span className="flex items-center gap-1.5 data-label"><Icon className="size-3 text-muted-foreground" aria-hidden="true" />{label}</span>
      <p className="mt-2 text-xs leading-5">{value}</p>
    </div>
  )
}

function RouteCard({ decision, fallbackRoute }: { decision: { route: string; reason_code: string; explanation: string; is_final?: boolean } | null; fallbackRoute: string | null }) {
  const reportedRoute = decision?.route ?? fallbackRoute ?? "unknown"
  return (
    <div className="panel h-full p-5">
      <div className="flex items-start justify-between gap-3">
        <Route className="size-4 text-muted-foreground" aria-hidden="true" />
        <div className="flex flex-wrap justify-end gap-2">
          <StatusBadge status={reportedRoute} />
          <Badge variant="outline" className="font-mono text-[9px] uppercase tracking-[0.08em]">
            {decision?.is_final ? "Final decision" : "Evidence input"}
          </Badge>
        </div>
      </div>
      <p className="mt-5 data-label">Deterministic route</p>
      <h3 className="mt-1 text-base font-medium">{humanize(reportedRoute)}</h3>
      <p className="mt-2 text-xs leading-5 text-muted-foreground">{decision?.explanation ?? "The backend has not reported a final route decision."}</p>
      {decision?.reason_code ? <p className="mt-3 font-mono text-[9px] uppercase tracking-[0.08em] text-muted-foreground">Route reason code · {humanize(decision.reason_code)}</p> : null}
    </div>
  )
}

function BackendUnavailable() {
  return (
    <div className="mx-auto grid min-h-[65vh] max-w-xl place-items-center text-center">
      <div>
        <CircleOff className="mx-auto size-6 text-muted-foreground" aria-hidden="true" />
        <p className="eyebrow mt-4">Run unavailable</p>
        <h1 className="mt-2 text-2xl">The ledger could not read this run.</h1>
        <p className="mt-3 text-sm leading-6 text-muted-foreground">No run state is fabricated. Confirm the server-only API origin and retry.</p>
        <Button asChild variant="outline" className="mt-6"><Link href="/"><ArrowLeft aria-hidden="true" /> Overview</Link></Button>
      </div>
    </div>
  )
}
