import {
  ArrowUpRight,
  CheckCircle2,
  CircleDashed,
  Compass,
  FileSearch,
  Fingerprint,
  Globe2,
  KeyRound,
  Mail,
  Network,
  ShieldCheck,
  UserRoundCheck,
} from "lucide-react"

import { StatusBadge } from "@/components/status-badge"
import { Badge } from "@/components/ui/badge"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { formatTimestamp, humanize } from "@/lib/format"
import { phaseMap } from "@/lib/phases"
import type {
  FieldEvidenceView,
  FlowSpecView,
  HitlRequest,
  IntegratorOutput,
  OnboardingStateView,
  OperationalResearch,
  PhaseCollection,
  PhaseState,
  ProviderProfileView,
  SecurityState,
} from "@/lib/types"

const phaseBlueprint = [
  { key: "research", name: "Research", icon: FileSearch, copy: "Verified evidence and deterministic route input." },
  { key: "browser", name: "Browser", icon: Globe2, copy: "Onboarding and deterministic credential capture." },
  { key: "hitl", name: "HITL", icon: UserRoundCheck, copy: "Explicit human intervention and durable resume." },
  { key: "email", name: "Email", icon: Mail, copy: "Locked Gmail operations and reply classification." },
  { key: "output", name: "Output", icon: KeyRound, copy: "Validated, reference-only IntegratorBundle." },
] as const

export function PhaseGrid({ phases }: { phases: PhaseCollection }) {
  const reported = phaseMap(phases)
  return (
    <div className="grid overflow-hidden rounded-md border border-border bg-border sm:grid-cols-2 xl:grid-cols-5">
      {phaseBlueprint.map(({ key, name, icon: Icon, copy }) => {
        const phase = reported.get(key)
        return (
          <article key={key} className="flex min-h-44 flex-col justify-between bg-card p-4 [&:not(:last-child)]:border-b [&:not(:last-child)]:border-border sm:[&:not(:last-child)]:border-b-0 sm:[&:not(:last-child)]:border-r">
            <div className="flex items-start justify-between gap-3">
              <span className="grid size-8 place-items-center rounded-md bg-secondary"><Icon className="size-4 text-brand-600" aria-hidden="true" /></span>
              <StatusBadge status={phase?.status ?? "unavailable"} />
            </div>
            <div>
              <p className="font-mono text-[9px] uppercase tracking-[0.12em] text-muted-foreground">{phase ? "Backend reported" : "Not reported"}</p>
              <h3 className="mt-1 text-sm font-semibold">{phase?.name ?? name}</h3>
              <p className="mt-1 line-clamp-3 text-xs leading-5 text-muted-foreground">{phase?.detail ?? copy}</p>
            </div>
          </article>
        )
      })}
    </div>
  )
}

function SafeLink({ href, children }: { href: string; children: React.ReactNode }) {
  let safe = false
  try {
    const parsed = new URL(href)
    safe = parsed.protocol === "https:" && !parsed.username && !parsed.password
  } catch {
    safe = false
  }
  return safe ? (
    <a href={href} target="_blank" rel="noreferrer" className="inline-flex max-w-full items-center gap-1 underline decoration-border underline-offset-4 hover:decoration-foreground">
      <span className="truncate">{children}</span> <ArrowUpRight className="size-3 shrink-0" aria-hidden="true" />
    </a>
  ) : <span>{children}</span>
}

export function ResearchPanel({ research }: { research: OperationalResearch | null }) {
  if (!research) return <UnavailablePanel title="Operational research" copy="No sanitized research payload has been reported for this run." />

  return (
    <Card className="h-full rounded-lg border-border bg-card py-0 shadow-none">
      <CardHeader className="border-b border-border px-5 py-4">
        <div className="flex items-center justify-between gap-3">
          <div><p className="eyebrow">Evidence record</p><CardTitle className="mt-1 text-lg font-semibold">Operational research</CardTitle></div>
          <Badge variant="outline" className="rounded-md font-mono text-[9px] uppercase tracking-[0.1em]">{Math.round(research.confidence * 100)}% confidence</Badge>
        </div>
      </CardHeader>
      <CardContent className="grid gap-5 px-5 py-5 sm:grid-cols-2">
        <DataPoint label="API type" value={research.api_type} />
        <DataPoint label="Access route" value={humanize(research.access_route)} />
        <DataPoint label="API availability" value={research.api_available == null ? "Not reported" : research.api_available ? "Available" : "Unavailable"} />
        <DataPoint label="Production approval" value={research.production_approval_required == null ? "Not reported" : research.production_approval_required ? "Required" : "Not reported as required"} />
        <div className="sm:col-span-2">
          <span className="data-label">Authentication methods</span>
          <div className="mt-2 flex flex-wrap gap-2">
            {research.auth_methods.length ? research.auth_methods.map((method) => <Badge key={method} variant="outline" className="rounded-md">{method}</Badge>) : <span className="text-sm text-muted-foreground">Not reported</span>}
          </div>
        </div>
        {/* Operational entry points, shown only when the backend reported them.
            Field-level extraction internals (operational_url_claims) stay out of
            the interface; only the resolved page is offered as a safe link. */}
        {research.login_url ? (
          <div>
            <span className="data-label">Official login page</span>
            <p className="mt-1 min-w-0 text-xs"><SafeLink href={research.login_url}>{research.login_url}</SafeLink></p>
          </div>
        ) : null}
        {research.credential_management_url ? (
          <div>
            <span className="data-label">Credential management page</span>
            <p className="mt-1 min-w-0 text-xs"><SafeLink href={research.credential_management_url}>{research.credential_management_url}</SafeLink></p>
          </div>
        ) : null}
        {research.credential_creation_instructions?.length ? (
          <div className="sm:col-span-2">
            <span className="data-label">Credential creation steps</span>
            <ol className="mt-2 list-decimal space-y-1 pl-4 text-xs leading-5 text-muted-foreground">
              {research.credential_creation_instructions.slice(0, 6).map((step) => (
                <li key={step}>{step}</li>
              ))}
            </ol>
          </div>
        ) : null}
        <div className="sm:col-span-2">
          <span className="data-label">Official evidence</span>
          <ul className="mt-2 space-y-2 text-xs">
            {research.evidence_urls.length ? research.evidence_urls.slice(0, 6).map((url) => <li key={url} className="min-w-0"><SafeLink href={url}>{url}</SafeLink></li>) : <li className="text-muted-foreground">No evidence URL reported.</li>}
          </ul>
        </div>
      </CardContent>
    </Card>
  )
}

export function SecurityPanel({ security }: { security: SecurityState | null }) {
  const safeguards = [
    { label: "Recursive redaction", value: security?.redaction, icon: Fingerprint },
    { label: "Fernet credential vault", value: security?.secret_vault, icon: KeyRound }, // pragma: allowlist secret
    { label: "Canonical + effect state", value: security?.operational_state_storage, icon: ShieldCheck },
    { label: "Owner-only storage", value: security?.owner_only_storage, icon: ShieldCheck },
    { label: "Live vendor email", value: security?.live_vendor_email, icon: Mail },
    { label: "Live browser", value: security?.live_browser, icon: Globe2 },
  ]

  return (
    <Card className="h-full rounded-lg border-white/10 bg-rail py-0 text-white shadow-none">
      <CardHeader className="border-b border-white/10 px-5 py-4">
        <p className="font-mono text-[9px] uppercase tracking-[0.14em] text-brand-300">Security boundary</p>
        <CardTitle className="mt-1 text-lg font-semibold text-white">Reference-only credential handling</CardTitle>
      </CardHeader>
      <CardContent className="space-y-3 px-5 py-5">
        {safeguards.map(({ label, value, icon: Icon }) => (
          <div key={label} className="flex items-center justify-between gap-4 border-b border-white/10 pb-3 last:border-0 last:pb-0">
            <span className="flex items-center gap-2 text-xs text-white/65"><Icon className="size-3.5 text-brand-300" aria-hidden="true" />{label}</span>
            <span className="text-right font-mono text-[9px] uppercase tracking-[0.1em] text-white/85">{controlValue(value)}</span>
          </div>
        ))}
        <p className="pt-2 text-xs leading-5 text-white/45">Credential values are never rendered. This view accepts only sanitized backend control state.</p>
      </CardContent>
    </Card>
  )
}

function controlValue(value: string | boolean | null | undefined): string {
  if (typeof value === "boolean") return value ? "Enabled" : "Disabled"
  if (value === "sqlite_not_app_encrypted") return "SQLite · not app-encrypted"
  return typeof value === "string" && /^[a-z0-9 _-]{1,60}$/i.test(value) ? humanize(value) : "Not reported"
}

export function CapabilityPanel({
  title,
  icon: Icon,
  phase,
  children,
}: {
  title: string
  icon: typeof Globe2
  phase?: PhaseState
  children?: React.ReactNode
}) {
  return (
    <Card className="h-full rounded-lg border-border bg-card py-0 shadow-none">
      <CardContent className="flex min-h-52 flex-col justify-between px-5 py-5">
        <div className="flex items-start justify-between gap-3"><span className="grid size-8 place-items-center rounded-md bg-secondary"><Icon className="size-4 text-brand-600" aria-hidden="true" /></span><StatusBadge status={phase?.status ?? "unavailable"} /></div>
        <div>
          <h3 className="text-base font-semibold">{title}</h3>
          <p className="mt-2 text-xs leading-5 text-muted-foreground">{phase?.detail ?? "The backend has not reported this capability state."}</p>
          {children ? <div className="mt-4 border-t border-border pt-4">{children}</div> : null}
        </div>
      </CardContent>
    </Card>
  )
}

export function HitlPanel({ request, action }: { request: HitlRequest | null | undefined; action?: React.ReactNode }) {
  if (!request) {
    return <CapabilityPanel title="Human intervention" icon={UserRoundCheck} phase={{ status: "unavailable", detail: "No active human action request is attached to this run." }} />
  }

  return (
    <Card className="h-full rounded-lg border-amber-300 bg-amber-50 py-0 shadow-none dark:border-amber-500/35 dark:bg-amber-500/10">
      <CardContent className="flex min-h-52 flex-col justify-between px-5 py-5">
        <div className="flex items-start justify-between gap-3"><span className="grid size-8 place-items-center rounded-md bg-amber-100 dark:bg-amber-500/20"><UserRoundCheck className="size-4 text-amber-700 dark:text-amber-300" aria-hidden="true" /></span><StatusBadge status="waiting_for_hitl" /></div>
        <div>
          <p className="font-mono text-[9px] uppercase tracking-[0.12em] text-amber-800 dark:text-amber-300">Human action · {humanize(request.action_type)}</p>
          <h3 className="mt-1 text-base font-semibold text-amber-950">{humanize(request.action_type)}</h3>
          <p className="mt-2 text-xs leading-5 text-amber-900/70 dark:text-amber-300/70">{request.message}</p>
          <p className="mt-3 font-mono text-[9px] uppercase tracking-[0.1em] text-amber-800/80 dark:text-amber-300/80">
            Resume signal · {humanize(request.expected_completion_signal)}
          </p>
          {action ? <div className="mt-4 border-t border-amber-200 pt-4">{action}</div> : null}
        </div>
      </CardContent>
    </Card>
  )
}

export function OutputPanel({ output }: { output: IntegratorOutput | null }) {
  if (!output) return <UnavailablePanel title="Integrator output" copy="No validated output is available. Credential readiness is never inferred by the interface." />

  const referenceCount = Object.keys(output.credential_refs).length
  return (
    <Card className="h-full rounded-lg border-emerald-300 bg-emerald-50/60 py-0 shadow-none dark:border-emerald-500/35 dark:bg-emerald-500/10">
      <CardHeader className="border-b border-emerald-200 dark:border-emerald-500/25 px-5 py-4">
        <p className="font-mono text-[9px] uppercase tracking-[0.13em] text-emerald-700 dark:text-emerald-300">Output · references only</p>
        <CardTitle className="mt-1 text-lg font-semibold">Integrator bundle</CardTitle>
      </CardHeader>
      <CardContent className="grid gap-4 px-5 py-5 sm:grid-cols-2">
        <DataPoint label="Readiness" value={humanize(output.readiness)} />
        <DataPoint label="Auth scheme" value={output.auth_scheme} />
        <DataPoint label="Granted scopes" value={String(output.scopes.length)} />
        <DataPoint label="Vault references held" value={String(referenceCount)} />
        <p className="sm:col-span-2 flex items-start gap-2 border-t border-emerald-200 dark:border-emerald-500/25 pt-4 text-xs leading-5 text-emerald-800 dark:text-emerald-300"><CheckCircle2 className="mt-0.5 size-4 shrink-0" aria-hidden="true" />Only reference counts and validation status are presented; values remain within the vault boundary.</p>
      </CardContent>
    </Card>
  )
}

/**
 * The onboarding "current focus" panel (design "Frontend Operator Console").
 *
 * Every value is read from the backend's onboarding projection: the durable
 * phase, the goal and step the phase declares, and the latest decision-shaped
 * label. Nothing here is inferred from the coarse run status.
 */
export function OnboardingFocusPanel({ state }: { state: OnboardingStateView | null | undefined }) {
  if (!state) {
    return (
      <UnavailablePanel
        title="Onboarding focus"
        copy="This run reports no onboarding phase, so no goal, step, or decision is projected for it."
      />
    )
  }

  return (
    <Card className="h-full rounded-lg border-border bg-card py-0 shadow-none">
      <CardHeader className="border-b border-border px-5 py-4">
        <div className="flex items-center justify-between gap-3">
          <div>
            <p className="eyebrow">Current focus</p>
            <CardTitle className="mt-1 text-lg font-semibold">{humanize(state.phase)}</CardTitle>
          </div>
          <div className="flex flex-wrap justify-end gap-2">
            <StatusBadge status={state.phase} />
            <Badge variant="outline" className="rounded-md font-mono text-[9px] uppercase tracking-[0.1em]">
              Attempt {state.attempt}
            </Badge>
          </div>
        </div>
      </CardHeader>
      <CardContent className="grid gap-5 px-5 py-5 sm:grid-cols-2">
        <span className="grid size-8 place-items-center rounded-md bg-secondary sm:col-span-2">
          <Compass className="size-4 text-brand-600" aria-hidden="true" />
        </span>
        <DataPoint label="Current goal" value={state.goal || "Not reported"} />
        <DataPoint label="Current step" value={state.step || "Not reported"} />
        <div className="sm:col-span-2">
          <span className="data-label">Latest decision</span>
          <p className="mt-1 break-words text-sm leading-6">{state.latest_decision || "No decision has been recorded yet."}</p>
        </div>
        {state.phase_at_pause ? <DataPoint label="Phase at pause" value={humanize(state.phase_at_pause)} /> : null}
        <DataPoint label="Reason code" value={humanize(state.reason_code)} />
        <DataPoint label="Operator prompts" value={`${state.admission_prompts} admission · ${state.captcha_prompts} CAPTCHA`} />
        <DataPoint label="Profile digest" value={state.profile_digest.slice(0, 12)} />
        <p className="sm:col-span-2 border-t border-border pt-4 font-mono text-[9px] uppercase tracking-[0.1em] text-muted-foreground">
          Correlation · {state.correlation_id}
        </p>
      </CardContent>
    </Card>
  )
}

/**
 * The sanitized provider profile panel (Requirement 18.9).
 *
 * Served by `GET /api/runs/{id}/profile`. It carries citations, hosts, and
 * closed vocabularies only: an approval or billing requirement the profile
 * reports as `unknown` is rendered as unknown and never softened to `none`
 * (Requirement 9.9).
 */
export function ProviderProfilePanel({ profile }: { profile: ProviderProfileView | null | undefined }) {
  if (!profile) {
    return (
      <UnavailablePanel
        title="Provider profile"
        copy="No committed provider profile has been reported for this run. Profile state is never inferred from research output."
      />
    )
  }

  const urls = [
    { label: "Developer portal", url: profile.developer_portal_url },
    { label: "Signup page", url: profile.signup_url },
    { label: "Login page", url: profile.login_url },
    { label: "Developer docs", url: profile.developer_docs_url },
  ].filter((entry): entry is { label: string; url: string } => Boolean(entry.url))

  return (
    <Card className="h-full rounded-lg border-border bg-card py-0 shadow-none">
      <CardHeader className="border-b border-border px-5 py-4">
        <div className="flex items-center justify-between gap-3">
          <div>
            <p className="eyebrow">Sanitized profile</p>
            <CardTitle className="mt-1 text-lg font-semibold">{profile.provider_name || humanize(profile.app_slug)}</CardTitle>
          </div>
          <div className="flex flex-wrap justify-end gap-2">
            <Badge variant="outline" className="rounded-md font-mono text-[9px] uppercase tracking-[0.1em]">
              {Math.round(profile.confidence * 100)}% confidence
            </Badge>
            <Badge variant="outline" className="rounded-md font-mono text-[9px] uppercase tracking-[0.1em]">
              Digest {profile.profile_digest.slice(0, 12)}
            </Badge>
          </div>
        </div>
      </CardHeader>
      <CardContent className="grid gap-5 px-5 py-5 sm:grid-cols-2">
        <span className="grid size-8 place-items-center rounded-md bg-secondary sm:col-span-2">
          <Network className="size-4 text-brand-600" aria-hidden="true" />
        </span>
        <DataPoint label="Registrable domain" value={profile.registrable_domain} />
        <DataPoint label="Profile built · UTC" value={formatTimestamp(profile.built_at)} />
        {/* `unknown` is reported as unknown: the run still drives the flow, and the
            interface must not present an unproven requirement as "none". */}
        <DataPoint label="Approval requirement" value={humanize(profile.approval_requirement)} />
        <DataPoint label="Billing requirement" value={humanize(profile.billing_requirement)} />
        <div className="sm:col-span-2">
          <span className="data-label">Allow-list patterns</span>
          <div className="mt-2 flex flex-wrap gap-2">
            {profile.allowed_host_patterns.length
              ? profile.allowed_host_patterns.map((pattern) => (
                  <Badge key={pattern} variant="outline" className="rounded-md font-mono text-[10px]">{pattern}</Badge>
                ))
              : <span className="text-sm text-muted-foreground">Not reported</span>}
          </div>
        </div>
        <div className="sm:col-span-2">
          <span className="data-label">Auxiliary hosts</span>
          <ul className="mt-2 space-y-1 text-xs" aria-label="Auxiliary hosts">
            {profile.auxiliary_hosts.length
              ? profile.auxiliary_hosts.map((host) => (
                  <li key={`${host.kind}:${host.host}`} className="flex flex-wrap items-center gap-2">
                    <span className="font-mono text-[10px]">{host.host}</span>
                    <Badge variant="outline" className="rounded-md font-mono text-[9px] uppercase tracking-[0.1em]">{humanize(host.kind)}</Badge>
                  </li>
                ))
              : <li className="text-muted-foreground">No auxiliary host is declared.</li>}
          </ul>
        </div>
        {urls.length ? (
          <div className="sm:col-span-2 grid gap-4 sm:grid-cols-2">
            {urls.map(({ label, url }) => (
              <div key={label}>
                <span className="data-label">{label}</span>
                <p className="mt-1 min-w-0 text-xs"><SafeLink href={url}>{url}</SafeLink></p>
              </div>
            ))}
          </div>
        ) : null}
        <div className="sm:col-span-2">
          <span className="data-label">Credential flows</span>
          <ul className="mt-2 space-y-3" aria-label="Credential flows">
            {profile.flows.length
              ? profile.flows.map((flow) => <FlowRow key={flow.kind} flow={flow} />)
              : <li className="text-xs text-muted-foreground">No flow is declared for this provider.</li>}
          </ul>
        </div>
        <div className="sm:col-span-2">
          <span className="data-label">Per-field evidence</span>
          <ul className="mt-2 space-y-3" aria-label="Per-field evidence">
            {profile.evidence.length
              ? profile.evidence.slice(0, 12).map((item) => <EvidenceRow key={`${item.field}:${item.source_digest}`} evidence={item} />)
              : <li className="text-xs text-muted-foreground">No field evidence was reported.</li>}
          </ul>
        </div>
      </CardContent>
    </Card>
  )
}

function FlowRow({ flow }: { flow: FlowSpecView }) {
  return (
    <li className="rounded-md border border-border p-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <span className="text-sm font-semibold">{humanize(flow.kind)}</span>
        <div className="flex flex-wrap justify-end gap-2">
          <StatusBadge status={flow.supported ? "ready" : "unavailable"} />
          {flow.requires_approval ? (
            <Badge variant="outline" className="rounded-md font-mono text-[9px] uppercase tracking-[0.1em]">Approval required</Badge>
          ) : null}
          {flow.requires_billing ? (
            <Badge variant="outline" className="rounded-md font-mono text-[9px] uppercase tracking-[0.1em]">Billing required</Badge>
          ) : null}
        </div>
      </div>
      {flow.produces.length ? (
        <p className="mt-2 text-xs text-muted-foreground">Produces · {flow.produces.map(humanize).join(", ")}</p>
      ) : null}
      {flow.entry_url ? (
        <p className="mt-1 min-w-0 text-xs"><SafeLink href={flow.entry_url}>{flow.entry_url}</SafeLink></p>
      ) : null}
      {flow.steps.length ? (
        <ol className="mt-2 list-decimal space-y-1 pl-4 text-xs leading-5 text-muted-foreground">
          {flow.steps.map((step) => <li key={step}>{step}</li>)}
        </ol>
      ) : null}
    </li>
  )
}

function EvidenceRow({ evidence }: { evidence: FieldEvidenceView }) {
  return (
    <li className="rounded-md border border-border p-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <span className="text-xs font-semibold">{humanize(evidence.field)}</span>
        <Badge variant="outline" className="rounded-md font-mono text-[9px] uppercase tracking-[0.1em]">
          {Math.round(evidence.confidence * 100)}% · {evidence.corroborations} corroborations
        </Badge>
      </div>
      <p className="mt-1 break-words font-mono text-[10px]">{evidence.value}</p>
      <p className="mt-1 min-w-0 text-xs"><SafeLink href={evidence.source_url}>{evidence.source_url}</SafeLink></p>
      <p className="mt-1 font-mono text-[9px] uppercase tracking-[0.1em] text-muted-foreground">
        Adapters · {evidence.adapters.length ? evidence.adapters.map(humanize).join(", ") : "Not reported"}
      </p>
    </li>
  )
}

function DataPoint({ label, value }: { label: string; value: string }) {
  return <div><span className="data-label">{label}</span><p className="mt-1 break-words text-sm">{value}</p></div>
}

function UnavailablePanel({ title, copy }: { title: string; copy: string }) {
  return (
    <Card className="h-full rounded-lg border-dashed border-border bg-card/55 shadow-none">
      <CardContent className="flex min-h-52 flex-col justify-between px-5 py-5">
        <CircleDashed className="size-5 text-muted-foreground" aria-hidden="true" />
        <div><p className="data-label">Backend state · unavailable</p><h3 className="mt-1 text-base font-semibold">{title}</h3><p className="mt-2 text-xs leading-5 text-muted-foreground">{copy}</p></div>
      </CardContent>
    </Card>
  )
}
