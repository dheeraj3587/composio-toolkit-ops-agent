import {
  ArrowUpRight,
  CheckCircle2,
  CircleDashed,
  FileSearch,
  Fingerprint,
  Globe2,
  KeyRound,
  Mail,
  ShieldCheck,
  UserRoundCheck,
} from "lucide-react"

import { StatusBadge } from "@/components/status-badge"
import { Badge } from "@/components/ui/badge"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { humanize } from "@/lib/format"
import type {
  HitlRequest,
  IntegratorOutput,
  OperationalResearch,
  PhaseCollection,
  PhaseState,
  SecurityState,
} from "@/lib/types"

const phaseBlueprint = [
  { key: "research", name: "Research", icon: FileSearch, copy: "Verified evidence and deterministic route input." },
  { key: "browser", name: "Browser", icon: Globe2, copy: "Onboarding and deterministic credential capture." },
  { key: "hitl", name: "HITL", icon: UserRoundCheck, copy: "Explicit human intervention and durable resume." },
  { key: "email", name: "Email", icon: Mail, copy: "Locked Gmail operations and reply classification." },
  { key: "output", name: "Output", icon: KeyRound, copy: "Validated, reference-only IntegratorBundle." },
] as const

export function phaseMap(collection: PhaseCollection): Map<string, PhaseState> {
  const result = new Map<string, PhaseState>()
  if (Array.isArray(collection)) {
    for (const phase of collection) {
      if (phase.key) result.set(phase.key, phase)
    }
  } else if (collection && typeof collection === "object") {
    for (const [key, phase] of Object.entries(collection)) {
      result.set(key, typeof phase === "string" ? { key, status: phase } : { key, ...(phase ?? {}) })
    }
  }
  return result
}

export function PhaseGrid({ phases }: { phases: PhaseCollection }) {
  const reported = phaseMap(phases)
  return (
    <div className="grid overflow-hidden rounded-md border border-border bg-border sm:grid-cols-2 xl:grid-cols-5">
      {phaseBlueprint.map(({ key, name, icon: Icon, copy }) => {
        const phase = reported.get(key)
        return (
          <article key={key} className="flex min-h-44 flex-col justify-between bg-card p-4 [&:not(:last-child)]:border-b [&:not(:last-child)]:border-border sm:[&:not(:last-child)]:border-b-0 sm:[&:not(:last-child)]:border-r">
            <div className="flex items-start justify-between gap-3">
              <span className="grid size-8 place-items-center rounded-md bg-secondary"><Icon className="size-4 text-violet-600" aria-hidden="true" /></span>
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
    <Card className="rounded-md border-border bg-card py-0 shadow-none">
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
    { label: "Secret vault", value: security?.secret_vault, icon: KeyRound }, // pragma: allowlist secret
    { label: "Checkpoint encryption", value: security?.checkpoint_encryption, icon: ShieldCheck },
    { label: "Owner-only storage", value: security?.owner_only_storage, icon: ShieldCheck },
    { label: "Live vendor email", value: security?.live_vendor_email, icon: Mail },
    { label: "Live browser", value: security?.live_browser, icon: Globe2 },
  ]

  return (
    <Card className="rounded-md border-white/10 bg-rail py-0 text-white shadow-none">
      <CardHeader className="border-b border-white/10 px-5 py-4">
        <p className="font-mono text-[9px] uppercase tracking-[0.14em] text-violet-300">Security boundary</p>
        <CardTitle className="mt-1 text-lg font-semibold text-white">Reference-only credential handling</CardTitle>
      </CardHeader>
      <CardContent className="space-y-3 px-5 py-5">
        {safeguards.map(({ label, value, icon: Icon }) => (
          <div key={label} className="flex items-center justify-between gap-4 border-b border-white/10 pb-3 last:border-0 last:pb-0">
            <span className="flex items-center gap-2 text-xs text-white/65"><Icon className="size-3.5 text-violet-300" aria-hidden="true" />{label}</span>
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
    <Card className="rounded-md border-border bg-card py-0 shadow-none">
      <CardContent className="flex min-h-52 flex-col justify-between px-5 py-5">
        <div className="flex items-start justify-between gap-3"><span className="grid size-8 place-items-center rounded-md bg-secondary"><Icon className="size-4 text-violet-600" aria-hidden="true" /></span><StatusBadge status={phase?.status ?? "unavailable"} /></div>
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
    <Card className="rounded-md border-amber-300 bg-amber-50 py-0 shadow-none">
      <CardContent className="flex min-h-52 flex-col justify-between px-5 py-5">
        <div className="flex items-start justify-between gap-3"><span className="grid size-8 place-items-center rounded-md bg-amber-100"><UserRoundCheck className="size-4 text-amber-700" aria-hidden="true" /></span><StatusBadge status="waiting_for_hitl" /></div>
        <div>
          <p className="font-mono text-[9px] uppercase tracking-[0.12em] text-amber-800">Human action · {humanize(request.action_type)}</p>
          <h3 className="mt-1 text-base font-semibold text-amber-950">{humanize(request.action_type)}</h3>
          <p className="mt-2 text-xs leading-5 text-amber-900/70">{request.message}</p>
          <p className="mt-3 font-mono text-[9px] uppercase tracking-[0.1em] text-amber-800/80">
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
    <Card className="rounded-md border-emerald-300 bg-emerald-50/60 py-0 shadow-none">
      <CardHeader className="border-b border-emerald-200 px-5 py-4">
        <p className="font-mono text-[9px] uppercase tracking-[0.13em] text-emerald-700">Output · references only</p>
        <CardTitle className="mt-1 text-lg font-semibold">Integrator bundle</CardTitle>
      </CardHeader>
      <CardContent className="grid gap-4 px-5 py-5 sm:grid-cols-2">
        <DataPoint label="Readiness" value={humanize(output.readiness)} />
        <DataPoint label="Auth scheme" value={output.auth_scheme} />
        <DataPoint label="Granted scopes" value={String(output.scopes.length)} />
        <DataPoint label="Vault references held" value={String(referenceCount)} />
        <p className="sm:col-span-2 flex items-start gap-2 border-t border-emerald-200 pt-4 text-xs leading-5 text-emerald-800"><CheckCircle2 className="mt-0.5 size-4 shrink-0" aria-hidden="true" />Only reference counts and validation status are presented; values remain within the vault boundary.</p>
      </CardContent>
    </Card>
  )
}

function DataPoint({ label, value }: { label: string; value: string }) {
  return <div><span className="data-label">{label}</span><p className="mt-1 break-words text-sm">{value}</p></div>
}

function UnavailablePanel({ title, copy }: { title: string; copy: string }) {
  return (
    <Card className="rounded-md border-dashed border-border bg-card/55 shadow-none">
      <CardContent className="flex min-h-52 flex-col justify-between px-5 py-5">
        <CircleDashed className="size-5 text-muted-foreground" aria-hidden="true" />
        <div><p className="data-label">Backend state · unavailable</p><h3 className="mt-1 text-base font-semibold">{title}</h3><p className="mt-2 text-xs leading-5 text-muted-foreground">{copy}</p></div>
      </CardContent>
    </Card>
  )
}
