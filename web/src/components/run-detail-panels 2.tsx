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
import type {
  IntegratorOutput,
  OperationalResearch,
  PhaseCollection,
  PhaseState,
  SecurityState,
} from "@/lib/types"
import { humanize } from "@/lib/format"

const phaseBlueprint = [
  { key: "research", name: "Research", icon: FileSearch, copy: "Official evidence and operational access route." },
  { key: "browser", name: "Browser", icon: Globe2, copy: "Onboarding session and deterministic credential boundary." },
  { key: "hitl", name: "HITL", icon: UserRoundCheck, copy: "CAPTCHA, OTP, legal, billing, or identity handoff." },
  { key: "email", name: "Email", icon: Mail, copy: "Controlled outreach thread and reply classification." },
  { key: "output", name: "Output", icon: KeyRound, copy: "Sanitized IntegratorBundle readiness." },
] as const

function phaseMap(collection: PhaseCollection): Map<string, PhaseState> {
  const result = new Map<string, PhaseState>()
  if (Array.isArray(collection)) {
    for (const phase of collection) {
      if (phase.key) result.set(phase.key, phase)
    }
  } else if (collection && typeof collection === "object") {
    for (const [key, phase] of Object.entries(collection)) {
      result.set(
        key,
        typeof phase === "string" ? { key, status: phase } : { key, ...(phase ?? {}) },
      )
    }
  }
  return result
}

export function PhaseGrid({ phases }: { phases: PhaseCollection }) {
  const reported = phaseMap(phases)
  return (
    <div className="grid gap-px overflow-hidden border border-ink/25 bg-ink/20 sm:grid-cols-2 xl:grid-cols-5">
      {phaseBlueprint.map(({ key, name, icon: Icon, copy }) => {
        const phase = reported.get(key)
        return (
          <article key={key} className="min-h-52 bg-card/90 p-5">
            <div className="flex items-start justify-between gap-3">
              <Icon className="size-5 text-rust" aria-hidden="true" />
              <StatusBadge status={phase?.status ?? "unavailable"} />
            </div>
            <p className="mt-10 font-mono text-[9px] uppercase tracking-[0.14em] text-muted-foreground">
              {phase ? "Backend reported" : "Awaiting backend"}
            </p>
            <h3 className="mt-2 font-heading text-2xl">{phase?.name ?? name}</h3>
            <p className="mt-2 text-xs leading-5 text-muted-foreground">{phase?.detail ?? copy}</p>
          </article>
        )
      })}
    </div>
  )
}

function SafeLink({ href, children }: { href: string; children: React.ReactNode }) {
  let safe = false
  try {
    safe = new URL(href).protocol === "https:"
  } catch {
    safe = false
  }
  return safe ? (
    <a href={href} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 underline decoration-ink/25 underline-offset-4 hover:decoration-ink">
      {children} <ArrowUpRight className="size-3" aria-hidden="true" />
    </a>
  ) : (
    <span>{children}</span>
  )
}

export function ResearchPanel({ research }: { research: OperationalResearch | null }) {
  if (!research) {
    return <UnavailablePanel title="Operational research" copy="No sanitized research payload has been reported for this run." />
  }

  const authMethods = research.auth_methods ?? []
  const evidence = research.evidence_urls ?? []
  return (
    <Card className="rounded-none border border-ink/25 bg-card/60 py-0 ring-0">
      <CardHeader className="border-b border-ink/20 px-5 py-4">
        <p className="eyebrow">Evidence / Sanitized</p>
        <CardTitle className="mt-2 font-heading text-2xl">Operational research</CardTitle>
      </CardHeader>
      <CardContent className="grid gap-5 px-5 py-5 sm:grid-cols-2">
        <DataPoint label="API type" value={research.api_type ?? "Not reported"} />
        <DataPoint label="Access route" value={humanize(research.access_route)} />
        <DataPoint label="API availability" value={research.api_available == null ? "Not reported" : research.api_available ? "Available" : "Unavailable"} />
        <DataPoint label="Production approval" value={research.production_approval_required == null ? "Not reported" : research.production_approval_required ? "Required" : "Not reported as required"} />
        <div className="sm:col-span-2">
          <span className="data-label">Authentication methods</span>
          <div className="mt-2 flex flex-wrap gap-2">
            {authMethods.length ? authMethods.map((method) => <Badge key={method} variant="outline" className="rounded-none">{method}</Badge>) : <span className="text-sm text-muted-foreground">Not reported</span>}
          </div>
        </div>
        <div className="sm:col-span-2">
          <span className="data-label">Official evidence</span>
          <ul className="mt-2 space-y-2 text-xs">
            {evidence.length ? evidence.slice(0, 5).map((url) => <li key={url} className="truncate"><SafeLink href={url}>{url}</SafeLink></li>) : <li className="text-muted-foreground">No evidence URL reported.</li>}
          </ul>
        </div>
      </CardContent>
    </Card>
  )
}

export function SecurityPanel({ security }: { security: SecurityState | null }) {
  const safeguards = [
    { label: "Recursive redaction", value: security?.redaction, icon: Fingerprint },
    { label: "Encrypted vault", value: security?.secret_vault, icon: KeyRound },
    { label: "Owner-only storage", value: security?.owner_only_storage, icon: ShieldCheck },
    { label: "Live vendor email", value: security?.live_vendor_email, icon: Mail },
  ]

  return (
    <Card className="rounded-none border border-ink/25 bg-ink text-paper ring-0">
      <CardHeader className="border-b border-paper/20 px-5 py-4">
        <p className="font-mono text-[9px] uppercase tracking-[0.16em] text-paper/55">Boundary / Security</p>
        <CardTitle className="mt-2 font-heading text-2xl text-paper">No reveal surface</CardTitle>
      </CardHeader>
      <CardContent className="space-y-4 px-5 py-5">
        {safeguards.map(({ label, value, icon: Icon }) => (
          <div key={label} className="flex items-center justify-between gap-4 border-b border-paper/15 pb-3 last:border-0 last:pb-0">
            <span className="flex items-center gap-2 text-xs text-paper/75"><Icon className="size-3.5 text-clay" aria-hidden="true" />{label}</span>
            <span className="font-mono text-[9px] uppercase tracking-[0.12em]">{controlValue(value)}</span>
          </div>
        ))}
        <p className="pt-2 text-xs leading-5 text-paper/55">Credential values are never rendered. This view accepts only backend-reported control status.</p>
      </CardContent>
    </Card>
  )
}

function controlValue(value: string | boolean | null | undefined): string {
  if (typeof value === "boolean") return value ? "Enabled" : "Disabled"
  return typeof value === "string" && /^[a-z0-9 _-]{1,40}$/i.test(value)
    ? humanize(value)
    : "Not reported"
}

export function OutputPanel({ output }: { output: IntegratorOutput | null }) {
  if (!output) {
    return <UnavailablePanel title="Integrator output" copy="No output is available. The interface will not invent credential readiness." />
  }
  const referenceCount = Object.keys(output.credential_refs ?? {}).length
  return (
    <Card className="rounded-none border border-viridian/45 bg-viridian/5 py-0 ring-0">
      <CardHeader className="border-b border-viridian/25 px-5 py-4">
        <p className="eyebrow text-viridian">Output / References only</p>
        <CardTitle className="mt-2 font-heading text-2xl">Integrator bundle</CardTitle>
      </CardHeader>
      <CardContent className="grid gap-4 px-5 py-5 sm:grid-cols-2">
        <DataPoint label="Readiness" value={humanize(output.readiness)} />
        <DataPoint label="Auth scheme" value={output.auth_scheme ?? "Not reported"} />
        <DataPoint label="Granted scopes" value={String(output.scopes?.length ?? 0)} />
        <DataPoint label="Vault references held" value={String(referenceCount)} />
        <p className="sm:col-span-2 flex items-center gap-2 border-t border-viridian/20 pt-4 text-xs text-viridian">
          <CheckCircle2 className="size-4" aria-hidden="true" /> Values remain inside the vault boundary; no reveal control exists.
        </p>
      </CardContent>
    </Card>
  )
}

function DataPoint({ label, value }: { label: string; value: string }) {
  return <div><span className="data-label">{label}</span><p className="mt-1 break-words text-sm">{value}</p></div>
}

function UnavailablePanel({ title, copy }: { title: string; copy: string }) {
  return (
    <Card className="rounded-none border border-dashed border-ink/30 bg-card/35 ring-0">
      <CardContent className="flex min-h-48 flex-col justify-between px-5 py-5">
        <CircleDashed className="size-5 text-rust" aria-hidden="true" />
        <div><p className="eyebrow">Backend state / Unavailable</p><h3 className="mt-2 font-heading text-2xl">{title}</h3><p className="mt-2 text-xs leading-5 text-muted-foreground">{copy}</p></div>
      </CardContent>
    </Card>
  )
}
