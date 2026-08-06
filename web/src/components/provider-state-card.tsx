import { ServerCog } from "lucide-react"

import { StatusBadge } from "@/components/status-badge"
import type { ProviderStatus } from "@/lib/types"

// ---------------------------------------------------------------------------
// One card per capability the control plane depends on.
//
// The card answers three questions and no others: is it set up, has that been
// checked, and where does that answer come from. The old version answered four,
// two of which ("Policy", "Evidence source") were phrased as internal concerns
// -- "System configuration/policy only" is true and tells an operator nothing.
// ---------------------------------------------------------------------------

const PROVIDER_TITLES: Record<string, string> = {
  langgraph: "Legacy checkpoint configuration",
  vault: "Credential vault",
  recipes: "App recipe catalog",
  gmail: "Signup inbox",
  composio_managed_auth: "Managed account connections",
  perplexity: "Perplexity search",
  gemini: "Gemini extraction",
  composio: "Composio capability preflight",
  browser_use: "Browser Use agent",
  playwright: "Browser service",
}

const PROVIDER_DESCRIPTIONS: Record<string, string> = {
  langgraph:
    "Reserved compatibility configuration only. Canonical production runs use ordinary SQLite and do not initialize a legacy checkpoint reader.",
  vault: "Encrypted storage for the credentials a run captures. Values are never shown here.",
  recipes: "The reviewed list of apps a run may be started for.",
  gmail: "The mailbox the agent reads to complete email verification during signup.",
  composio_managed_auth:
    "Hosted connection links for apps that support connecting an account directly.",
  perplexity: "Bounded official-document discovery via Perplexity search API.",
  gemini: "Structured extraction against fetched official evidence.",
  composio:
    "Read-only toolkit and connected-account capability evaluation. Gmail delivery is a separate policy-controlled action.",
  browser_use: "Cloud browser agent for onboarding navigation and live evaluator inspection.",
  playwright: "The isolated Chromium the agent drives, with policy-bounded navigation.",
}

const CONFIGURED_STATUSES = new Set(["configured", "configured_not_verified", "ready"])

// The values are deliberately short answers to the column's own question, so a
// value can never be mistaken for a label, and the three columns read across.
function setupFact(status: string): string {
  if (status === "disabled") return "Turned off"
  if (status === "not_configured") return "No"
  if (status === "schema_incompatible") return "Yes, but incompatible"
  if (CONFIGURED_STATUSES.has(status)) return "Yes"
  return "Not reported"
}

function checkedFact(provider: string, status: string): string {
  if (provider === "langgraph") return "Not part of this runtime"
  if (status === "ready") return "Yes, working"
  if (status === "configured_not_verified") return "Not yet"
  if (status === "disabled") return "Nothing to check"
  return "Not reported"
}

function sourceFact(evidenceScope: "system" | "run", status: string): string {
  if (status === "ready" && evidenceScope === "run") return "A live check, plus this run"
  return evidenceScope === "system" ? "This deployment's configuration" : "This run"
}

function providerExplanation(provider: ProviderStatus): string {
  if (provider.provider === "langgraph") {
    return "A configured key does not prove checkpoint data, encryption activity, or reader wiring."
  }
  if (provider.status === "configured_not_verified") {
    return "Everything it needs is present. It is marked working once a live check confirms it, which for some capabilities happens the first time a run uses them."
  }
  if (provider.status === "disabled" && /composio/i.test(provider.provider)) {
    return "Live Gmail delivery is off. The read-only Composio capability check is a separate step and is unaffected."
  }
  if (provider.status === "disabled") {
    return "Turned off deliberately by this deployment's policy. This is not a fault."
  }
  if (provider.status === "not_configured") {
    return "The configuration this needs is missing, so it cannot run."
  }
  return provider.detail
}

export function ProviderStateCard({
  provider,
  evidenceScope,
}: {
  provider: ProviderStatus
  evidenceScope: "system" | "run"
}) {
  const title =
    PROVIDER_TITLES[provider.provider] ??
    provider.provider.replaceAll("_", " ").replace(/\b\w/g, (l) => l.toUpperCase())
  const description = PROVIDER_DESCRIPTIONS[provider.provider]

  const facts = [
    ["Set up", setupFact(provider.status)],
    ["Checked", checkedFact(provider.provider, provider.status)],
    ["Based on", sourceFact(evidenceScope, provider.status)],
  ] as const

  return (
    <article className="panel flex h-full flex-col rounded-lg p-5">
      <div className="flex items-start justify-between gap-3">
        <span className="grid size-8 place-items-center rounded-md bg-secondary">
          <ServerCog className="size-4" aria-hidden="true" />
        </span>
        <StatusBadge status={provider.status} />
      </div>
      <div className="mt-5">
        <h3 className="text-base font-medium">{title}</h3>
        {description ? (
          <p className="mt-1.5 text-[12px] leading-5 text-muted-foreground">{description}</p>
        ) : null}
      </div>
      <p className="mt-3 text-[12px] leading-5 text-muted-foreground/70">
        {providerExplanation(provider)}
      </p>
      <dl className="mt-auto grid gap-3 border-t border-border pt-4 sm:grid-cols-3">
        {facts.map(([label, value]) => (
          <div key={label}>
            <dt className="data-label">{label}</dt>
            <dd className="mt-1 text-[12px] leading-5">{value}</dd>
          </div>
        ))}
      </dl>
    </article>
  )
}
