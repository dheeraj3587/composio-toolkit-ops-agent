import { ServerCog } from "lucide-react"

import { StatusBadge } from "@/components/status-badge"
import type { ProviderStatus } from "@/lib/types"

// ---------------------------------------------------------------------------
// Provider-specific display names and descriptions
// ---------------------------------------------------------------------------

const PROVIDER_TITLES: Record<string, string> = {
  langgraph: "LangGraph checkpoint encryption",
  vault: "Secret vault",
  perplexity: "Perplexity search",
  gemini: "Gemini extraction",
  composio: "Composio capability preflight",
  browser_use: "Browser Use agent",
}

const PROVIDER_DESCRIPTIONS: Record<string, string> = {
  langgraph: "Encrypted workflow checkpoints for durable interrupt and resume.",
  vault: "Fernet-encrypted credential vault for reference-only storage.",
  perplexity: "Bounded official-document discovery via Perplexity search API.",
  gemini: "Structured extraction against fetched official evidence.",
  composio:
    "Read-only toolkit and connected-account capability evaluation. Gmail delivery is a separate policy-controlled action.",
  browser_use: "Cloud browser agent for onboarding navigation and live evaluator inspection.",
}

// ---------------------------------------------------------------------------
// Fact derivation — configuration, policy, readiness, and evidence stay separate.
// ---------------------------------------------------------------------------

const CONFIGURED_STATUSES = new Set([
  "configured",
  "configured_not_verified",
  "ready",
])
const POLICY_GATED_PROVIDERS = new Set(["composio", "browser_use"])

function configurationFact(status: string): string {
  if (status === "disabled") return "Not reported by this state"
  if (status === "not_configured") return "Missing"
  if (status === "schema_incompatible") return "Schema incompatible"
  if (CONFIGURED_STATUSES.has(status)) return "Configured"
  return "Not reported"
}

function policyFact(provider: string, status: string): string {
  if (status === "disabled") return "Policy disabled"
  if (provider === "composio") return "Read-only preflight"
  if (provider === "browser_use") return "Allowed"
  if (POLICY_GATED_PROVIDERS.has(provider)) return "Allowed"
  return "No policy gate"
}

function verificationFact(status: string): string {
  if (status === "ready") return "Runtime initialized"
  if (status === "configured_not_verified") return "Awaiting run evidence"
  if (status === "disabled") return "Not applicable"
  return "Not reported"
}

function evidenceFact(evidenceScope: "system" | "run", status: string): string {
  if (status === "ready" && evidenceScope === "run") return "Runtime wiring plus run timeline"
  return evidenceScope === "system"
    ? "System configuration/policy only"
    : "See run phases and timeline"
}

function providerExplanation(provider: ProviderStatus): string {
  if (provider.status === "configured_not_verified") {
    return "Configuration is present. Execute-mode evidence will promote this capability to Ready when its runtime adapter is initialized."
  }
  if (provider.status === "disabled" && /composio/i.test(provider.provider)) {
    return "Live Gmail delivery is disabled, while the read-only Composio capability preflight remains a separate run step."
  }
  if (provider.status === "disabled") {
    return "This capability is intentionally disabled by runtime policy. Configuration and run-specific evidence are separate states."
  }
  if (provider.status === "not_configured") {
    return "The required configuration is not present. This provider cannot operate until configured."
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
    provider.provider
      .replaceAll("_", " ")
      .replace(/\b\w/g, (l) => l.toUpperCase())
  const description = PROVIDER_DESCRIPTIONS[provider.provider]

  const facts = [
    ["Configuration", configurationFact(provider.status)],
    ["Policy", policyFact(provider.provider, provider.status)],
    ["Readiness", verificationFact(provider.status)],
    ["Evidence source", evidenceFact(evidenceScope, provider.status)],
  ] as const

  return (
    <article className="panel flex min-h-64 flex-col rounded-md p-5">
      <div className="flex items-start justify-between gap-3">
        <span className="grid size-8 place-items-center rounded-md bg-secondary">
          <ServerCog className="size-4" aria-hidden="true" />
        </span>
        <StatusBadge status={provider.status} />
      </div>
      <div className="mt-5">
        <h3 className="text-base font-semibold">{title}</h3>
        {description ? (
          <p className="mt-1 text-[10px] leading-4 text-muted-foreground/60">
            {description}
          </p>
        ) : null}
        <p className="mt-2 text-xs leading-5 text-muted-foreground">
          {providerExplanation(provider)}
        </p>
      </div>
      <dl className="mt-5 grid gap-3 border-t border-border pt-4 sm:grid-cols-2">
        {facts.map(([label, value]) => (
          <div key={label}>
            <dt className="data-label">{label}</dt>
            <dd className="mt-1 text-xs leading-5">{value}</dd>
          </div>
        ))}
      </dl>
    </article>
  )
}
