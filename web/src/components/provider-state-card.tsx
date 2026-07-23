import { ServerCog } from "lucide-react"

import { StatusBadge } from "@/components/status-badge"
import { humanize } from "@/lib/format"
import type { ProviderStatus } from "@/lib/types"

const CONFIGURED_STATUSES = new Set(["configured", "configured_not_verified", "ready"])

function configurationValue(status: string): string {
  if (status === "not_configured") return "Not configured"
  if (status === "schema_incompatible") return "Schema incompatible"
  if (CONFIGURED_STATUSES.has(status)) return "Present"
  return "Not reported"
}

function policyValue(status: string): string {
  return status === "disabled" ? "External actions disabled" : "Not reported"
}

function verificationValue(liveTested: boolean | undefined): string {
  if (liveTested === true) return "Live tested"
  if (liveTested === false) return "Not live tested"
  return "Not reported"
}

function providerExplanation(provider: ProviderStatus): string {
  if (provider.status === "configured_not_verified") {
    return "Configuration is present, but no live provider verification was reported."
  }
  if (provider.status === "disabled" && /composio|gmail/i.test(provider.provider)) {
    return "External Gmail actions are disabled by policy. This does not mean the Composio toolkit is disabled."
  }
  if (provider.status === "disabled") {
    return "External actions are disabled by policy. Configuration and verification remain separate states."
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
  const facts = [
    ["Configuration", configurationValue(provider.status)],
    ["Action policy", policyValue(provider.status)],
    ["Live verification", verificationValue(provider.live_tested)],
    [
      "Run evidence",
      evidenceScope === "system" ? "Not shown at system level" : "See run phases and timeline",
    ],
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
        <h3 className="text-base font-semibold">{humanize(provider.provider)}</h3>
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
