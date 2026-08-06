"use client"

import { PanelsTopLeft } from "lucide-react"

import type { BrowserProvider, ProviderStatus } from "@/lib/types"

const selectableProviderStatuses = new Set(["configured", "configured_not_verified", "ready"])

export function browserProviderIsSelectable(
  providerStates: ProviderStatus[],
  provider: BrowserProvider,
): boolean {
  const state = providerStates.find((candidate) => candidate.provider === provider)
  return Boolean(state && selectableProviderStatuses.has(state.status))
}

/**
 * The browser engine, stated rather than chosen.
 *
 * This used to be a two-card picker between the self-hosted Playwright harness
 * and the Browser Use cloud agent. The cloud adapter is gone — it could not run
 * the reviewed credential ladder, because its SDK exposed no allowed-domains
 * control and host safety had to be reconstructed after a task returned a URL
 * rather than enforced at the network layer. One backend means there is nothing
 * to pick, so what is left is the part that was always load-bearing: whether
 * Chromium is actually ready, and what to do when it is not.
 */
export function BrowserEngineStatus({ providerStates }: { providerStates: ProviderStatus[] }) {
  const state = providerStates.find((candidate) => candidate.provider === "playwright")
  const ready = browserProviderIsSelectable(providerStates, "playwright")

  return (
    <section className="space-y-2" aria-labelledby="browser-engine-heading">
      <h3 id="browser-engine-heading" className="text-sm font-medium">
        Browser engine
      </h3>
      <div className="flex items-start gap-3 rounded-lg border border-border bg-card p-4">
        <span className="grid size-8 shrink-0 place-items-center rounded-md border border-border bg-card text-brand-700">
          <PanelsTopLeft className="size-4" aria-hidden="true" />
        </span>
        <div className="min-w-0 space-y-1">
          <p className="font-mono text-xs uppercase tracking-[0.13em] text-muted-foreground">
            Self-hosted
          </p>
          <p className="text-sm font-semibold">Playwright</p>
          <p className="text-sm leading-6 text-muted-foreground">
            Policy-bounded Chromium. Every request is checked against this app&rsquo;s reviewed
            host allowlist before it leaves the container.
          </p>
          {ready ? null : (
            <p className="pt-1 text-sm leading-6 text-amber-800 dark:text-amber-300">
              {state?.detail ?? "Browser readiness could not be confirmed."}
            </p>
          )}
        </div>
      </div>
    </section>
  )
}
