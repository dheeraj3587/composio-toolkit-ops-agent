import { readFileSync } from "node:fs"
import { join } from "node:path"
import { renderToStaticMarkup } from "react-dom/server"
import { describe, expect, it } from "vitest"

import { ProviderStateCard } from "./provider-state-card"

function renderProvider(
  provider: { provider: string; status: string; detail: string },
  evidenceScope: "system" | "run" = "system",
) {
  return renderToStaticMarkup(
    <ProviderStateCard provider={provider} evidenceScope={evidenceScope} />,
  )
}

describe("ProviderStateCard", () => {
  it("renders configured adapters as awaiting run evidence rather than a failure", () => {
    const html = renderProvider({
      provider: "browser_use",
      status: "configured_not_verified",
      detail: "Adapter configuration was found.",
    })

    expect(html).toContain("Readiness")
    expect(html).toContain("Awaiting run evidence")
    expect(html).toContain("text-sky-800")
    expect(html).not.toContain("text-red-800")
  })

  it("renders ready adapters as runtime initialized", () => {
    const html = renderProvider(
      {
        provider: "browser_use",
        status: "ready",
        detail: "Browser Use is initialized with live execution enabled.",
      },
      "run",
    )

    expect(html).toContain("Runtime initialized")
    expect(html).toContain("Runtime wiring plus run timeline")
    expect(html).toContain("text-emerald-800")
  })

  it("does not contain stale LIVE TESTED wording", () => {
    const html = renderProvider({
      provider: "perplexity",
      status: "ready",
      detail: "Search is wired into execute-mode enrichment.",
    })

    expect(html).not.toMatch(/live.?test/i)
    expect(html).not.toMatch(/live.?verified/i)
  })

  it("displays disabled status as policy-disabled, not as a failure", () => {
    const html = renderProvider({
      provider: "browser_use",
      status: "disabled",
      detail: "Live browser execution is policy-disabled.",
    })

    expect(html).toContain("Policy disabled")
    expect(html).toContain("text-indigo-800")
    expect(html).not.toContain("text-red-800")
  })

  it("does not infer configuration presence from disabled status", () => {
    const html = renderProvider({
      provider: "browser_use",
      status: "disabled",
      detail: "Live browser execution is policy-disabled.",
    })

    expect(html).toContain("Not reported by this state")
    expect(html).not.toMatch(/>Configured</)
  })

  it("renders Composio as the capability preflight rather than only Gmail", () => {
    const html = renderProvider({
      provider: "composio",
      status: "ready",
      detail: "Read-only Composio preflight initialized.",
    })

    expect(html).toContain("Composio capability preflight")
    expect(html).toContain("Read-only preflight")
    expect(html).toContain("Gmail delivery is a separate policy-controlled action")
  })

  it("explains configured_not_verified without claiming live verification", () => {
    const html = renderProvider({
      provider: "gemini",
      status: "configured_not_verified",
      detail: "Structured extraction runs only against fetched official evidence.",
    })

    expect(html).toContain(
      "Configuration is present. Execute-mode evidence will promote this capability to Ready",
    )
    expect(html).not.toContain("Live verified")
    expect(html).not.toContain("Live tested")
  })

  it("does not convert unknown or absent fields into false states", () => {
    const html = renderProvider({
      provider: "future_adapter",
      status: "unknown",
      detail: "No normalized state is available.",
    })

    expect(html).toContain("Not reported")
    expect(html).not.toContain(">Disabled<")
    expect(html).not.toContain(">Configured<")
  })

  it("keeps system configuration separate from run-specific evidence", () => {
    const systemHtml = renderProvider(
      { provider: "browser_use", status: "configured_not_verified", detail: "d" },
      "system",
    )
    const runHtml = renderProvider(
      { provider: "browser_use", status: "configured_not_verified", detail: "d" },
      "run",
    )

    for (const label of ["Configuration", "Policy", "Readiness", "Evidence source"]) {
      expect(systemHtml).toContain(label)
    }
    expect(systemHtml).toContain("System configuration/policy only")
    expect(runHtml).toContain("See run phases and timeline")
  })

  it("shows Browser Use policy as Allowed", () => {
    const html = renderProvider({
      provider: "browser_use",
      status: "ready",
      detail: "Browser runtime ready.",
    })

    expect(html).toContain(">Allowed<")
  })

  it("shows No policy gate for providers without a policy gate", () => {
    const html = renderProvider({
      provider: "perplexity",
      status: "ready",
      detail: "Search is wired into execute-mode enrichment.",
    })

    expect(html).toContain("No policy gate")
  })

  it("does not retain stale demo or placeholder-record wording", () => {
    const dashboardSource = readFileSync(
      join(process.cwd(), "src/app/page.tsx"),
      "utf8",
    )

    expect(dashboardSource).not.toMatch(/demo records|placeholder records/i)
  })
})
