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
  // Point 3 / 11-a: absent live verification → Not reported
  it("renders verification as Not reported (backend has no verification field)", () => {
    const html = renderProvider({
      provider: "browser_use",
      status: "configured_not_verified",
      detail: "Adapter configuration was found.",
    })

    expect(html).toContain("Verification")
    expect(html).toContain(">Not reported<")
  })

  // Point 11-h: old "LIVE TESTED · NO" wording is absent
  it("does not contain stale LIVE TESTED wording", () => {
    const html = renderProvider({
      provider: "perplexity",
      status: "configured_not_verified",
      detail: "Search is used only for bounded official-document discovery.",
    })

    expect(html).not.toMatch(/live.?test/i)
    expect(html).not.toMatch(/live.?verified/i)
  })

  // Point 11-b: disabled policy is not a failure
  it("displays disabled status as policy-disabled, not as a failure", () => {
    const html = renderProvider({
      provider: "browser_use",
      status: "disabled",
      detail: "Live browser execution is policy-disabled.",
    })

    expect(html).toContain("Policy disabled")
    // Indigo treatment for policy, not red for failure
    expect(html).toContain("text-indigo-800")
    expect(html).not.toContain("text-red-800")
  })

  // Point 11-c: disabled does not imply configured
  it("does not infer configuration presence from disabled status", () => {
    const html = renderProvider({
      provider: "browser_use",
      status: "disabled",
      detail: "Live browser execution is policy-disabled.",
    })

    expect(html).toContain("Not reported by this state")
    expect(html).not.toMatch(/>Configured</)
    expect(html).not.toMatch(/>Present</)
  })

  // Point 11-d: Composio Gmail delivery title
  it("renders the composio provider as Composio Gmail delivery", () => {
    const html = renderProvider({
      provider: "composio",
      status: "disabled",
      detail: "Live Gmail is policy-disabled.",
    })

    expect(html).toContain("Composio Gmail delivery")
    expect(html).not.toMatch(/>Composio<\/h3>/)
  })

  // Point 11-e: toolkit capability is described as run-specific
  it("explains that Composio toolkit capability is evaluated during runs", () => {
    const html = renderProvider({
      provider: "composio",
      status: "disabled",
      detail: "Live Gmail is policy-disabled.",
    })

    expect(html).toContain("toolkit capability is evaluated separately during individual runs")
  })

  // Point 11-f: configured_not_verified explanation
  it("explains configured_not_verified without claiming live verification", () => {
    const html = renderProvider({
      provider: "gemini",
      status: "configured_not_verified",
      detail: "Structured extraction runs only against fetched official evidence.",
    })

    expect(html).toContain(
      "Configuration is present, but the health endpoint has not performed a live provider probe.",
    )
    expect(html).not.toContain("Live verified")
    expect(html).not.toContain("Live tested")
  })

  // Point 11-g: unknown states render without invented certainty
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

  // System vs run evidence distinction
  it("keeps system configuration separate from run-specific evidence", () => {
    const systemHtml = renderProvider(
      { provider: "browser_use", status: "configured_not_verified", detail: "d" },
      "system",
    )
    const runHtml = renderProvider(
      { provider: "browser_use", status: "configured_not_verified", detail: "d" },
      "run",
    )

    for (const label of ["Configuration", "Policy", "Verification", "Evidence source"]) {
      expect(systemHtml).toContain(label)
    }
    expect(systemHtml).toContain("System configuration/policy only")
    expect(runHtml).toContain("See run phases and timeline")
  })

  // For configured_not_verified: policy shows "Allowed" for gated providers
  it("shows policy as Allowed when a policy-gated provider is configured", () => {
    const html = renderProvider({
      provider: "browser_use",
      status: "configured_not_verified",
      detail: "Browser configuration is present.",
    })

    expect(html).toContain(">Allowed<")
  })

  // For non-gated providers: policy shows "No policy gate"
  it("shows No policy gate for providers without a policy gate", () => {
    const html = renderProvider({
      provider: "perplexity",
      status: "configured_not_verified",
      detail: "Search is used only for bounded official-document discovery.",
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
