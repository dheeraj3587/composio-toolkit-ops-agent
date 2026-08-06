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
  it("renders configured adapters as not yet checked rather than as a failure", () => {
    const html = renderProvider({
      provider: "browser_use",
      status: "configured_not_verified",
      detail: "Adapter configuration was found.",
    })

    expect(html).toContain("Checked")
    expect(html).toContain(">Not yet<")
    expect(html).toContain("text-blue-800")
    expect(html).not.toContain("text-red-800")
  })

  it("renders ready adapters as checked and working", () => {
    const html = renderProvider(
      {
        provider: "browser_use",
        status: "ready",
        detail: "Browser Use is initialized with live execution enabled.",
      },
      "run",
    )

    expect(html).toContain("Yes, working")
    expect(html).toContain("A live check, plus this run")
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

  it("does not turn a LangGraph key into legacy-reader readiness", () => {
    const html = renderProvider({
      provider: "langgraph",
      status: "ready",
      detail: "A legacy encryption key is configured.",
    })

    expect(html).toContain("Legacy checkpoint configuration")
    expect(html).toContain("Not part of this runtime")
    expect(html).not.toContain("Yes, working")
    expect(html).not.toContain("Encrypted checkpoint compatibility")
  })

  it("displays disabled status as deliberate, not as a failure", () => {
    const html = renderProvider({
      provider: "browser_use",
      status: "disabled",
      detail: "Live browser execution is policy-disabled.",
    })

    expect(html).toContain("Turned off")
    expect(html).toContain("This is not a fault")
    expect(html).not.toContain("text-red-800")
  })

  it("does not infer configuration presence from disabled status", () => {
    const html = renderProvider({
      provider: "browser_use",
      status: "disabled",
      detail: "Live browser execution is policy-disabled.",
    })

    expect(html).not.toMatch(/>Yes</)
  })

  it("renders Composio as the capability preflight rather than only Gmail", () => {
    const html = renderProvider({
      provider: "composio",
      status: "ready",
      detail: "Read-only Composio preflight initialized.",
    })

    expect(html).toContain("Composio capability preflight")
    expect(html).toContain("Gmail delivery is a separate policy-controlled action")
  })

  it("explains configured_not_verified without claiming live verification", () => {
    const html = renderProvider({
      provider: "gemini",
      status: "configured_not_verified",
      detail: "Structured extraction runs only against fetched official evidence.",
    })

    expect(html).toContain("It is marked working once a live check confirms it")
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
    expect(html).not.toContain(">Yes<")
  })

  it("keeps deployment configuration separate from run-specific evidence", () => {
    const systemHtml = renderProvider(
      { provider: "browser_use", status: "configured_not_verified", detail: "d" },
      "system",
    )
    const runHtml = renderProvider(
      { provider: "browser_use", status: "configured_not_verified", detail: "d" },
      "run",
    )

    for (const label of ["Set up", "Checked", "Based on"]) {
      expect(systemHtml).toContain(label)
    }
    expect(systemHtml).toContain("This deployment&#x27;s configuration")
    expect(runHtml).toContain(">This run<")
  })

  it("names the capabilities an operator actually sees on the system page", () => {
    expect(renderProvider({ provider: "vault", status: "ready", detail: "d" })).toContain(
      "Credential vault",
    )
    expect(renderProvider({ provider: "gmail", status: "ready", detail: "d" })).toContain(
      "Signup inbox",
    )
    expect(
      renderProvider({ provider: "composio_managed_auth", status: "ready", detail: "d" }),
    ).toContain("Managed account connections")
  })

  it("does not retain stale demo or placeholder-record wording", () => {
    const dashboardSource = readFileSync(join(process.cwd(), "src/app/page.tsx"), "utf8")

    expect(dashboardSource).not.toMatch(/demo records|placeholder records/i)
  })
})
