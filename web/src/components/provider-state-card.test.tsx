import { readFileSync } from "node:fs"
import { join } from "node:path"
import { renderToStaticMarkup } from "react-dom/server"
import { describe, expect, it } from "vitest"

import { ProviderStateCard } from "./provider-state-card"

const baseProvider = {
  provider: "browser_use",
  status: "configured_not_verified",
  detail: "Adapter configuration was found.",
}

function renderProvider(
  provider: typeof baseProvider & { live_tested?: boolean },
  evidenceScope: "system" | "run" = "system",
) {
  return renderToStaticMarkup(
    <ProviderStateCard provider={provider} evidenceScope={evidenceScope} />,
  )
}

describe("ProviderStateCard", () => {
  it("renders an absent live_tested value as Not reported, never No", () => {
    const html = renderProvider(baseProvider)

    expect(html).toContain("Live verification")
    expect(html).toContain(">Not reported<")
    expect(html).not.toContain(">No<")
  })

  it("explains that disabled Gmail actions do not disable the Composio toolkit", () => {
    const html = renderProvider({
      provider: "composio_gmail",
      status: "disabled",
      detail: "Composio disabled",
    })

    expect(html).toContain("External Gmail actions are disabled by policy")
    expect(html).toContain("does not mean the Composio toolkit is disabled")
    expect(html).not.toContain(">Composio disabled<")
  })

  it("defines configured_not_verified without claiming live verification", () => {
    const html = renderProvider(baseProvider)

    expect(html).toContain(
      "Configuration is present, but no live provider verification was reported.",
    )
    expect(html).not.toContain("Live verified")
  })

  it("keeps system configuration separate from run-specific evidence", () => {
    const systemHtml = renderProvider(baseProvider, "system")
    const runHtml = renderProvider(baseProvider, "run")

    for (const label of ["Configuration", "Action policy", "Live verification", "Run evidence"]) {
      expect(systemHtml).toContain(label)
    }
    expect(systemHtml).toContain("Not shown at system level")
    expect(runHtml).toContain("See run phases and timeline")
  })

  it("does not convert unknown or absent fields into false states", () => {
    const html = renderProvider({
      provider: "future_adapter",
      status: "unknown",
      detail: "No normalized state is available.",
    })

    expect(html).toContain("Not reported")
    expect(html).not.toContain(">Disabled<")
    expect(html).not.toContain(">Not live tested<")
  })

  it("does not retain stale demo or placeholder-record wording", () => {
    const dashboardSource = readFileSync(
      join(process.cwd(), "src/app/page.tsx"),
      "utf8",
    )

    expect(dashboardSource).not.toMatch(/demo records|placeholder records/i)
  })
})
