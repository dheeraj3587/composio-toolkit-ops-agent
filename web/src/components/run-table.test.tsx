import { render, screen } from "@testing-library/react"

import { RunTable } from "@/components/run-table"
import type { RunSummary } from "@/lib/types"

const run: RunSummary = {
  run_id: "run_0123456789abcdef0123456789abcdef",
  thread_id: "thread_canonical_123",
  app_name: "Pipedrive",
  app_slug: "pipedrive",
  status: "browser_running",
  access_route: "self_serve",
  execution_mode: "execute_when_configured",
  browser_provider: "playwright",
  credential_creation_policy: "create_if_missing",
  recipe_version: "2026-07-28.v1",
  route_kind: "playwright",
  readiness_tier: "browser_ready",
  attempt: 1,
  phase: "target_probe_pending",
  reason_code: "playwright_session_live",
  state_engine: "canonical_v1",
  external_actions: true,
  created_at: "2026-07-28T10:00:00Z",
  updated_at: "2026-07-28T10:01:00Z",
}

describe("RunTable", () => {
  it("shows the immutable provider, recipe, route, and readiness tier", () => {
    render(<RunTable runs={[run]} />)

    expect(screen.getByText(/Playwright · recipe 2026-07-28.v1/)).toBeInTheDocument()
    expect(screen.getByText("Playwright", { selector: "span.block" })).toBeInTheDocument()
    expect(screen.getByText("Browser Ready")).toBeInTheDocument()
    expect(screen.getByRole("link", { name: "Open Pipedrive run" })).toHaveAttribute(
      "href",
      `/runs/${run.run_id}`,
    )
  })
})
