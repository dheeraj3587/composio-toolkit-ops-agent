import { render, screen } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import { beforeEach, describe, expect, it, vi } from "vitest"

const mocks = vi.hoisted(() => ({
  refresh: vi.fn(),
}))

vi.mock("next/navigation", () => ({
  useRouter: () => ({ refresh: mocks.refresh }),
}))

import { RunProgress } from "@/components/run-progress"

describe("RunProgress", () => {
  beforeEach(() => mocks.refresh.mockReset())

  it("renders plan-only work as a completed plan rather than a live agent", () => {
    render(
      <RunProgress
        status="route_selected"
        phase="route_selected"
        executionMode="plan_only"
        accountMode="existing_account"
      />,
    )

    expect(screen.getByRole("heading", { name: "Planning is complete" })).toBeInTheDocument()
    expect(screen.getAllByText("Plan ready")).toHaveLength(2)
    expect(screen.getByRole("progressbar", { name: "Run completion" })).toHaveAttribute(
      "aria-valuenow",
      "100",
    )
    expect(screen.queryByText(/agent is working/i)).not.toBeInTheDocument()
    expect(screen.queryByText(/auto-updating/i)).not.toBeInTheDocument()
  })

  it("offers a manual refresh for recoverable configuration state", async () => {
    const user = userEvent.setup()
    render(
      <RunProgress
        status="configuration_required"
        phase="browser_unavailable"
        executionMode="execute_when_configured"
        accountMode="existing_account"
      />,
    )

    await user.click(screen.getByRole("button", { name: "Refresh status" }))
    expect(mocks.refresh).toHaveBeenCalledOnce()
  })
})
