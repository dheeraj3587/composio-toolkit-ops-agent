import { render, screen } from "@testing-library/react"
import { axe } from "jest-axe"
import { vi } from "vitest"

vi.mock("@/app/runs/[runId]/actions", () => ({
  runManagedConnectionAction: vi.fn(async (state) => state),
  runPhaseAction: vi.fn(async (state) => state),
}))

import { CanonicalPrimaryAction } from "@/components/canonical-primary-action"
import type { PrimaryAction } from "@/lib/types"

const RUN_ID = "run_0123456789abcdef0123456789abcdef"

function renderAction(action: PrimaryAction) {
  return render(<CanonicalPrimaryAction runId={RUN_ID} action={action} />)
}

describe("CanonicalPrimaryAction", () => {
  it("renders one managed-auth control from the backend action", () => {
    const { container } = renderAction({
      kind: "connect_account",
      enabled: true,
      reason_code: "managed_connection_required",
    })

    expect(screen.getByRole("button", { name: "Connect account" })).toBeEnabled()
    expect(container.querySelectorAll("button, a[href]")).toHaveLength(1)
    expect(screen.getByText(/Reason · Managed Connection Required/)).toBeInTheDocument()
  })

  it("renders one in-page Playwright action without inventing provider authority", () => {
    const { container } = renderAction({
      kind: "open_browser",
      enabled: true,
      reason_code: "playwright_session_live",
    })

    expect(screen.getByRole("link", { name: "Open Playwright session" })).toHaveAttribute(
      "href",
      "#browser-session",
    )
    expect(container.querySelectorAll("button, a[href]")).toHaveLength(1)
  })

  it("keeps a backend-disabled action visible and inert", () => {
    const { container } = renderAction({
      kind: "review_outreach",
      enabled: false,
      reason_code: "outreach_contact_review_required",
    })

    expect(screen.getByRole("button", { name: "Review gated outreach" })).toBeDisabled()
    expect(container.querySelectorAll("button, a[href]")).toHaveLength(1)
  })

  it("is accessible for a managed connection requirement", async () => {
    const { container } = renderAction({
      kind: "poll_connection",
      enabled: true,
      reason_code: "managed_connection_pending",
    })

    expect(await axe(container)).toHaveNoViolations()
  })
})
