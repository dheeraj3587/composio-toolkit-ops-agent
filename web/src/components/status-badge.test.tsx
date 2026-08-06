import { render, screen } from "@testing-library/react"
import { axe } from "jest-axe"

import { StatusBadge } from "@/components/status-badge"

describe("StatusBadge", () => {
  it("renders the exact backend status without promoting configuration-required to success", () => {
    render(<StatusBadge status="configuration_required" />)

    const badge = screen.getByText("Needs setup")
    expect(badge).toHaveClass("text-amber-800")
    expect(screen.queryByText("Ready")).not.toBeInTheDocument()
  })

  // Tone answers "what does this mean for me?", so several statuses share one.
  // What must never collapse is the distinction between done, working, and
  // needing a person.
  it.each([
    ["self_serve", "Self serve", "text-emerald-800"],
    ["completed", "Completed", "text-emerald-800"],
    ["running", "Running", "text-blue-800"],
    ["waiting_for_reply", "Waiting For Reply", "text-blue-800"],
    ["partner_gated", "Partner approval", "text-amber-800"],
    ["configuration_required", "Needs setup", "text-amber-800"],
    ["waiting_for_hitl", "Needs you", "text-amber-800"],
    ["failed", "Failed", "text-red-800"],
    ["unknown", "Unknown", "text-slate-600"],
  ])("gives %s a truthful treatment", (_status, label, className) => {
    render(<StatusBadge status={_status} />)
    expect(screen.getByText(label)).toHaveClass(className)
  })

  it("gives disabled a quiet treatment, not a failure treatment", () => {
    render(<StatusBadge status="disabled" />)
    const badge = screen.getByText("Disabled")
    expect(badge).toHaveClass("text-slate-600")
    expect(badge).not.toHaveClass("text-red-800")
  })

  it("does not ask for attention when configuration is merely unverified", () => {
    render(<StatusBadge status="configured_not_verified" />)
    const badge = screen.getByText("Not yet checked")
    expect(badge).toHaveClass("text-blue-800")
    expect(badge).not.toHaveClass("text-amber-800")
  })

  it("gives not_configured the same attention treatment as any other blocker", () => {
    render(<StatusBadge status="not_configured" />)
    expect(screen.getByText("Not Configured")).toHaveClass("text-amber-800")
  })

  it("explains what a status means in plain language", () => {
    render(<StatusBadge status="waiting_for_hitl" />)
    expect(screen.getByText("Needs you")).toHaveAttribute(
      "title",
      "Paused: the website needs a person to act.",
    )
  })

  it("is accessible for a failed status", async () => {
    const { container } = render(<StatusBadge status="failed" />)
    expect(await axe(container)).toHaveNoViolations()
  })
})
