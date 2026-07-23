import { render, screen } from "@testing-library/react"
import { axe } from "jest-axe"

import { StatusBadge } from "@/components/status-badge"

describe("StatusBadge", () => {
  it("renders the exact backend status without promoting configuration-required to success", () => {
    render(<StatusBadge status="configuration_required" />)

    const badge = screen.getByText("Configuration Required")
    expect(badge).toHaveClass("text-orange-800")
    expect(screen.queryByText("Ready")).not.toBeInTheDocument()
  })

  it.each([
    ["self_serve", "text-emerald-800"],
    ["partner_gated", "text-violet-800"],
    ["unknown", "text-slate-600"],
    ["configuration_required", "text-orange-800"],
    ["waiting_for_reply", "text-sky-800"],
    ["waiting_for_hitl", "text-amber-800"],
    ["completed", "text-emerald-800"],
    ["failed", "text-red-800"],
  ])("gives %s a distinct truthful treatment", (status, className) => {
    render(<StatusBadge status={status} />)
    expect(screen.getByText(status.replaceAll("_", " "), { exact: false })).toHaveClass(className)
  })

  it("gives disabled a distinct policy treatment, not a failure treatment", () => {
    render(<StatusBadge status="disabled" />)
    const badge = screen.getByText("Disabled")
    expect(badge).toHaveClass("text-indigo-800")
    expect(badge).not.toHaveClass("text-red-800")
  })

  it("gives configured_not_verified an informational configuration treatment", () => {
    render(<StatusBadge status="configured_not_verified" />)
    const badge = screen.getByText("Configured Not Verified")
    expect(badge).toHaveClass("text-sky-800")
    expect(badge).not.toHaveClass("text-amber-800")
  })

  it("gives not_configured a distinct missing-configuration treatment", () => {
    render(<StatusBadge status="not_configured" />)
    const badge = screen.getByText("Not Configured")
    expect(badge).toHaveClass("text-orange-800")
  })

  it("is accessible for a failed status", async () => {
    const { container } = render(<StatusBadge status="failed" />)
    expect(await axe(container)).toHaveNoViolations()
  })
})
