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

  it("is accessible for a failed status", async () => {
    const { container } = render(<StatusBadge status="failed" />)
    expect(await axe(container)).toHaveNoViolations()
  })
})
