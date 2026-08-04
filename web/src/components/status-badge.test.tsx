import { render, screen } from "@testing-library/react"
import { axe } from "jest-axe"

import { StatusBadge } from "@/components/status-badge"

/**
 * These tests previously pinned hue classes (`text-orange-300`,
 * `text-emerald-300`, …). The console is now monochrome, so hue can no longer
 * carry status — every one of those tokens resolves to the same grey.
 *
 * The INTENT is preserved exactly, and it was the valuable part: a status must
 * stay visually distinct and must never be promoted into looking like success.
 * The assertions now read the `data-form` shape, which is what actually encodes
 * status. That is a stronger contract than a colour class, because it is also
 * what a colour-blind operator perceives.
 */

function badgeFor(status: string): HTMLElement {
  const label = screen.getByText(status.replaceAll("_", " "), { exact: false })
  const badge = label.closest("[data-form]")
  if (!(badge instanceof HTMLElement)) throw new Error(`no data-form ancestor for ${status}`)
  return badge
}

describe("StatusBadge", () => {
  it("does not promote configuration-required to a settled treatment", () => {
    render(<StatusBadge status="configuration_required" />)

    expect(badgeFor("configuration_required")).toHaveAttribute("data-form", "flagged")
    expect(screen.queryByText("Ready")).not.toBeInTheDocument()
  })

  it.each([
    ["self_serve", "settled"],
    ["completed", "settled"],
    ["browser_running", "live"],
    ["waiting_for_hitl", "held"],
    ["waiting_for_reply", "held"],
    ["failed", "stopped"],
    ["blocked", "stopped"],
    ["configuration_required", "flagged"],
    ["not_configured", "flagged"],
    ["partner_gated", "idle"],
    ["unknown", "idle"],
  ])("gives %s the %s treatment", (status, expected) => {
    render(<StatusBadge status={status} />)
    expect(badgeFor(status)).toHaveAttribute("data-form", expected)
  })

  it("keeps a stopped status visually heavier than a held one", () => {
    const { unmount } = render(<StatusBadge status="failed" />)
    // Severity is carried by border weight now that red is unavailable.
    expect(badgeFor("failed").className).toContain("border-l-[3px]")
    unmount()

    render(<StatusBadge status="waiting_for_hitl" />)
    expect(badgeFor("waiting_for_hitl").className).not.toContain("border-l-[3px]")
  })

  it("gives disabled a policy treatment, not a failure treatment", () => {
    render(<StatusBadge status="disabled" />)

    const badge = badgeFor("disabled")
    expect(badge).toHaveAttribute("data-form", "idle")
    expect(badge).not.toHaveAttribute("data-form", "stopped")
  })

  it("distinguishes configured_not_verified from a status awaiting a person", () => {
    render(<StatusBadge status="configured_not_verified" />)

    const badge = badgeFor("configured_not_verified")
    expect(badge).toHaveAttribute("data-form", "idle")
    expect(badge).not.toHaveAttribute("data-form", "held")
  })

  it("falls back to an idle treatment for an unrecognised status", () => {
    render(<StatusBadge status="some_future_status" />)
    expect(badgeFor("some_future_status")).toHaveAttribute("data-form", "idle")
  })

  it("is accessible for a failed status", async () => {
    const { container } = render(<StatusBadge status="failed" />)
    expect(await axe(container)).toHaveNoViolations()
  })
})
