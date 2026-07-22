import { render, screen } from "@testing-library/react"
import { axe } from "jest-axe"

import { HitlPanel, ResearchPanel, SecurityPanel } from "@/components/run-detail-panels"
import type { OperationalResearch } from "@/lib/types"

const research: OperationalResearch = {
  app_name: "Unsafe-looking but escaped",
  app_slug: "unsafe-looking-but-escaped",
  api_available: true,
  api_type: '<img src=x onerror="alert(1)">',
  api_base_url: null,
  auth_methods: ["OAuth 2.0"],
  authorization_url: null,
  token_url: null,
  credential_fields: [],
  scopes: [],
  developer_portal_url: null,
  signup_url: null,
  access_route: "self_serve",
  production_approval_required: false,
  contact_email: null,
  contact_url: null,
  evidence_urls: [],
  confidence: 0.9,
}

describe("safe run detail panels", () => {
  it("renders backend text as text rather than executable HTML", () => {
    const { container } = render(<ResearchPanel research={research} />)
    expect(screen.getByText(research.api_type)).toBeInTheDocument()
    expect(container.querySelector("img")).toBeNull()
    expect(container.querySelector("script")).toBeNull()
  })

  it("has no credential reveal control", () => {
    render(<SecurityPanel security={{ secret_vault: "ready", redaction: "enabled" }} />) // pragma: allowlist secret
    expect(screen.queryByRole("button", { name: /reveal|show.*secret|copy.*secret/i })).not.toBeInTheDocument() // pragma: allowlist secret
  })

  it("only renders a HITL action when a real request exists", () => {
    const { rerender } = render(<HitlPanel request={null} action={<button>Resume run</button>} />)
    expect(screen.queryByRole("button", { name: "Resume run" })).not.toBeInTheDocument()

    rerender(
      <HitlPanel
        request={{ kind: "otp", title: "Enter the provider OTP", instruction: "Complete the OTP step in the controlled session." }}
        action={<button>Resume run</button>}
      />,
    )
    expect(screen.getByRole("button", { name: "Resume run" })).toBeInTheDocument()
  })

  it("keeps the human intervention panel accessible", async () => {
    const { container } = render(<HitlPanel request={null} />)
    expect(await axe(container)).toHaveNoViolations()
  })
})
