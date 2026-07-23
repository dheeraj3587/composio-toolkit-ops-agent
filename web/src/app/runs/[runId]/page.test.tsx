import { render, screen } from "@testing-library/react"

const mocks = vi.hoisted(() => ({
  getRun: vi.fn(),
  getRunOutput: vi.fn(),
  getTimeline: vi.fn(),
}))

vi.mock("next/server", () => ({ connection: vi.fn(async () => undefined) }))
vi.mock("next/navigation", () => ({
  notFound: vi.fn(),
  useRouter: () => ({ refresh: vi.fn() }),
}))
vi.mock("@/components/phase-action-form", () => ({
  PhaseActionForm: ({ label }: { label: string }) => <button>{label}</button>,
}))
vi.mock("@/lib/api", () => ({
  ApiError: class ApiError extends Error {
    constructor(public readonly status: number) {
      super("API error")
    }
  },
  getRun: mocks.getRun,
  getRunOutput: mocks.getRunOutput,
  getTimeline: mocks.getTimeline,
}))

import RunDetailPage from "@/app/runs/[runId]/page"

describe("RunDetailPage", () => {
  it("renders backend-reported workflow context without exposing credential references", async () => {
    mocks.getRun.mockResolvedValue({
      run: {
        run_id: "run_frontend_123",
        thread_id: "thread_frontend_123",
        app_name: "Linear",
        app_slug: "linear",
        status: "configuration_required",
        access_route: "self_serve",
        execution_mode: "plan_only",
        external_actions: false,
        created_at: "2026-07-23T10:00:00Z",
        updated_at: "2026-07-23T10:05:00Z",
      },
      research: {
        app_name: "Linear",
        app_slug: "linear",
        api_available: true,
        api_type: "REST",
        api_base_url: "https://api.linear.app",
        auth_methods: ["OAuth 2.0"],
        authorization_url: "https://linear.app/oauth/authorize",
        token_url: "https://api.linear.app/oauth/token",
        credential_fields: ["client_id", "client_secret"],
        scopes: [],
        developer_portal_url: "https://linear.app/developers",
        signup_url: null,
        access_route: "self_serve",
        production_approval_required: false,
        contact_email: null,
        contact_url: null,
        evidence_urls: ["https://linear.app/developers/oauth-2-0-authentication"],
        confidence: 0.94,
        source: "p1_snapshot",
        missing_fields: ["contact_email"],
      },
      phases: {
        research: { key: "research", status: "complete", detail: "Evidence loaded." },
        email: { key: "email", status: "configuration_required", detail: "Gmail provider is not configured." },
      },
      security: { redaction: "enabled", external_actions: false },
      route_decision: {
        route: "self_serve",
        reason_code: "official_self_serve_documented",
        explanation: "Official developer access is documented.",
        is_final: true,
      },
      hitl_request: null,
      missing_fields: ["company.work_email_ref"],
      provider_states: [
        {
          provider: "composio_gmail",
          status: "configuration_required",
          detail: "Gmail capability is not configured.",
        },
      ],
    })
    mocks.getTimeline.mockResolvedValue({
      run_id: "run_frontend_123",
      items: [
        {
          event_type: "route_selected",
          summary: "Selected the documented self-serve route.",
          status: "recorded",
          created_at: "2026-07-23T10:03:00Z",
        },
      ],
    })
    mocks.getRunOutput.mockResolvedValue({
      app_name: "Linear",
      app_slug: "linear",
      readiness: "configuration_required",
      api_type: "REST",
      api_base_url: "https://api.linear.app",
      auth_scheme: "OAuth 2.0",
      authorization_url: "https://linear.app/oauth/authorize",
      token_url: "https://api.linear.app/oauth/token",
      scopes: ["read"],
      callback_urls: ["https://example.com/oauth/callback"],
      credential_refs: { client_id: "vault://linear/oauth/client_id_1" },
      access_route: "self_serve",
      evidence_urls: ["https://linear.app/developers/oauth-2-0-authentication"],
      operational_notes: ["Provider configuration is still required."],
      created_at: "2026-07-23T10:04:00Z",
    })

    render(await RunDetailPage({ params: Promise.resolve({ runId: "run_frontend_123" }) }))

    expect(screen.getByRole("heading", { name: "Linear", level: 1 })).toBeInTheDocument()
    expect(screen.getAllByText("Configuration Required").length).toBeGreaterThan(0)
    expect(screen.getAllByText("Self Serve").length).toBeGreaterThan(0)
    expect(screen.getByText("Plan Only")).toBeInTheDocument()
    expect(screen.getByText("Off")).toBeInTheDocument()
    expect(screen.getByText(/company\.work email ref/i)).toBeInTheDocument()
    expect(screen.getByText(/official self serve documented/i)).toBeInTheDocument()
    expect(screen.getByRole("link", { name: /linear\.app\/developers\/oauth-2-0-authentication/i })).toHaveAttribute(
      "href",
      "https://linear.app/developers/oauth-2-0-authentication",
    )
    expect(screen.getByText("Selected the documented self-serve route.")).toBeInTheDocument()
    expect(screen.getByText("Integrator bundle")).toBeInTheDocument()
    expect(screen.getByText("Gmail capability is not configured.")).toBeInTheDocument()
    expect(screen.queryByText("vault://linear/oauth/client_id_1")).not.toBeInTheDocument()
  })
})
