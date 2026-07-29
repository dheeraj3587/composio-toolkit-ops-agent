import { render, screen } from "@testing-library/react"

const mocks = vi.hoisted(() => ({
  getRun: vi.fn(),
  getRunOutput: vi.fn(),
  getTimeline: vi.fn(),
}))

vi.mock("server-only", () => ({}))
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
  it("renders plan-only runs as completed planning without implying provider failures", async () => {
    mocks.getRun.mockResolvedValue({
      run: {
        run_id: "run_frontend_123",
        thread_id: "thread_frontend_123",
        app_name: "Pipedrive",
        app_slug: "pipedrive",
        status: "route_selected",
        access_route: "self_serve",
        execution_mode: "plan_only",
        browser_provider: "playwright",
        credential_creation_policy: "create_if_missing",
        phase: "route_selected",
        account_mode: "existing_account",
        external_actions: false,
        created_at: "2026-07-23T10:00:00Z",
        updated_at: "2026-07-23T10:05:00Z",
      },
      research: {
        app_name: "Pipedrive",
        app_slug: "pipedrive",
        api_available: null,
        api_type: "REST",
        api_base_url: null,
        auth_methods: ["OAuth2", "API Key"],
        authorization_url: null,
        token_url: null,
        credential_fields: [],
        scopes: [],
        developer_portal_url: "https://developers.pipedrive.com/docs/api/v1",
        signup_url: null,
        access_route: "self_serve",
        production_approval_required: null,
        contact_email: null,
        contact_url: null,
        evidence_urls: ["https://developers.pipedrive.com/docs/api/v1"],
        confidence: 0.95,
        source: "p1_snapshot",
        missing_fields: ["api_base_url", "token_url"],
      },
      phases: {
        research: { key: "research", status: "ready", detail: "Evidence loaded." },
        browser: { key: "browser", status: "unavailable", detail: "Static backend blocker." },
        hitl: { key: "hitl", status: "ready", detail: "Checkpoint configured." },
        email: { key: "email", status: "configuration_required", detail: "Gmail provider is not configured." },
        output: { key: "output", status: "waiting", detail: "No bundle." },
      },
      security: { redaction: "enabled", external_actions: false },
      route_decision: {
        route: "self_serve",
        reason_code: "verified_evidence_route",
        explanation: "Official developer access is documented.",
        is_final: true,
      },
      hitl_request: null,
      missing_fields: ["api_base_url", "token_url"],
      provider_states: [],
    })
    mocks.getTimeline.mockResolvedValue({
      run_id: "run_frontend_123",
      items: [
        {
          event_id: 1,
          event_type: "route_selected",
          summary: "Access route selected.",
          status: "recorded",
          created_at: "2026-07-23T10:03:00Z",
        },
      ],
    })
    mocks.getRunOutput.mockRejectedValue(new Error("No output"))

    render(await RunDetailPage({ params: Promise.resolve({ runId: "run_frontend_123" }) }))

    expect(screen.getByRole("heading", { name: "Pipedrive", level: 1 })).toBeInTheDocument()
    expect(screen.getByText("Planning completed")).toBeInTheDocument()
    expect(screen.getByText(/browser, email, hitl, and credential validation were not attempted/i)).toBeInTheDocument()
    expect(screen.getByText("Baseline planning completed")).toBeInTheDocument()
    expect(screen.getByText(/operational fields were not enriched in plan only mode/i)).toBeInTheDocument()
    expect(screen.getAllByText("Not Attempted").length).toBeGreaterThanOrEqual(4)
    expect(screen.queryByText("Static backend blocker.")).not.toBeInTheDocument()
    expect(screen.queryByRole("button", { name: /retry browser phase/i })).not.toBeInTheDocument()
    expect(screen.getByText("Plan only")).toBeInTheDocument()
    expect(screen.getByRole("heading", { name: "Planning is complete" })).toBeInTheDocument()
    expect(screen.getByRole("progressbar", { name: "Run completion" })).toHaveAttribute(
      "aria-valuenow",
      "100",
    )
    expect(screen.queryByText(/auto-updating/i)).not.toBeInTheDocument()
    expect(screen.getByText("Access route selected.")).toBeInTheDocument()
  })

  it("shows frozen canonical metadata and only the backend-authorized primary action", async () => {
    const runId = "run_11111111111111111111111111111111"
    mocks.getRun.mockResolvedValue({
      run: {
        run_id: runId,
        thread_id: "thread_canonical_123",
        app_name: "GitHub",
        app_slug: "github",
        status: "connection_required",
        access_route: "self_serve",
        execution_mode: "execute_when_configured",
        account_mode: "existing_account",
        browser_provider: "playwright",
        credential_creation_policy: "create_if_missing",
        recipe_version: "2026-07-28.v1",
        route_kind: "managed_auth",
        readiness_tier: "managed_auth_ready",
        attempt: 0,
        phase: "connection_required",
        reason_code: "managed_connection_required",
        state_engine: "canonical_v1",
        external_actions: false,
        created_at: "2026-07-28T10:00:00Z",
        updated_at: "2026-07-28T10:01:00Z",
      },
      research: null,
      phases: null,
      security: null,
      route_decision: null,
      hitl_request: null,
      missing_fields: [],
      provider_states: [],
      browser: null,
      primary_action: {
        kind: "connect_account",
        enabled: true,
        reason_code: "managed_connection_required",
      },
    })
    mocks.getTimeline.mockResolvedValue({ run_id: runId, items: [] })
    mocks.getRunOutput.mockRejectedValue(new Error("No output"))

    render(await RunDetailPage({ params: Promise.resolve({ runId }) }))

    expect(screen.getByText("Live run")).toBeInTheDocument()
    expect(screen.getByText("Existing Account")).toBeInTheDocument()
    expect(screen.getByText("Managed Auth")).toBeInTheDocument()
    expect(screen.getByText("Playwright")).toBeInTheDocument()
    expect(screen.getByRole("button", { name: "Connect account" })).toBeEnabled()
    expect(screen.queryByRole("button", { name: /retry/i })).not.toBeInTheDocument()
  })
})
