import { render, screen } from "@testing-library/react"

const mocks = vi.hoisted(() => ({
  getAppResearch: vi.fn(),
  notFound: vi.fn(),
}))

vi.mock("next/server", () => ({ connection: vi.fn(async () => undefined) }))
vi.mock("next/navigation", () => ({
  notFound: mocks.notFound,
}))
vi.mock("@/lib/api", () => ({
  ApiError: class ApiError extends Error {
    constructor(
      public readonly status: number,
      public readonly code = `HTTP_${status}`,
    ) {
      super("API error")
    }
  },
  getAppResearch: mocks.getAppResearch,
}))

import AppResearchPage from "@/app/apps/[slug]/page"
import { ApiError } from "@/lib/api"

function responseFor(appSlug: "github" | "pipedrive") {
  if (appSlug === "github") {
    return {
      app: {
        app_name: "GitHub",
        app_slug: "github",
        category: "DevInfra",
        api_type: "REST",
        access_route: "self_serve",
        auth_methods: ["Personal Access Token", "OAuth2"],
        confidence: 0.95,
        buildability: "Easy",
        verification_status: "Hand-Checked",
      },
      research: {
        app_name: "GitHub",
        app_slug: "github",
        api_available: null,
        api_type: "REST",
        api_base_url: null,
        auth_methods: ["Personal Access Token", "OAuth2"],
        authorization_url: null,
        token_url: null,
        credential_fields: [],
        scopes: [],
        developer_portal_url: null,
        signup_url: null,
        access_route: "self_serve",
        production_approval_required: null,
        contact_email: null,
        contact_url: null,
        evidence_urls: ["https://docs.github.com/en/rest/authentication/authenticating-to-the-rest-api"],
        confidence: 0.95,
        source: "p1_snapshot",
        missing_fields: [],
      },
      provenance: { verified: true },
    }
  }

  return {
    app: {
      app_name: "Pipedrive",
      app_slug: "pipedrive",
      category: "CRM",
      api_type: "REST",
      access_route: "self_serve",
      auth_methods: ["OAuth2", "API Key"],
      confidence: 0.95,
      buildability: "Easy",
      verification_status: "Auto",
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
      developer_portal_url: null,
      signup_url: null,
      access_route: "self_serve",
      production_approval_required: null,
      contact_email: null,
      contact_url: null,
      evidence_urls: [
        "https://developers.pipedrive.com/docs/api/v1",
        "https://developers.pipedrive.com/docs/api/v1/Oauth",
      ],
      confidence: 0.95,
      source: "p1_snapshot",
      missing_fields: [],
    },
    provenance: { verified: true },
  }
}

describe("AppResearchPage", () => {
  beforeEach(() => {
    mocks.getAppResearch.mockReset()
    mocks.notFound.mockReset()
    mocks.notFound.mockImplementation(() => {
      throw new Error("NEXT_NOT_FOUND")
    })
  })

  it("renders the actual GitHub P1 profile without assigning browser runtime support", async () => {
    mocks.getAppResearch.mockResolvedValue(responseFor("github"))

    render(await AppResearchPage({ params: Promise.resolve({ slug: "github" }) }))

    expect(mocks.getAppResearch).toHaveBeenCalledWith("github")
    expect(screen.getByRole("heading", { name: "GitHub", level: 1 })).toBeInTheDocument()
    expect(screen.getByText("github")).toBeInTheDocument()
    expect(screen.getAllByText("Self Serve").length).toBeGreaterThan(0)
    expect(screen.getAllByText("Personal Access Token").length).toBeGreaterThan(0)
    expect(
      screen.getByRole("link", {
        name: /docs\.github\.com\/en\/rest\/authentication\/authenticating-to-the-rest-api/i,
      }),
    ).toHaveAttribute("href", "https://docs.github.com/en/rest/authentication/authenticating-to-the-rest-api")
    expect(screen.queryByText(/browser use.*ready/i)).not.toBeInTheDocument()
    expect(screen.queryByText(/unsupported/i)).not.toBeInTheDocument()
  })

  it("renders the actual Pipedrive P1 profile", async () => {
    mocks.getAppResearch.mockResolvedValue(responseFor("pipedrive"))

    render(await AppResearchPage({ params: Promise.resolve({ slug: "pipedrive" }) }))

    expect(mocks.getAppResearch).toHaveBeenCalledWith("pipedrive")
    expect(screen.getByRole("heading", { name: "Pipedrive", level: 1 })).toBeInTheDocument()
    expect(screen.getByText("pipedrive")).toBeInTheDocument()
    expect(screen.getAllByText("API Key").length).toBeGreaterThan(0)
    expect(
      screen
        .getAllByRole("link", { name: /developers\.pipedrive\.com\/docs\/api\/v1/i })
        .map((link) => link.getAttribute("href")),
    ).toContain("https://developers.pipedrive.com/docs/api/v1")
  })

  it("returns the not-found state for a genuine unknown app", async () => {
    mocks.getAppResearch.mockRejectedValue(new ApiError(404, "HTTP_404"))

    await expect(AppResearchPage({ params: Promise.resolve({ slug: "not-a-real-app" }) })).rejects.toThrow(
      "NEXT_NOT_FOUND",
    )
  })

  it("shows a response-contract mismatch state for invalid API responses", async () => {
    mocks.getAppResearch.mockRejectedValue(new ApiError(502, "INVALID_API_RESPONSE"))

    render(await AppResearchPage({ params: Promise.resolve({ slug: "github" }) }))

    expect(screen.getByRole("heading", { name: "Response contract mismatch" })).toBeInTheDocument()
    expect(screen.getByText(/does not match the frontend contract/i)).toBeInTheDocument()
  })

  it("shows a backend-unavailable state for unreachable API failures", async () => {
    mocks.getAppResearch.mockRejectedValue(new ApiError(503, "API_UNREACHABLE"))

    render(await AppResearchPage({ params: Promise.resolve({ slug: "github" }) }))

    expect(screen.getByRole("heading", { name: "Backend unavailable" })).toBeInTheDocument()
    expect(screen.getByText(/operations api is unreachable/i)).toBeInTheDocument()
  })
})
