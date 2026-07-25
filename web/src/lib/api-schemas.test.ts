import { describe, expect, it, vi } from "vitest"

vi.mock("server-only", () => ({}))

import { appResearchResponseSchema, liveViewResponseSchema } from "@/lib/api-schemas"

const RUN_ID = "run_0123456789abcdef0123456789abcdef"

const explicitNullResponse = {
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
  provenance: {
    verified: true,
  },
}

describe("app research response schema", () => {
  it("accepts explicit nulls for nullable backend research fields", () => {
    const parsed = appResearchResponseSchema.safeParse(explicitNullResponse)

    expect(parsed.success).toBe(true)
    if (parsed.success) {
      expect(parsed.data.research.api_base_url).toBeNull()
      expect(parsed.data.research.contact_email).toBeNull()
    }
  })

  it("accepts legacy omitted-null research fields and normalizes them to null", () => {
    const legacy = structuredClone(explicitNullResponse) as typeof explicitNullResponse & {
      research: Record<string, unknown>
    }
    for (const field of [
      "api_available",
      "api_base_url",
      "authorization_url",
      "token_url",
      "developer_portal_url",
      "signup_url",
      "production_approval_required",
      "contact_email",
      "contact_url",
    ] as const) {
      delete legacy.research[field]
    }

    const parsed = appResearchResponseSchema.safeParse(legacy)

    expect(parsed.success).toBe(true)
    if (parsed.success) {
      expect(parsed.data.research.api_available).toBeNull()
      expect(parsed.data.research.api_base_url).toBeNull()
      expect(parsed.data.research.authorization_url).toBeNull()
      expect(parsed.data.research.token_url).toBeNull()
      expect(parsed.data.research.developer_portal_url).toBeNull()
      expect(parsed.data.research.signup_url).toBeNull()
      expect(parsed.data.research.production_approval_required).toBeNull()
      expect(parsed.data.research.contact_email).toBeNull()
      expect(parsed.data.research.contact_url).toBeNull()
    }
  })
})

describe("operational research contract synchronization", () => {
  it("accepts the full current backend research response", () => {
    const current = structuredClone(explicitNullResponse) as typeof explicitNullResponse & {
      research: Record<string, unknown>
    }
    current.research.credential_creation_instructions = [
      "Open Settings > Developer settings.",
      "Create a fine-grained personal access token.",
    ]
    current.research.login_url = "https://github.com/login"
    current.research.credential_management_url = "https://github.com/settings/tokens"
    current.research.operational_url_claims = [
      {
        field: "credential_management_url",
        url: "https://github.com/settings/tokens",
        source_url:
          "https://docs.github.com/en/rest/authentication/authenticating-to-the-rest-api",
      },
    ]

    const parsed = appResearchResponseSchema.safeParse(current)

    expect(parsed.success).toBe(true)
    if (parsed.success) {
      expect(parsed.data.research.login_url).toBe("https://github.com/login")
      expect(parsed.data.research.credential_management_url).toBe(
        "https://github.com/settings/tokens",
      )
      expect(parsed.data.research.credential_creation_instructions).toHaveLength(2)
      expect(parsed.data.research.operational_url_claims[0]?.field).toBe(
        "credential_management_url",
      )
    }
  })

  it("defaults the newer array and URL fields for an older response", () => {
    // The older backend omitted these fields entirely; they must normalize
    // rather than fail strict validation.
    const parsed = appResearchResponseSchema.safeParse(explicitNullResponse)

    expect(parsed.success).toBe(true)
    if (parsed.success) {
      expect(parsed.data.research.credential_creation_instructions).toEqual([])
      expect(parsed.data.research.operational_url_claims).toEqual([])
      expect(parsed.data.research.login_url).toBeNull()
      expect(parsed.data.research.credential_management_url).toBeNull()
    }
  })

  it("rejects an unknown operational URL claim field", () => {
    const drifted = structuredClone(explicitNullResponse) as typeof explicitNullResponse & {
      research: Record<string, unknown>
    }
    drifted.research.operational_url_claims = [
      {
        field: "totally_new_url",
        url: "https://github.com/settings/tokens",
        source_url: "https://docs.github.com/en/rest",
      },
    ]

    expect(appResearchResponseSchema.safeParse(drifted).success).toBe(false)
  })
})

describe("live view contract synchronization", () => {
  const hosted = {
    run_id: RUN_ID,
    provider: "browser_use",
    available: true,
    mode: "hosted_url",
    live_url: "https://live.browser-use.com/session/abc?token=opaque",
    interaction_available: true,
    reason_code: "hosted_session_live",
  }

  const screenshot = {
    run_id: RUN_ID,
    provider: "playwright",
    available: true,
    mode: "screenshot",
    screenshot_url: `/api/runs/${RUN_ID}/live-view/screenshot`,
    captured_at: "2026-07-25T10:00:00+00:00",
    interaction_available: false,
    reason_code: "screenshot_frames_available",
  }

  const unavailable = {
    run_id: RUN_ID,
    provider: "playwright",
    available: false,
    mode: "unavailable",
    interaction_available: false,
    reason_code: "no_active_browser_session",
  }

  it("accepts the Browser Use hosted view as interactive", () => {
    const parsed = liveViewResponseSchema.safeParse(hosted)

    expect(parsed.success).toBe(true)
    if (parsed.success) {
      expect(parsed.data.provider).toBe("browser_use")
      expect(parsed.data.mode).toBe("hosted_url")
      expect(parsed.data.interaction_available).toBe(true)
      expect(parsed.data.screenshot_url).toBeNull()
    }
  })

  it("accepts the Playwright screenshot view as non-interactive", () => {
    const parsed = liveViewResponseSchema.safeParse(screenshot)

    expect(parsed.success).toBe(true)
    if (parsed.success) {
      expect(parsed.data.provider).toBe("playwright")
      expect(parsed.data.interaction_available).toBe(false)
      expect(parsed.data.live_url).toBeNull()
    }
  })

  it("accepts an unavailable view with no viewer URL", () => {
    expect(liveViewResponseSchema.safeParse(unavailable).success).toBe(true)
  })

  it("rejects a mode whose matching viewer URL is missing", () => {
    expect(
      liveViewResponseSchema.safeParse({ ...hosted, live_url: null }).success,
    ).toBe(false)
    expect(
      liveViewResponseSchema.safeParse({ ...screenshot, screenshot_url: null }).success,
    ).toBe(false)
    expect(
      liveViewResponseSchema.safeParse({
        ...screenshot,
        mode: "interactive_remote",
        screenshot_url: null,
      }).success,
    ).toBe(false)
  })

  it("rejects an unavailable view that still carries a viewer URL", () => {
    expect(
      liveViewResponseSchema.safeParse({ ...unavailable, live_url: hosted.live_url }).success,
    ).toBe(false)
    expect(
      liveViewResponseSchema.safeParse({
        ...unavailable,
        screenshot_url: screenshot.screenshot_url,
      }).success,
    ).toBe(false)
  })

  it("rejects a screenshot view that claims interaction", () => {
    expect(
      liveViewResponseSchema.safeParse({ ...screenshot, interaction_available: true }).success,
    ).toBe(false)
  })

  it("rejects a private browser-service address as a viewer path", () => {
    for (const address of [
      "http://browser-worker:8081/vnc.html?session=pw_1&token=t",
      "https://browser-worker.opsnet/vnc.html",
      "http://127.0.0.1:6080/vnc.html",
    ]) {
      expect(
        liveViewResponseSchema.safeParse({ ...screenshot, screenshot_url: address }).success,
      ).toBe(false)
      expect(
        liveViewResponseSchema.safeParse({
          ...screenshot,
          mode: "interactive_remote",
          screenshot_url: null,
          interactive_url: address,
        }).success,
      ).toBe(false)
    }
  })

  it("rejects a viewer path that addresses a different run", () => {
    expect(
      liveViewResponseSchema.safeParse({
        ...screenshot,
        screenshot_url: "/api/runs/run_ffffffffffffffffffffffffffffffff/live-view/screenshot",
      }).success,
    ).toBe(false)
  })

  it("rejects an unknown provider or mode", () => {
    expect(liveViewResponseSchema.safeParse({ ...hosted, provider: "puppeteer" }).success).toBe(
      false,
    )
    expect(liveViewResponseSchema.safeParse({ ...hosted, mode: "video_stream" }).success).toBe(
      false,
    )
  })
})
