import { describe, expect, it, vi } from "vitest"

vi.mock("server-only", () => ({}))

import {
  appResearchResponseSchema,
  browserUiStateSchema,
  liveViewResponseSchema,
  managedConnectionResponseSchema,
  providerProfileResponseSchema,
  runDetailResponseSchema,
  runSummarySchema,
} from "@/lib/api-schemas"

const RUN_ID = "run_0123456789abcdef0123456789abcdef"

const canonicalRun = {
  run_id: RUN_ID,
  thread_id: "thread_canonical_123",
  app_name: "GitHub",
  app_slug: "github",
  status: "connection_required",
  access_route: "self_serve",
  created_at: "2026-07-28T10:00:00Z",
  updated_at: "2026-07-28T10:01:00Z",
  execution_mode: "execute_when_configured",
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
}

describe("canonical route contracts", () => {
  it("accepts immutable recipe, route, provider, readiness, and state metadata", () => {
    const parsed = runSummarySchema.safeParse(canonicalRun)

    expect(parsed.success).toBe(true)
    if (parsed.success) {
      expect(parsed.data.status).toBe("connection_required")
      expect(parsed.data.route_kind).toBe("managed_auth")
      expect(parsed.data.recipe_version).toBe("2026-07-28.v1")
      expect(parsed.data.state_engine).toBe("canonical_v1")
    }
  })

  it("defaults new metadata only for a structurally valid legacy response", () => {
    const legacy = { ...canonicalRun }
    for (const field of [
      "recipe_version",
      "route_kind",
      "readiness_tier",
      "attempt",
      "phase",
      "reason_code",
      "state_engine",
    ] as const) {
      delete legacy[field]
    }

    const parsed = runSummarySchema.safeParse({ ...legacy, status: "completed" })
    expect(parsed.success).toBe(true)
    if (parsed.success) {
      expect(parsed.data.recipe_version).toBeNull()
      expect(parsed.data.route_kind).toBeNull()
      expect(parsed.data.phase).toBe("legacy")
      expect(parsed.data.state_engine).toBe("legacy")
    }
  })

  it("accepts one strict backend-authorized primary action", () => {
    const parsed = runDetailResponseSchema.safeParse({
      run: canonicalRun,
      research: null,
      phases: null,
      security: null,
      primary_action: {
        kind: "connect_account",
        enabled: true,
        reason_code: "managed_connection_required",
      },
    })

    expect(parsed.success).toBe(true)
    if (parsed.success) {
      expect(parsed.data.primary_action?.kind).toBe("connect_account")
    }
    expect(
      runDetailResponseSchema.safeParse({
        run: canonicalRun,
        research: null,
        phases: null,
        security: null,
        primary_action: {
          kind: "invented_action",
          enabled: true,
          reason_code: "drift",
        },
      }).success,
    ).toBe(false)
  })

  it("accepts the onboarding projections and the sanitized profile", () => {
    // GET /api/runs/{id} does not exclude nulls, so absent optional fields
    // arrive as explicit nulls; the profile route does exclude them.
    const detail = runDetailResponseSchema.safeParse({
      run: canonicalRun,
      research: null,
      phases: null,
      security: null,
      route_decision: null,
      hitl_request: null,
      browser: null,
      primary_action: null,
      onboarding: {
        phase: "developer_app",
        phase_at_pause: null,
        profile_digest: "a".repeat(64),
        reason_code: "developer_app_created",
        goal: "Create a developer application",
        step: "Filling the application form",
        latest_decision: "Opening the developer portal",
        attempt: 1,
        admission_prompts: 1,
        captcha_prompts: 0,
        correlation_id: "corr_01",
      },
      controls: {
        can_decide_admission: false,
        can_pause: true,
        can_resume: false,
        can_cancel: true,
        can_reset: true,
        can_retry_step: true,
        retryable_step: "developer_app",
        reason_code: "developer_app_created",
      },
      autonomy: null,
    })

    expect(detail.success).toBe(true)
    if (detail.success) {
      expect(detail.data.onboarding?.phase).toBe("developer_app")
      expect(detail.data.controls?.retryable_step).toBe("developer_app")
      expect(detail.data.autonomy).toBeNull()
    }

    const profile = providerProfileResponseSchema.safeParse({
      run_id: RUN_ID,
      profile_digest: "b".repeat(64),
      provider_name: "GitHub",
      app_slug: "github",
      registrable_domain: "github.com",
      allowed_host_patterns: ["*.github.com"],
      auxiliary_hosts: [{ host: "accounts.google.com", kind: "identity_provider" }],
      developer_portal_url: "https://github.com/settings/developers",
      flows: [
        {
          kind: "developer_app",
          supported: true,
          entry_url: "https://github.com/settings/apps/new",
          steps: ["Open the new app form."],
          produces: ["oauth_client_id"],
        },
      ],
      approval_requirement: "unknown",
      billing_requirement: "unknown",
      evidence: [
        {
          field: "developer_portal_url",
          value: "https://github.com/settings/developers",
          source_url: "https://docs.github.com/en/apps",
          source_digest: "c".repeat(64),
          adapters: ["perplexity_search"],
          corroborations: 2,
          confidence: 0.9,
        },
      ],
      confidence: 0.92,
      built_at: "2026-07-28T10:00:00Z",
    })

    expect(profile.success).toBe(true)
    if (profile.success) {
      // Requirement 9.9: unknown stays unknown across the wire.
      expect(profile.data.approval_requirement).toBe("unknown")
      expect(profile.data.billing_requirement).toBe("unknown")
      expect(profile.data.signup_url).toBeNull()
      expect(profile.data.flows[0]?.requires_approval).toBe(false)
    }
  })

  it("accepts an ephemeral HTTPS provider redirect and rejects unsafe redirects", () => {
    const response = {
      run: canonicalRun,
      connection_request_id: "conn_request_123",
      state: "pending",
      redirect_url: "https://accounts.example.com/oauth/authorize?state=opaque&token=opaque",
      replayed: false,
    }

    expect(managedConnectionResponseSchema.safeParse(response).success).toBe(true)
    expect(
      managedConnectionResponseSchema.safeParse({
        ...response,
        redirect_url: "http://accounts.example.com/oauth/authorize",
      }).success,
    ).toBe(false)
    expect(
      managedConnectionResponseSchema.safeParse({
        ...response,
        redirect_url: "https://user:password@accounts.example.com/oauth/authorize", // pragma: allowlist secret
      }).success,
    ).toBe(false)
  })
})

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

  const interactive = {
    run_id: RUN_ID,
    provider: "playwright",
    available: true,
    mode: "interactive_remote",
    interactive_url:
      "http://browser-worker:8081/internal/browser/live-view/novnc?session=pw_session_1&token=signed-grant",
    interaction_available: true,
    reason_code: "interactive_hitl_available",
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

  it("accepts only the reviewed private Playwright interactive grant", () => {
    const parsed = liveViewResponseSchema.safeParse(interactive)

    expect(parsed.success).toBe(true)
    if (parsed.success) {
      expect(parsed.data.mode).toBe("interactive_remote")
      expect(parsed.data.interactive_url).toBe(interactive.interactive_url)
      expect(parsed.data.interaction_available).toBe(true)
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
        ...interactive,
        interactive_url: null,
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

  it("rejects every interactive address except the exact reviewed private grant", () => {
    for (const address of [
      "http://browser-worker:8081/vnc.html?session=pw_1&token=t",
      "http://browser-worker:8081/internal/browser/live-view/novnc?session=pw_1&token=t&extra=1",
      "http://browser-worker:8081/internal/browser/live-view/novnc?session=bad%2Fsession&token=t",
      "http://browser-worker:8081/internal/browser/live-view/novnc?session=pw_1&token=t%0Ainjected",
      "https://browser-worker.opsnet/vnc.html",
      "http://127.0.0.1:6080/vnc.html",
      `/api/runs/${RUN_ID}/live-view/interactive`,
    ]) {
      expect(
        liveViewResponseSchema.safeParse({ ...screenshot, screenshot_url: address }).success,
      ).toBe(false)
      expect(
        liveViewResponseSchema.safeParse({
          ...interactive,
          interactive_url: address,
        }).success,
      ).toBe(false)
    }
  })

  it("accepts an interactive grant with server-enforced read-only access", () => {
    expect(
      liveViewResponseSchema.safeParse({
        ...interactive,
        interaction_available: false,
      }).success,
    ).toBe(true)
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

describe("browser UI state contract", () => {
  const browser = {
    provider: "playwright",
    lifecycle: "running",
    live_view_mode: "screenshot",
    live_view_available: true,
    interaction_available: false,
    screenshot_available: true,
    credential_page_verified: false,
    can_submit_login: false,
    can_submit_otp: false,
    can_resume: false,
    can_submit_credential: false,
    reason_code: "browser_session_running",
  }

  it("accepts the backend-authoritative capability payload", () => {
    const parsed = browserUiStateSchema.safeParse(browser)

    expect(parsed.success).toBe(true)
    if (parsed.success) {
      expect(parsed.data.provider).toBe("playwright")
      expect(parsed.data.interaction_available).toBe(false)
      expect(parsed.data.can_submit_credential).toBe(false)
    }
  })

  it("defaults every capability to false when the backend omits it", () => {
    const parsed = browserUiStateSchema.safeParse({
      provider: "browser_use",
      lifecycle: "not_started",
      live_view_mode: "unavailable",
    })

    expect(parsed.success).toBe(true)
    if (parsed.success) {
      expect(parsed.data.live_view_available).toBe(false)
      expect(parsed.data.can_resume).toBe(false)
      expect(parsed.data.credential_page_verified).toBe(false)
      expect(parsed.data.reason_code).toBeNull()
    }
  })

  it("rejects an unknown lifecycle or extra capability key", () => {
    expect(
      browserUiStateSchema.safeParse({ ...browser, lifecycle: "totally_new" }).success,
    ).toBe(false)
    expect(
      browserUiStateSchema.safeParse({ ...browser, can_do_anything: true }).success,
    ).toBe(false)
  })
})
