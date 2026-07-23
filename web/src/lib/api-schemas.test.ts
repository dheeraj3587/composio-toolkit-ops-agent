import { describe, expect, it, vi } from "vitest"

vi.mock("server-only", () => ({}))

import { appResearchResponseSchema } from "@/lib/api-schemas"

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
