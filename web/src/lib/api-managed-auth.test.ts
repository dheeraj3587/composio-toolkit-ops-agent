import { beforeEach, describe, expect, it, vi } from "vitest"

vi.mock("server-only", () => ({}))

import { connectManagedRun, pollManagedConnection } from "@/lib/api"

const RUN_ID = "run_0123456789abcdef0123456789abcdef"
const response = {
  run: {
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
  },
  connection_request_id: "conn_request_123",
  state: "pending",
  redirect_url: "https://accounts.example.com/oauth/authorize?state=opaque",
  replayed: false,
}

describe("managed-auth API client", () => {
  const fetchMock = vi.fn()

  beforeEach(() => {
    fetchMock.mockReset()
    vi.stubGlobal("fetch", fetchMock)
    vi.stubEnv("OPS_API_URL", "http://127.0.0.1:8000")
    vi.stubEnv("OPS_INTERNAL_API_TOKEN", "internal-test-token")
    fetchMock.mockResolvedValue(
      new Response(JSON.stringify(response), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    )
  })

  it("posts to the managed connection endpoint without persisting a provider URL", async () => {
    const result = await connectManagedRun(RUN_ID)

    expect(result.redirect_url).toBe(response.redirect_url)
    expect(fetchMock).toHaveBeenCalledWith(
      `http://127.0.0.1:8000/api/runs/${RUN_ID}/connect`,
      expect.objectContaining({
        method: "POST",
        cache: "no-store",
        headers: expect.objectContaining({ "X-Ops-Internal-Token": "internal-test-token" }),
      }),
    )
    expect(fetchMock.mock.calls[0]?.[1]).not.toHaveProperty("body")
  })

  it("polls only the stored managed connection request", async () => {
    await pollManagedConnection(RUN_ID)

    expect(fetchMock.mock.calls[0]?.[0]).toBe(
      `http://127.0.0.1:8000/api/runs/${RUN_ID}/poll-connection`,
    )
    expect(fetchMock.mock.calls[0]?.[1]).toMatchObject({ method: "POST", cache: "no-store" })
  })
})
