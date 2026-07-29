import { NextRequest } from "next/server"
import { afterEach, describe, expect, it, vi } from "vitest"

import { proxy } from "@/proxy"

describe("authentication proxy boundary", () => {
  afterEach(() => vi.unstubAllEnvs())

  it("does not make dynamic routes public because their slug looks like an asset", async () => {
    vi.stubEnv("OPS_AUTH_USERNAME", "")
    vi.stubEnv("OPS_AUTH_PASSWORD", "")
    vi.stubEnv("OPS_AUTH_SESSION_SECRET", "")
    vi.stubEnv("OPS_AUTH_TOTP_SECRET", "")

    const response = await proxy(
      new NextRequest("https://ops.example.test/apps/github.js"),
    )

    expect(response.status).toBe(307)
    expect(response.headers.get("location")).toContain("/login")
  })

  it("keeps only explicit login, health, and Next asset paths public", async () => {
    for (const pathname of ["/login", "/health", "/_next/static/chunk.js"]) {
      const response = await proxy(
        new NextRequest(`https://ops.example.test${pathname}`),
      )
      expect(response.status).toBe(200)
    }
  })
})
