import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"

const mocks = vi.hoisted(() => ({
  cookies: vi.fn(),
  headers: vi.fn(),
  redirect: vi.fn(),
}))

vi.mock("next/headers", () => ({
  cookies: mocks.cookies,
  headers: mocks.headers,
}))
vi.mock("next/navigation", () => ({
  redirect: mocks.redirect,
}))

import { loginAction } from "@/app/login/actions"

function loginForm(password: string, totp = "000000"): FormData {
  const form = new FormData()
  form.set("username", "operator")
  form.set("password", password)
  form.set("totp", totp)
  form.set("next", "/")
  return form
}

describe("loginAction throttling", () => {
  beforeEach(() => {
    vi.stubEnv("OPS_AUTH_USERNAME", "operator")
    vi.stubEnv("OPS_AUTH_PASSWORD", "correct-password-for-ops")
    vi.stubEnv(
      "OPS_AUTH_SESSION_SECRET",
      "test-session-secret-that-is-longer-than-thirty-two-characters",
    )
    mocks.cookies.mockReset()
    mocks.headers.mockReset()
    mocks.redirect.mockReset()
    mocks.headers.mockResolvedValue(
      new Headers({ "x-forwarded-for": "203.0.113.77" }),
    )
    mocks.redirect.mockImplementation((destination: string) => {
      throw new Error(`NEXT_REDIRECT:${destination}`)
    })
  })

  afterEach(() => {
    vi.useRealTimers()
    vi.unstubAllEnvs()
  })

  it("temporarily blocks repeated failures without revealing credential identity", async () => {
    for (let attempt = 0; attempt < 4; attempt += 1) {
      await expect(loginAction(loginForm("wrong-password"))).rejects.toThrow(
        "error=invalid",
      )
    }

    await expect(loginAction(loginForm("wrong-password"))).rejects.toThrow(
      "error=rate_limited",
    )
    await expect(loginAction(loginForm("correct-password"))).rejects.toThrow(
      "error=rate_limited",
    )
    expect(mocks.cookies).not.toHaveBeenCalled()
  })

  it("grants a session on password match without requiring a second factor", async () => {
    vi.useFakeTimers()
    vi.setSystemTime(59_000)
    mocks.headers.mockResolvedValue(
      new Headers({ "x-forwarded-for": "203.0.113.88" }),
    )
    const setCookie = vi.fn()
    mocks.cookies.mockResolvedValue({ set: setCookie })

    await expect(
      loginAction(loginForm("correct-password-for-ops", "287082")),
    ).rejects.toThrow("NEXT_REDIRECT:/")
    expect(setCookie).toHaveBeenCalledOnce()
    expect(setCookie.mock.calls[0][0]).toBe("ops_session")
  })
})
