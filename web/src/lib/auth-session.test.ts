import { describe, expect, it } from "vitest"

import { authConfigurationValid } from "@/lib/auth-session"

const USERNAME = "operator"
const PASSWORD = "correct-password-for-ops-that-is-long" // pragma: allowlist secret
const SESSION_SECRET = "test-session-secret-that-is-longer-than-thirty-two-characters" // pragma: allowlist secret

describe("operator authentication configuration", () => {
  it("accepts three independently configured authentication values", () => {
    expect(authConfigurationValid(USERNAME, PASSWORD, SESSION_SECRET)).toBe(true)
  })

  it.each([
    ["password as the session signing key", PASSWORD, PASSWORD],
    ["public username as the password", USERNAME, SESSION_SECRET],
    ["public username as the session signing key", PASSWORD, USERNAME],
  ])("fails closed when authentication reuses %s", (_label, password, secret) => {
    expect(authConfigurationValid(USERNAME, password, secret)).toBe(false)
  })

  it("rejects a public username reused as a secret", () => {
    const publicIdentifier = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567" // pragma: allowlist secret
    expect(
      authConfigurationValid(
        publicIdentifier,
        `${publicIdentifier}-password`,
        publicIdentifier,
      ),
    ).toBe(false)
  })
})
