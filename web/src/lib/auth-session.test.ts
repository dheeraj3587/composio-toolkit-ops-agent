import { describe, expect, it } from "vitest"

import { authConfigurationValid } from "@/lib/auth-session"

const USERNAME = "operator"
const PASSWORD = "correct-password-for-ops-that-is-long" // pragma: allowlist secret
const SESSION_SECRET = "test-session-secret-that-is-longer-than-thirty-two-characters" // pragma: allowlist secret

describe("operator authentication configuration", () => {
  it("accepts three independently configured authentication values", () => {
    expect(authConfigurationValid(USERNAME, PASSWORD, SESSION_SECRET)).toBe(true)
  })

  it("fails closed when the password is reused as the session signing key", () => {
    expect(authConfigurationValid(USERNAME, PASSWORD, PASSWORD)).toBe(false)
  })

  it("fails closed when the username is reused as the session signing key", () => {
    expect(authConfigurationValid(USERNAME, PASSWORD, USERNAME)).toBe(false)
  })

  it("rejects a public username reused as a session secret", () => {
    const publicIdentifier = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567" // pragma: allowlist secret
    expect(
      authConfigurationValid(
        publicIdentifier,
        `${publicIdentifier}-password`,
        publicIdentifier,
      ),
    ).toBe(false)
  })

  it("rejects an under-length password", () => {
    expect(authConfigurationValid(USERNAME, "short", SESSION_SECRET)).toBe(false)
  })

  it("rejects an under-length session secret", () => {
    expect(authConfigurationValid(USERNAME, PASSWORD, "too-short-secret")).toBe(false)
  })

  it("rejects when any required value is missing", () => {
    expect(authConfigurationValid(USERNAME, undefined, SESSION_SECRET)).toBe(false)
    expect(authConfigurationValid(undefined, PASSWORD, SESSION_SECRET)).toBe(false)
    expect(authConfigurationValid(USERNAME, PASSWORD, undefined)).toBe(false)
  })
})
