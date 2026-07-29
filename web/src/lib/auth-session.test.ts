import { describe, expect, it } from "vitest"

import { authConfigurationValid } from "@/lib/auth-session"

const USERNAME = "operator"
const PASSWORD = "correct-password-for-ops-that-is-long" // pragma: allowlist secret
const SESSION_SECRET = "test-session-secret-that-is-longer-than-thirty-two-characters" // pragma: allowlist secret
const TOTP_SECRET = "JBSWY3DPEHPK3PXP" // pragma: allowlist secret

describe("operator authentication configuration", () => {
  it("accepts four independently configured authentication values", () => {
    expect(
      authConfigurationValid(USERNAME, PASSWORD, SESSION_SECRET, TOTP_SECRET),
    ).toBe(true)
  })

  it.each([
    ["password as the session signing key", PASSWORD, PASSWORD, TOTP_SECRET],
    [
      "TOTP seed as the password",
      "jbs wy3d pehpk3pxp jbs wy3d pehpk3pxp",
      SESSION_SECRET,
      `${TOTP_SECRET}${TOTP_SECRET}`,
    ],
    [
      "TOTP seed as the session signing key",
      PASSWORD,
      `${TOTP_SECRET}${TOTP_SECRET}`,
      `${TOTP_SECRET} ${TOTP_SECRET}`,
    ],
  ])("fails closed when authentication reuses %s", (_label, password, secret, totp) => {
    expect(authConfigurationValid(USERNAME, password, secret, totp)).toBe(false)
  })

  it("rejects a public username reused as a secret", () => {
    const publicIdentifier = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567" // pragma: allowlist secret
    expect(
      authConfigurationValid(
        publicIdentifier,
        `${publicIdentifier}-password`,
        publicIdentifier,
        TOTP_SECRET,
      ),
    ).toBe(false)
  })
})
