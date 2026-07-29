import { describe, expect, it } from "vitest"

import { matchTotpStep, totpConfigurationValid } from "@/lib/totp"

describe("operator TOTP", () => {
  it("validates a known RFC 6238 counter and rejects malformed secrets", () => {
    const secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ" // pragma: allowlist secret
    const now = 59

    expect(totpConfigurationValid(secret)).toBe(true)
    expect(totpConfigurationValid("not-base32")).toBe(false)
    // RFC 6238's SHA-1 vector at t=59 is 94287082; six-digit TOTP keeps
    // the least-significant six digits.
    expect(matchTotpStep("287082", secret, now)).toBe(1)
    expect(matchTotpStep("287083", secret, now)).toBeNull()
    expect(matchTotpStep("not-a-code", secret, now)).toBeNull()
  })
})
