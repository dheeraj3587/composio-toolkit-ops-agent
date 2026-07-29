import { createHmac, timingSafeEqual } from "node:crypto"

const TOTP_PERIOD_SECONDS = 30
const TOTP_DIGITS = 6
const BASE32_PATTERN = /^[A-Z2-7]+={0,6}$/u

function decodeBase32(value: string): Buffer | null {
  const normalized = value.trim().replaceAll(" ", "").toUpperCase()
  if (
    normalized.length < 16 ||
    normalized.length > 128 ||
    !BASE32_PATTERN.test(normalized)
  ) {
    return null
  }

  const unpadded = normalized.replace(/=+$/u, "")
  let bits = 0
  let accumulator = 0
  const output: number[] = []
  for (const character of unpadded) {
    const index = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".indexOf(character) // pragma: allowlist secret
    if (index < 0) return null
    accumulator = (accumulator << 5) | index
    bits += 5
    if (bits >= 8) {
      bits -= 8
      output.push((accumulator >>> bits) & 0xff)
    }
  }
  return output.length >= 10 ? Buffer.from(output) : null
}

export function totpConfigurationValid(secret: string | undefined): boolean {
  return Boolean(secret && decodeBase32(secret))
}

function codeForStep(secret: Buffer, step: number): string {
  const counter = Buffer.alloc(8)
  counter.writeBigUInt64BE(BigInt(step))
  const digest = createHmac("sha1", secret).update(counter).digest()
  const offset = digest[digest.length - 1]! & 0x0f
  const binary =
    ((digest[offset]! & 0x7f) << 24) |
    ((digest[offset + 1]! & 0xff) << 16) |
    ((digest[offset + 2]! & 0xff) << 8) |
    (digest[offset + 3]! & 0xff)
  return String(binary % (10 ** TOTP_DIGITS)).padStart(TOTP_DIGITS, "0")
}

function secureCodeEqual(candidate: string, expected: string): boolean {
  const candidateBuffer = Buffer.from(candidate.padEnd(TOTP_DIGITS, "\0"), "utf8")
  const expectedBuffer = Buffer.from(expected, "utf8")
  return (
    candidate.length === TOTP_DIGITS &&
    candidateBuffer.length === expectedBuffer.length &&
    timingSafeEqual(candidateBuffer, expectedBuffer)
  )
}

/**
 * Return the matched 30-second counter, allowing one adjacent window for clock
 * skew. Callers persist the returned counter to reject same-code replay.
 */
export function matchTotpStep(
  candidate: string,
  encodedSecret: string,
  nowSeconds = Math.floor(Date.now() / 1_000),
): number | null {
  const secret = decodeBase32(encodedSecret)
  const wellFormed = /^\d{6}$/u.test(candidate)
  if (!secret) return null

  const currentStep = Math.floor(nowSeconds / TOTP_PERIOD_SECONDS)
  let matched: number | null = null
  for (const delta of [-1, 0, 1]) {
    const step = currentStep + delta
    const expected = codeForStep(secret, step)
    if (secureCodeEqual(wellFormed ? candidate : "", expected)) matched = step
  }
  return matched
}
