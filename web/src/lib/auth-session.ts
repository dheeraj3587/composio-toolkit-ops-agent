import { totpConfigurationValid } from "@/lib/totp"

export const AUTH_COOKIE_NAME = "ops_session"
export const AUTH_SESSION_SECONDS = 60 * 60 * 12

interface SessionPayload {
  sub: string
  iat: number
  exp: number
}

const encoder = new TextEncoder()
const decoder = new TextDecoder()

function base64UrlEncode(bytes: Uint8Array): string {
  let binary = ""
  for (const byte of bytes) binary += String.fromCharCode(byte)
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/u, "")
}

function base64UrlDecode(value: string): Uint8Array<ArrayBuffer> | null {
  if (!/^[A-Za-z0-9_-]+$/u.test(value)) return null
  try {
    const padded = value.replaceAll("-", "+").replaceAll("_", "/").padEnd(
      Math.ceil(value.length / 4) * 4,
      "=",
    )
    const binary = atob(padded)
    const bytes = new Uint8Array(new ArrayBuffer(binary.length))
    for (let index = 0; index < binary.length; index += 1) {
      bytes[index] = binary.charCodeAt(index)
    }
    return bytes
  } catch {
    return null
  }
}

async function signingKey(secret: string): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"],
  )
}

export function authConfigurationValid(
  username: string | undefined,
  password: string | undefined,
  secret: string | undefined,
  totpSecret: string | undefined,
): boolean {
  const configuredValues = [username?.trim(), password, secret, totpSecret?.trim()]
  const canonicalValues = configuredValues.map((value) =>
    value?.replaceAll(" ", "").toUpperCase(),
  )
  const independent =
    canonicalValues.every((value): value is string => Boolean(value)) &&
    new Set(canonicalValues).size === canonicalValues.length

  return Boolean(
    username?.trim() &&
      password &&
      password.length >= 20 &&
      secret &&
      secret.length >= 32 &&
      totpConfigurationValid(totpSecret) &&
      independent,
  )
}

export async function createAuthSession(
  username: string,
  secret: string,
  nowSeconds = Math.floor(Date.now() / 1_000),
): Promise<string> {
  const payload: SessionPayload = {
    sub: username,
    iat: nowSeconds,
    exp: nowSeconds + AUTH_SESSION_SECONDS,
  }
  const encodedPayload = base64UrlEncode(encoder.encode(JSON.stringify(payload)))
  const signature = new Uint8Array(
    await crypto.subtle.sign("HMAC", await signingKey(secret), encoder.encode(encodedPayload)),
  )
  return `${encodedPayload}.${base64UrlEncode(signature)}`
}

export async function verifyAuthSession(
  token: string | undefined,
  expectedUsername: string,
  secret: string,
  nowSeconds = Math.floor(Date.now() / 1_000),
): Promise<boolean> {
  if (!token || token.length > 2_048) return false
  const [encodedPayload, encodedSignature, ...rest] = token.split(".")
  if (!encodedPayload || !encodedSignature || rest.length > 0) return false

  const payloadBytes = base64UrlDecode(encodedPayload)
  const signature = base64UrlDecode(encodedSignature)
  if (!payloadBytes || !signature) return false

  const signatureValid = await crypto.subtle.verify(
    "HMAC",
    await signingKey(secret),
    signature,
    encoder.encode(encodedPayload),
  )
  if (!signatureValid) return false

  try {
    const payload = JSON.parse(decoder.decode(payloadBytes)) as Partial<SessionPayload>
    return (
      payload.sub === expectedUsername &&
      Number.isInteger(payload.iat) &&
      Number.isInteger(payload.exp) &&
      (payload.iat as number) <= nowSeconds + 60 &&
      (payload.exp as number) > nowSeconds &&
      (payload.exp as number) - (payload.iat as number) === AUTH_SESSION_SECONDS
    )
  } catch {
    return false
  }
}
