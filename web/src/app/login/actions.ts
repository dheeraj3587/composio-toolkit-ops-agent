"use server"

import { createHash, timingSafeEqual } from "node:crypto"

import { cookies, headers } from "next/headers"
import { redirect } from "next/navigation"

import {
  AUTH_COOKIE_NAME,
  AUTH_SESSION_SECONDS,
  authConfigurationValid,
  createAuthSession,
} from "@/lib/auth-session"
import { matchTotpStep } from "@/lib/totp"

const THROTTLE_WINDOW_MS = 10 * 60 * 1_000
const INITIAL_LOCKOUT_MS = 30 * 1_000
const MAX_LOCKOUT_MS = 15 * 60 * 1_000
const IDENTITY_FAILURE_LIMIT = 5
const ADDRESS_FAILURE_LIMIT = 12
const MAX_TRACKED_ATTEMPTS = 10_000

interface LoginAttempt {
  failures: number
  windowStartedAt: number
  blockedUntil: number
  lastSeenAt: number
}

// This deployment has one web container. Keep the emergency login boundary
// bounded in-process; a multi-replica deployment must replace this with a shared
// limiter at the ingress or session store.
const loginAttempts = new Map<string, LoginAttempt>()
const acceptedTotpSteps = new Map<string, number>()

function safeDestination(value: FormDataEntryValue | null): string {
  if (
    typeof value === "string" &&
    value.startsWith("/") &&
    !value.startsWith("//") &&
    !value.includes("\\") &&
    value.length <= 1_024
  ) {
    return value
  }
  return "/"
}

function secureEqual(candidate: string, expected: string): boolean {
  const candidateDigest = createHash("sha256").update(candidate, "utf8").digest()
  const expectedDigest = createHash("sha256").update(expected, "utf8").digest()
  return timingSafeEqual(candidateDigest, expectedDigest)
}

function throttleKey(kind: "address" | "identity", ...values: string[]): string {
  return createHash("sha256")
    .update([kind, ...values].join("\u0000"), "utf8")
    .digest("hex")
}

function requestAddress(requestHeaders: Headers): string {
  const forwarded = requestHeaders.get("x-forwarded-for")?.split(",", 1)[0]?.trim()
  const value = forwarded || requestHeaders.get("x-real-ip")?.trim() || "unknown"
  return value.slice(0, 200)
}

function pruneAttempts(now: number): void {
  for (const [key, attempt] of loginAttempts) {
    if (
      attempt.blockedUntil <= now &&
      now - attempt.lastSeenAt >= THROTTLE_WINDOW_MS
    ) {
      loginAttempts.delete(key)
    }
  }
  while (loginAttempts.size >= MAX_TRACKED_ATTEMPTS) {
    const oldest = loginAttempts.keys().next().value as string | undefined
    if (!oldest) break
    loginAttempts.delete(oldest)
  }
}

function touchAttempt(key: string, attempt: LoginAttempt): void {
  loginAttempts.delete(key)
  while (loginAttempts.size >= MAX_TRACKED_ATTEMPTS) {
    const oldest = loginAttempts.keys().next().value as string | undefined
    if (!oldest) break
    loginAttempts.delete(oldest)
  }
  loginAttempts.set(key, attempt)
}

function retryAfterSeconds(keys: string[], now: number): number {
  let retryAfterMs = 0
  for (const key of keys) {
    const attempt = loginAttempts.get(key)
    if (!attempt) continue
    attempt.lastSeenAt = now
    touchAttempt(key, attempt)
    retryAfterMs = Math.max(retryAfterMs, attempt.blockedUntil - now)
  }
  return Math.max(0, Math.ceil(retryAfterMs / 1_000))
}

function recordFailure(key: string, limit: number, now: number): number {
  const current = loginAttempts.get(key)
  const expired = !current || now - current.windowStartedAt >= THROTTLE_WINDOW_MS
  const attempt: LoginAttempt = expired
    ? { failures: 0, windowStartedAt: now, blockedUntil: 0, lastSeenAt: now }
    : current

  attempt.failures += 1
  attempt.lastSeenAt = now
  if (attempt.failures >= limit) {
    const escalation = Math.min(attempt.failures - limit, 5)
    const lockout = Math.min(INITIAL_LOCKOUT_MS * (2 ** escalation), MAX_LOCKOUT_MS)
    attempt.blockedUntil = Math.max(attempt.blockedUntil, now + lockout)
  }
  touchAttempt(key, attempt)
  return Math.max(0, Math.ceil((attempt.blockedUntil - now) / 1_000))
}

function rateLimitedDestination(destination: string, retryAfter: number): string {
  return `/login?error=rate_limited&retry_after=${Math.min(retryAfter, 900)}&next=${encodeURIComponent(destination)}`
}

export async function loginAction(formData: FormData): Promise<void> {
  const configuredUsername = process.env.OPS_AUTH_USERNAME
  const configuredPassword = process.env.OPS_AUTH_PASSWORD
  const sessionSecret = process.env.OPS_AUTH_SESSION_SECRET
  const totpSecret = process.env.OPS_AUTH_TOTP_SECRET
  const destination = safeDestination(formData.get("next"))

  if (
    !authConfigurationValid(
      configuredUsername,
      configuredPassword,
      sessionSecret,
      totpSecret,
    )
  ) {
    redirect(`/login?error=configuration&next=${encodeURIComponent(destination)}`)
  }

  const username = formData.get("username")
  const password = formData.get("password")
  const totp = formData.get("totp")
  const usernameWellFormed = typeof username === "string" && username.length <= 320
  const passwordWellFormed =
    typeof password === "string" && // pragma: allowlist secret
    password.length <= 1_024
  const usernameCandidate =
    usernameWellFormed && typeof username === "string" ? username : ""
  const passwordCandidate =
    passwordWellFormed && typeof password === "string" ? password : "" // pragma: allowlist secret
  const totpWellFormed = typeof totp === "string" && /^\d{6}$/u.test(totp)
  const totpCandidate = totpWellFormed && typeof totp === "string" ? totp : ""

  // Evaluate both comparisons for every well-formed or malformed submission so
  // username validity does not change the amount of credential work performed.
  const usernameValid = secureEqual(usernameCandidate, configuredUsername!.trim())
  const passwordValid = secureEqual(passwordCandidate, configuredPassword!)

  const now = Date.now()
  pruneAttempts(now)
  const address = requestAddress(await headers())
  const addressKey = throttleKey("address", address)
  const identityKey = throttleKey("identity", address, usernameCandidate.toLocaleLowerCase("en-US"))
  const attemptKeys = [addressKey, identityKey]
  const blockedFor = retryAfterSeconds(attemptKeys, now)
  if (blockedFor > 0) {
    redirect(rateLimitedDestination(destination, blockedFor))
  }

  const matchedTotpStep = matchTotpStep(
    totpCandidate,
    totpSecret!,
    Math.floor(now / 1_000),
  )
  const lastAcceptedStep = acceptedTotpSteps.get(configuredUsername!.trim()) ?? -1
  const totpValid =
    totpWellFormed &&
    matchedTotpStep !== null &&
    matchedTotpStep > lastAcceptedStep
  const valid =
    usernameWellFormed &&
    passwordWellFormed &&
    usernameValid &&
    passwordValid &&
    totpValid

  if (!valid) {
    const retryAfter = Math.max(
      recordFailure(addressKey, ADDRESS_FAILURE_LIMIT, now),
      recordFailure(identityKey, IDENTITY_FAILURE_LIMIT, now),
    )
    if (retryAfter > 0) {
      redirect(rateLimitedDestination(destination, retryAfter))
    }
    redirect(`/login?error=invalid&next=${encodeURIComponent(destination)}`)
  }

  for (const key of attemptKeys) loginAttempts.delete(key)
  acceptedTotpSteps.set(configuredUsername!.trim(), matchedTotpStep!)
  const session = await createAuthSession(configuredUsername!.trim(), sessionSecret!)
  const cookieStore = await cookies()
  cookieStore.set(AUTH_COOKIE_NAME, session, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "strict",
    path: "/",
    maxAge: AUTH_SESSION_SECONDS,
  })
  redirect(destination)
}

export async function signOutAction(): Promise<void> {
  const cookieStore = await cookies()
  cookieStore.set(AUTH_COOKIE_NAME, "", {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "strict",
    path: "/",
    maxAge: 0,
  })
  redirect("/login")
}
