// Local dev only: mint the same HMAC session cookie the login action issues, so a
// signed-in page can be fetched by a verification script for visual/DOM checks.
//
// This prints a VALID 12-HOUR OPERATOR SESSION for the configured account. That is
// the whole point of it and also the whole risk, so it is gated three ways and all
// three must hold:
//
//   1. `ALLOW_DEV_SESSION_MINT=true` must be set in the PROCESS environment. It is
//      deliberately NOT read from any env file: a `.env.local` or `.env.production`
//      that happened to carry the flag must not be able to arm this by itself.
//   2. `NODE_ENV` must not be `production`.
//   3. Credentials are read only from `web/.env.local`, never `.env.production` or
//      the process environment, so this cannot mint against deployed secrets.
//
// It prints only the cookie value — never the signing secret or the password.
import { existsSync, readFileSync } from "node:fs"

function refuse(reason) {
  process.stderr.write(`dev-session-cookie: refusing to run — ${reason}\n`)
  process.exit(1)
}

if (process.env.ALLOW_DEV_SESSION_MINT !== "true") {
  refuse(
    "ALLOW_DEV_SESSION_MINT=true is required in the process environment " +
      "(this mints a valid 12-hour operator session)",
  )
}

if (process.env.NODE_ENV === "production") {
  refuse("NODE_ENV=production")
}

const envPath = new URL("../.env.local", import.meta.url)
if (!existsSync(envPath)) {
  refuse("web/.env.local not found — this is a local-development-only tool")
}

const env = Object.fromEntries(
  readFileSync(envPath, "utf8")
    .split("\n")
    .filter((line) => line.includes("=") && !line.trimStart().startsWith("#"))
    .map((line) => {
      const at = line.indexOf("=")
      return [line.slice(0, at).trim(), line.slice(at + 1).trim().replace(/^["']|["']$/g, "")]
    }),
)

const username = env.OPS_AUTH_USERNAME
const secret = env.OPS_AUTH_SESSION_SECRET
if (!username || !secret) {
  refuse("OPS_AUTH_USERNAME and OPS_AUTH_SESSION_SECRET must both be set in web/.env.local")
}

const { createAuthSession } = await import("../src/lib/auth-session.ts")
process.stdout.write(await createAuthSession(username, secret))
