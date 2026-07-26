import "server-only"

import { ApiError } from "@/lib/api"

const INTERACTIVE_ENDPOINT = "/internal/browser/live-view/novnc"
const SESSION_PATTERN = /^[A-Za-z0-9_-]{1,180}$/

/**
 * Convert the one reviewed private browser-service grant into a same-origin path.
 *
 * The token is intentionally returned only to the caller. This helper never
 * logs it, persists it, or includes it in an error message.
 */
export function sameOriginInteractivePath(value: string): string {
  let parsed: URL

  try {
    parsed = new URL(value)
  } catch {
    throw new ApiError(502, "INVALID_INTERACTIVE_GRANT")
  }

  const queryKeys = [...parsed.searchParams.keys()]
  const session = parsed.searchParams.get("session")
  const token = parsed.searchParams.get("token")
  const validEndpoint =
    parsed.protocol === "http:" &&
    parsed.hostname === "browser-worker" &&
    parsed.port === "8081" &&
    parsed.pathname === INTERACTIVE_ENDPOINT &&
    parsed.username === "" &&
    parsed.password === "" &&
    parsed.hash === ""
  const validQuery =
    queryKeys.length === 2 &&
    new Set(queryKeys).size === 2 &&
    queryKeys.includes("session") &&
    queryKeys.includes("token") &&
    session !== null &&
    SESSION_PATTERN.test(session) &&
    token !== null &&
    token.length > 0 &&
    token.length <= 2_048 &&
    !/[\u0000-\u001f\u007f]/.test(token)

  if (!validEndpoint || !validQuery || session === null || token === null) {
    throw new ApiError(502, "INVALID_INTERACTIVE_GRANT")
  }

  return `${INTERACTIVE_ENDPOINT}?${new URLSearchParams({ session, token }).toString()}`
}
