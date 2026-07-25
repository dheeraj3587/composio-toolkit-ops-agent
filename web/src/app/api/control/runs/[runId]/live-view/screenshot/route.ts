import { ApiError, getLiveScreenshotBinary } from "@/lib/api"

export const runtime = "nodejs"
export const dynamic = "force-dynamic"

const RUN_ID = /^run_[0-9a-f]{32}$/

const NO_STORE_HEADERS = {
  "Cache-Control": "no-store, max-age=0",
  Pragma: "no-cache",
  "X-Content-Type-Options": "nosniff",
} as const

/**
 * Same-origin browser-for-frontend boundary for Playwright screenshots.
 *
 * Browser JavaScript cannot call the private FastAPI origin because that request
 * requires the server-only internal API token. This handler performs the private
 * request on the server and returns only validated PNG bytes. It never redirects
 * to FastAPI or exposes the browser-worker hostname.
 */
export async function GET(
  _request: Request,
  context: { params: Promise<{ runId: string }> },
): Promise<Response> {
  const { runId } = await context.params

  if (!RUN_ID.test(runId)) {
    return new Response(null, {
      status: 400,
      headers: NO_STORE_HEADERS,
    })
  }

  try {
    const result = await getLiveScreenshotBinary(runId)
    const headers: Record<string, string> = {
      ...NO_STORE_HEADERS,
      "Content-Type": "image/png",
    }

    if (result.capturedAt) {
      headers["X-Captured-At"] = result.capturedAt
    }

    return new Response(
      new Blob([result.bytes], { type: "image/png" }),
      {
        status: 200,
        headers,
      },
    )
  } catch (error) {
    const status = error instanceof ApiError ? error.status : 500
    return new Response(null, {
      status,
      headers: NO_STORE_HEADERS,
    })
  }
}
