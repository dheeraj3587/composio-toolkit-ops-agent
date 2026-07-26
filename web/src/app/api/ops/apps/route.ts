import { ApiError, listApps } from "@/lib/api"

/**
 * The whole verified catalog, so the browser can populate a selector.
 *
 * Deliberately takes no query: the search route exists for narrowing and
 * enforces its own minimum length, which is exactly why it could never answer
 * "show me what I can choose from". The backend token stays server-side; only
 * the sanitized projection reaches the client.
 */
export async function GET() {
  try {
    const result = await listApps()
    return Response.json(result, {
      status: 200,
      headers: {
        // The snapshot is immutable, but a run's view of it must never be a
        // stale shared cache entry, so this stays private and revalidated.
        "Cache-Control": "private, no-store",
        "X-Content-Type-Options": "nosniff",
      },
    })
  } catch (error) {
    const status = error instanceof ApiError && error.status === 404 ? 404 : 503
    return Response.json(
      {
        error: status === 404 ? "not_found" : "backend_unavailable",
        message:
          status === 404
            ? "The verified catalog is not available."
            : "The app catalog is unavailable.",
      },
      { status, headers: { "Cache-Control": "private, no-store" } },
    )
  }
}
