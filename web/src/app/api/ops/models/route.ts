import { ApiError, getModelCatalog } from "@/lib/api"

/**
 * The decision-model catalog, proxied for the browser.
 *
 * The backend answers only with providers whose key is configured, so this
 * route never has to decide what is serviceable — it forwards the answer. On
 * any backend failure it returns an empty catalog rather than a guess, and the
 * form falls back to the deployment's own default chain.
 */
export async function GET() {
  try {
    const catalog = await getModelCatalog()
    return Response.json(catalog, {
      status: 200,
      headers: {
        "Cache-Control": "private, no-store",
        "X-Content-Type-Options": "nosniff",
      },
    })
  } catch (error) {
    const status = error instanceof ApiError && error.status === 404 ? 404 : 503
    return Response.json(
      {
        error: status === 404 ? "not_found" : "backend_unavailable",
        message: "The decision model catalog could not be read.",
      },
      { status, headers: { "Cache-Control": "private, no-store" } },
    )
  }
}
