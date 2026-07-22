import { ApiError, searchApps } from "@/lib/api"

export async function GET(request: Request) {
  const query = new URL(request.url).searchParams.get("q")?.trim().slice(0, 120) ?? ""

  if (query.length < 2) {
    return Response.json(
      { error: "invalid_query", message: "Enter at least two characters." },
      { status: 400, headers: { "Cache-Control": "private, no-store" } },
    )
  }

  try {
    const result = await searchApps(query)
    return Response.json(result, {
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
        message: status === 404 ? "No app matched the query." : "The app catalog is unavailable.",
      },
      { status, headers: { "Cache-Control": "private, no-store" } },
    )
  }
}
