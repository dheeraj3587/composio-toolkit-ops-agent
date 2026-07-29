import { ApiError, getAppResearch } from "@/lib/api"

const APP_SLUG_PATTERN = /^[a-z0-9]+(?:-[a-z0-9]+)*$/

export async function GET(
  _request: Request,
  { params }: { params: Promise<{ slug: string }> },
) {
  const { slug } = await params
  if (!APP_SLUG_PATTERN.test(slug)) {
    return Response.json(
      { error: "invalid_app", message: "The app identifier is invalid." },
      { status: 400, headers: { "Cache-Control": "private, no-store" } },
    )
  }

  try {
    const result = await getAppResearch(slug)
    const accountCreationSupported = Boolean(result.research.signup_url)
    return Response.json(
      {
        app_slug: result.app.app_slug,
        account_creation_supported: accountCreationSupported,
        reason_code: accountCreationSupported
          ? "reviewed_signup_route"
          : "signup_route_unavailable",
      },
      {
        status: 200,
        headers: {
          "Cache-Control": "private, no-store",
          "X-Content-Type-Options": "nosniff",
        },
      },
    )
  } catch (error) {
    const status = error instanceof ApiError && error.status === 404 ? 404 : 503
    return Response.json(
      {
        error: status === 404 ? "not_found" : "backend_unavailable",
        message:
          status === 404
            ? "No verified app profile was found."
            : "App capabilities could not be verified.",
      },
      { status, headers: { "Cache-Control": "private, no-store" } },
    )
  }
}
