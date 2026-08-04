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
    // A successful lookup proves reviewed-catalog membership. Account creation
    // enters backend-authoritative profile research/planning; a static signup URL
    // is an optimization, not the eligibility boundary.
    return Response.json(
      {
        app_slug: result.app.app_slug,
        account_creation_supported: true,
        reason_code: result.research.signup_url
          ? "reviewed_signup_route"
          : "planner_onboarding_available",
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
