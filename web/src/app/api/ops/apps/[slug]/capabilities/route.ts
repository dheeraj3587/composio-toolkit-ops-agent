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
    const signupSource = result.signup_source ?? "unavailable"
    // "runtime_research" means the app can be signed up for but the route is
    // resolved from its own site when the run starts. That is a supported
    // capability, not a missing one — refusing it here was the blocker that
    // limited account creation to the single app with a hand-authored route.
    const accountCreationSupported =
      Boolean(result.research.signup_url) || signupSource === "runtime_research"
    return Response.json(
      {
        app_slug: result.app.app_slug,
        account_creation_supported: accountCreationSupported,
        // A researched route enables the toggle but is reported under its own
        // reason code, so the form can caveat it instead of presenting a model's
        // extraction as a reviewed one.
        signup_source: signupSource,
        signup_evidence_url: result.signup_evidence_url ?? null,
        reason_code: !accountCreationSupported
          ? "signup_route_unavailable"
          : signupSource === "runtime_research"
            ? "runtime_research_signup_route"
            : "reviewed_signup_route",
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
