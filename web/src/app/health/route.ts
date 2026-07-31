import { NextResponse } from "next/server"

import { authConfigurationValid } from "@/lib/auth-session"

export function GET(): NextResponse {
  const authConfigured = authConfigurationValid(
    process.env.OPS_AUTH_USERNAME,
    process.env.OPS_AUTH_PASSWORD,
    process.env.OPS_AUTH_SESSION_SECRET,
  )
  return NextResponse.json(
    {
      status: authConfigured ? "ok" : "configuration_required",
      service: "composio-operations-web",
      auth_configured: authConfigured,
    },
    {
      status: authConfigured ? 200 : 503,
      headers: { "Cache-Control": "no-store" },
    },
  )
}
