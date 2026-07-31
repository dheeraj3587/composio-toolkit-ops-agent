import { NextRequest, NextResponse } from "next/server"

import {
  AUTH_COOKIE_NAME,
  authConfigurationValid,
  verifyAuthSession,
} from "@/lib/auth-session"

const PUBLIC_FILES = new Set(["/favicon.ico", "/robots.txt", "/sitemap.xml"])

function isPublicPath(pathname: string): boolean {
  return (
    pathname === "/login" ||
    pathname === "/health" ||
    pathname.startsWith("/_next/") ||
    PUBLIC_FILES.has(pathname)
  )
}

function unauthorized(request: NextRequest): NextResponse {
  if (request.nextUrl.pathname.startsWith("/api/")) {
    return NextResponse.json({ error: "AUTHENTICATION_REQUIRED" }, { status: 401 })
  }

  const loginUrl = request.nextUrl.clone()
  loginUrl.pathname = "/login"
  loginUrl.search = ""
  const destination = `${request.nextUrl.pathname}${request.nextUrl.search}`
  if (destination.startsWith("/") && destination.length <= 1_024) {
    loginUrl.searchParams.set("next", destination)
  }
  return NextResponse.redirect(loginUrl)
}

export async function proxy(request: NextRequest): Promise<NextResponse> {
  if (isPublicPath(request.nextUrl.pathname)) return NextResponse.next()

  const username = process.env.OPS_AUTH_USERNAME
  const password = process.env.OPS_AUTH_PASSWORD
  const sessionSecret = process.env.OPS_AUTH_SESSION_SECRET
  if (!authConfigurationValid(username, password, sessionSecret)) {
    return unauthorized(request)
  }

  const authenticated = await verifyAuthSession(
    request.cookies.get(AUTH_COOKIE_NAME)?.value,
    username!.trim(),
    sessionSecret!,
  )
  return authenticated ? NextResponse.next() : unauthorized(request)
}

export const config = {
  matcher: ["/((?!_next/static|_next/image).*)"],
}
