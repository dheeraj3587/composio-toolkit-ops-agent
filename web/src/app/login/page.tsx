import type { Metadata } from "next"
import { cookies } from "next/headers"
import { redirect } from "next/navigation"
import { ArrowRight, LockKeyhole, ShieldCheck, Sparkles } from "lucide-react"

import { loginAction } from "@/app/login/actions"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import {
  AUTH_COOKIE_NAME,
  authConfigurationValid,
  verifyAuthSession,
} from "@/lib/auth-session"

export const metadata: Metadata = { title: "Sign in" }

function destination(value: string | string[] | undefined): string {
  return typeof value === "string" &&
    value.startsWith("/") &&
    !value.startsWith("//") &&
    !value.includes("\\") &&
    value.length <= 1_024
    ? value
    : "/"
}

export default async function LoginPage({
  searchParams,
}: {
  searchParams: Promise<{
    error?: string | string[]
    next?: string | string[]
    retry_after?: string | string[]
  }>
}) {
  const params = await searchParams
  const next = destination(params.next)
  const configuredUsername = process.env.OPS_AUTH_USERNAME
  const configuredPassword = process.env.OPS_AUTH_PASSWORD
  const sessionSecret = process.env.OPS_AUTH_SESSION_SECRET
  const configured = authConfigurationValid(
    configuredUsername,
    configuredPassword,
    sessionSecret,
  )

  if (
    configured &&
    await verifyAuthSession(
      (await cookies()).get(AUTH_COOKIE_NAME)?.value,
      configuredUsername!.trim(),
      sessionSecret!,
    )
  ) {
    redirect(next)
  }

  const error = typeof params.error === "string" ? params.error : null
  const rawRetryAfter = typeof params.retry_after === "string"
    ? Number.parseInt(params.retry_after, 10)
    : 0
  const retryAfter = Number.isInteger(rawRetryAfter)
    ? Math.min(Math.max(rawRetryAfter, 1), 900)
    : 30
  const rateLimited = error === "rate_limited"
  const invalid = error === "invalid"
  const configurationError = error === "configuration" || !configured

  return (
    <main className="relative grid min-h-svh overflow-hidden bg-background lg:grid-cols-[1.05fr_0.95fr]">
      <div className="relative hidden overflow-hidden bg-rail p-12 text-white lg:flex lg:flex-col lg:justify-between">
        <div className="absolute -left-24 top-24 size-96 rounded-full bg-brand-500/12 blur-3xl" />
        <div className="absolute -bottom-32 right-0 size-[30rem] rounded-full bg-brand-500/8 blur-3xl" />
        <div className="relative flex items-center gap-3">
          <span className="grid size-11 place-items-center rounded-xl border border-white/15 bg-white/10 font-mono text-[12px] tracking-[0.16em]">
            C/O
          </span>
          <div>
            <p className="text-base font-medium">Composio Operations</p>
            <p className="mt-0.5 font-mono text-[11px] uppercase tracking-[0.16em] text-white/45">
              Private workspace
            </p>
          </div>
        </div>

        <div className="relative max-w-xl">
          <div className="mb-7 grid size-12 place-items-center rounded-2xl bg-brand-500 text-rail">
            <Sparkles className="size-5" aria-hidden="true" />
          </div>
          <h1 className="text-5xl font-medium leading-[1.02] tracking-[-0.05em]">
            Set up apps
            <br />
            without the busywork.
          </h1>
          <p className="mt-6 max-w-lg text-base leading-7 text-white/55">
            The agent signs in, handles email verification, finds the developer settings, and
            stores each credential where nothing can read it back out.
          </p>
        </div>

        <div className="relative flex flex-wrap items-center gap-x-6 gap-y-2 text-xs text-white/45">
          <span className="flex items-center gap-2">
            <ShieldCheck className="size-4 text-brand-300" aria-hidden="true" /> Sessions signed
            server-side
          </span>
          <span className="flex items-center gap-2">
            <LockKeyhole className="size-4 text-brand-300" aria-hidden="true" /> Credentials never
            reach the browser
          </span>
        </div>
      </div>

      <div className="flex items-center justify-center px-5 py-12 sm:px-10">
        <div className="w-full max-w-md">
          <div className="mb-10 flex items-center gap-3 lg:hidden">
            <span className="grid size-10 place-items-center rounded-xl bg-rail font-mono text-[12px] tracking-[0.15em] text-white">
              C/O
            </span>
            <span className="font-medium">Composio Operations</span>
          </div>

          <p className="eyebrow">Operator access</p>
          <h2 className="mt-3 text-3xl font-medium tracking-[-0.04em]">Sign in</h2>
          <p className="mt-3 text-sm leading-6 text-muted-foreground">
            Use the operator account configured for this deployment.
          </p>

          {invalid || rateLimited || configurationError ? (
            <Alert
              variant={invalid || rateLimited ? "destructive" : "default"}
              className="mt-6 rounded-xl"
              aria-live="polite"
            >
              <AlertTitle>
                {rateLimited
                  ? "Too many sign-in attempts"
                  : invalid
                    ? "Sign-in failed"
                    : "Authentication is not configured"}
              </AlertTitle>
              <AlertDescription>
                {rateLimited
                  ? `Sign-in is temporarily paused. Try again in about ${retryAfter} seconds.`
                  : invalid
                    ? "That username and password combination was not accepted. Nothing about which of the two was wrong is reported, deliberately."
                    : "This deployment has no operator account configured. It needs a username, a password of at least 8 characters, and a 32-character session secret."}
              </AlertDescription>
            </Alert>
          ) : null}

          <form action={loginAction} className="mt-8 space-y-5">
            <input type="hidden" name="next" value={next} />
            <div className="space-y-2">
              <label htmlFor="username" className="text-sm font-medium">Username</label>
              <Input
                id="username"
                name="username"
                type="text"
                required
                maxLength={320}
                autoComplete="username"
                autoFocus
                className="h-12 rounded-xl bg-card px-4"
                placeholder="Operator username"
              />
            </div>
            <div className="space-y-2">
              <label htmlFor="password" className="text-sm font-medium">Password</label>
              <Input
                id="password"
                name="password"
                type="password"
                required
                maxLength={1_024}
                autoComplete="current-password"
                className="h-12 rounded-xl bg-card px-4"
                placeholder="Your password"
              />
            </div>
            <Button
              type="submit"
              size="lg"
              disabled={!configured}
              className="h-12 w-full rounded-xl text-sm font-medium"
            >
              Sign in securely <ArrowRight className="size-4" aria-hidden="true" />
            </Button>
          </form>

          <p className="mt-6 flex items-start gap-2 text-xs leading-5 text-muted-foreground">
            <LockKeyhole className="mt-0.5 size-3.5 shrink-0" aria-hidden="true" />
            Your session is signed on the server and stored in an HTTP-only cookie.
            Credentials never enter the browser bundle.
          </p>
        </div>
      </div>
    </main>
  )
}
