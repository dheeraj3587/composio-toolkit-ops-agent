import type { Metadata } from "next"
import { cookies } from "next/headers"
import { redirect } from "next/navigation"
import { Activity, ArrowRight, LockKeyhole, ShieldCheck } from "lucide-react"

import { loginAction } from "@/app/login/actions"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { AUTH_COOKIE_NAME, authConfigurationValid, verifyAuthSession } from "@/lib/auth-session"

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
  const configured = authConfigurationValid(configuredUsername, configuredPassword, sessionSecret)

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
  const rawRetryAfter = typeof params.retry_after === "string" ? Number.parseInt(params.retry_after, 10) : 0
  const retryAfter = Number.isInteger(rawRetryAfter) ? Math.min(Math.max(rawRetryAfter, 1), 900) : 30
  const rateLimited = error === "rate_limited"
  const invalid = error === "invalid"
  const configurationError = error === "configuration" || !configured

  return (
    <main className="grid min-h-svh bg-background lg:grid-cols-[0.82fr_1.18fr]">
      <section className="hidden border-r border-border bg-rail p-10 lg:flex lg:flex-col lg:justify-between xl:p-14" aria-label="Composio Operations overview">
        <div className="flex items-center gap-3">
          <span className="grid size-9 place-items-center rounded-md bg-brand-dev font-mono text-[10px] tracking-[0.13em] text-white">C/O</span>
          <div>
            <p className="text-sm font-medium">Composio Operations</p>
            <p className="mt-0.5 font-mono text-[9px] uppercase tracking-[0.13em] text-muted-foreground">Private workspace</p>
          </div>
        </div>

        <div className="max-w-md">
          <p className="eyebrow">Operator console</p>
          <h2 className="mt-4 text-4xl leading-[1.06] tracking-[-0.045em] xl:text-5xl">
            Integration work, with clear checkpoints.
          </h2>
          <p className="mt-5 max-w-sm text-sm leading-6 text-muted-foreground">
            Monitor browser sessions, provider state, and human handoffs without exposing credential values.
          </p>
          <ul className="mt-8 space-y-3 border-t border-border pt-6 text-xs text-muted-foreground">
            <li className="flex items-center gap-2.5"><Activity className="size-3.5 text-brand-300" aria-hidden="true" /> Backend-authoritative run state</li>
            <li className="flex items-center gap-2.5"><ShieldCheck className="size-3.5 text-emerald-400" aria-hidden="true" /> Sanitized operational views</li>
            <li className="flex items-center gap-2.5"><LockKeyhole className="size-3.5 text-brand-300" aria-hidden="true" /> Reference-only credential handling</li>
          </ul>
        </div>

        <p className="font-mono text-[9px] uppercase tracking-[0.12em] text-muted-foreground">Composio DEV surface</p>
      </section>

      <section className="flex items-center justify-center px-5 py-12 sm:px-10">
        <div className="w-full max-w-md">
          <div className="mb-10 flex items-center gap-3 lg:hidden">
            <span className="grid size-9 place-items-center rounded-md bg-brand-dev font-mono text-[9px] tracking-[0.13em] text-white">C/O</span>
            <span className="text-sm font-medium">Composio Operations</span>
          </div>

          <div className="panel p-6 sm:p-8">
            <p className="eyebrow">Operator access</p>
            <h1 className="mt-3 text-3xl tracking-[-0.04em]">Sign in</h1>
            <p className="mt-3 text-sm leading-6 text-muted-foreground">
              Continue to integration runs and live browser sessions.
            </p>

            {invalid || rateLimited || configurationError ? (
              <Alert variant={invalid || rateLimited ? "destructive" : "default"} className="mt-6" aria-live="polite">
                <AlertTitle>
                  {rateLimited ? "Too many sign-in attempts" : invalid ? "Sign-in failed" : "Authentication is not configured"}
                </AlertTitle>
                <AlertDescription>
                  {rateLimited
                    ? `Sign-in is temporarily paused. Try again in about ${retryAfter} seconds.`
                    : invalid
                      ? "The username or password was not accepted."
                      : "Set the operator username, a password of at least 8 characters, and a 32-character session secret."}
                </AlertDescription>
              </Alert>
            ) : null}

            <form action={loginAction} className="mt-7 space-y-5">
              <input type="hidden" name="next" value={next} />
              <div className="space-y-2">
                <label htmlFor="username" className="text-sm font-medium">Username</label>
                <Input id="username" name="username" type="text" required maxLength={320} autoComplete="username" autoFocus className="h-11 px-3.5" placeholder="Operator username" />
              </div>
              <div className="space-y-2">
                <label htmlFor="password" className="text-sm font-medium">Password</label>
                <Input id="password" name="password" type="password" required maxLength={1_024} autoComplete="current-password" className="h-11 px-3.5" placeholder="Your password" />
              </div>
              <Button type="submit" size="lg" disabled={!configured} className="h-11 w-full">
                Sign in <ArrowRight className="size-4" aria-hidden="true" />
              </Button>
            </form>
          </div>

          <p className="mt-5 flex items-start justify-center gap-2 text-xs leading-5 text-muted-foreground">
            <LockKeyhole className="mt-0.5 size-3.5 shrink-0" aria-hidden="true" />
            Server-signed session in an HTTP-only cookie.
          </p>
        </div>
      </section>
    </main>
  )
}
