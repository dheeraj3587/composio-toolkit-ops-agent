import type { Metadata } from "next"
import { connection } from "next/server"
import QRCode from "qrcode"
import { KeyRound, ShieldAlert, ShieldCheck } from "lucide-react"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { totpConfigurationValid } from "@/lib/totp"

export const metadata: Metadata = { title: "Authenticator setup" }

// This page renders the enrolment secret, so it must never be cached, prerendered,
// or served from a shared cache. The proxy already requires a valid signed session
// for every path except /login and /health, so reaching it means authenticated.
export const dynamic = "force-dynamic"
export const revalidate = 0

function provisioningUri(username: string, secret: string): string {
  const label = encodeURIComponent(`ComposioOps:${username}`)
  const parameters = new URLSearchParams({
    secret,
    issuer: "ComposioOps",
    algorithm: "SHA1",
    digits: "6",
    period: "30",
  })
  return `otpauth://totp/${label}?${parameters.toString()}`
}

function grouped(secret: string): string {
  return secret.replace(/(.{4})/gu, "$1 ").trim()
}

export default async function AuthenticatorPage() {
  await connection()

  const username = (process.env.OPS_AUTH_USERNAME ?? "").trim()
  const secret = (process.env.OPS_AUTH_TOTP_SECRET ?? "").trim().toUpperCase()

  if (!username || !totpConfigurationValid(secret)) {
    return (
      <div className="page-enter page-stack">
        <header className="border-b border-border pb-7">
          <p className="eyebrow">Security</p>
          <h1 className="mt-3 text-3xl font-semibold tracking-[-0.035em]">Authenticator setup</h1>
        </header>
        <Alert className="rounded-md border-red-200 bg-red-50 text-red-950">
          <ShieldAlert className="text-red-600" aria-hidden="true" />
          <AlertTitle>Sign-in codes are not configured</AlertTitle>
          <AlertDescription>
            This deployment has no valid operator username and Base32 TOTP secret, so no
            enrolment can be shown.
          </AlertDescription>
        </Alert>
      </div>
    )
  }

  const uri = provisioningUri(username, secret)
  // Encoded on the server into a self-contained PNG data URL. The secret never
  // travels to a QR service, and a data URL keeps the frontend boundary intact:
  // no raw HTML is injected anywhere. The CSP already allows data: images.
  const qrDataUrl = await QRCode.toDataURL(uri, {
    errorCorrectionLevel: "M",
    margin: 1,
    width: 232,
  })

  return (
    <div className="page-enter page-stack">
      <header className="border-b border-border pb-7">
        <p className="eyebrow">Security</p>
        <h1 className="mt-3 text-3xl font-semibold tracking-[-0.035em] sm:text-4xl">
          Authenticator setup
        </h1>
        <p className="mt-3 max-w-2xl text-sm leading-6 text-muted-foreground">
          Scan this once with any authenticator app. It then produces the six-digit code the
          sign-in form asks for, every 30 seconds, offline.
        </p>
      </header>

      <section aria-labelledby="enrolment" className="panel rounded-md p-6">
        <div className="mb-5">
          <p className="eyebrow">Enrolment</p>
          <h2 id="enrolment" className="mt-1 text-xl font-semibold">
            Operator <span className="font-mono text-base">{username}</span>
          </h2>
        </div>
        <div className="flex flex-col gap-7 sm:flex-row sm:items-start">
          <div className="w-fit shrink-0 rounded-md border border-border bg-white p-3">
            {/* eslint-disable-next-line @next/next/no-img-element -- a data URL needs no optimizer */}
            <img
              src={qrDataUrl}
              alt="Authenticator enrolment QR code"
              width={232}
              height={232}
            />
          </div>
          <div className="min-w-0 space-y-4">
            <div>
              <p className="text-sm font-medium">Cannot scan? Enter the key manually.</p>
              <p className="mt-2 break-all rounded-md border border-border bg-muted px-3 py-2 font-mono text-sm">
                {grouped(secret)}
              </p>
            </div>
            <dl className="grid grid-cols-2 gap-x-6 gap-y-2 text-xs text-muted-foreground sm:max-w-sm">
              <dt>Type</dt>
              <dd className="text-foreground">Time based (TOTP)</dd>
              <dt>Algorithm</dt>
              <dd className="text-foreground">SHA1</dd>
              <dt>Digits</dt>
              <dd className="text-foreground">6</dd>
              <dt>Period</dt>
              <dd className="text-foreground">30 seconds</dd>
            </dl>
          </div>
        </div>
      </section>

      <Alert className="rounded-md">
        <ShieldCheck aria-hidden="true" />
        <AlertTitle>This page is the second factor</AlertTitle>
        <AlertDescription>
          Anyone who reads this key can generate valid sign-in codes, so it is only reachable
          with an authenticated session and is never cached. Each code is accepted once; if two
          people submit the same code, the second attempt is rejected and must wait for the
          next 30-second window.
        </AlertDescription>
      </Alert>

      <Alert className="rounded-md">
        <KeyRound aria-hidden="true" />
        <AlertTitle>Rotating the key</AlertTitle>
        <AlertDescription>
          The key comes from <span className="font-mono text-xs">OPS_AUTH_TOTP_SECRET</span> in
          the host-only production environment file. Changing it invalidates every enrolled
          device and takes effect on the next release.
        </AlertDescription>
      </Alert>
    </div>
  )
}
