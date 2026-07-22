# Operations Ledger frontend

Next.js 16 and React 19 product dashboard for the Composio Toolkit Ops Agent. It renders only the
sanitized FastAPI contract and performs API access in server code.

```bash
npm ci
cp .env.example .env.local
npm run dev
```

`OPS_API_URL` must be the trusted FastAPI origin, normally `http://127.0.0.1:8000` for local
development. It is intentionally server-only. Do not introduce a `NEXT_PUBLIC_` alias, browser
storage for request/run data, or a direct vault integration.

Verification:

```bash
npm run lint
npm run typecheck
npm run build
npm audit --audit-level=high
```

Successful API envelopes are validated at runtime with strict Zod schemas before rendering. A
schema mismatch is reduced to a generic gateway error; validation details and the rejected payload
are never returned to the browser. The production response includes a static Next-compatible CSP,
clickjacking and MIME-sniffing defenses, a no-referrer policy, and a restrictive permissions policy.

`npm run build` also copies `public/` and `.next/static/` into the official standalone output. This
makes `npm start` and the production image use the same complete artifact, including all CSS, font,
and JavaScript assets.

Package install scripts default to denied via `.npmrc` (`strict-allow-scripts=true`). The only pinned
exception is `unrs-resolver@1.12.2`, which is required by the lint resolver and is reviewed through
the exact lockfile. Any dependency change must update the lockfile, keep this allowlist minimal, and
pass `npm audit` before release.

The dashboard has no application authentication yet and is for trusted access only. Container and
full-stack setup are documented in the repository-level `README.md`.
