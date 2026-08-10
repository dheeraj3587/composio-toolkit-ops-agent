# Browser-agent research prompt — the 36 apps with an empty `urls` object

Hand the block below to a browser agent. Run it **once per app**, substituting
`{{APP_NAME}}`, `{{APP_SLUG}}`, and `{{GROUP}}` from the table at the bottom.
Do not paste all 36 at once — a single agent session that tries to cover the
whole list produces confident guesses for the tail end, and a guessed URL here
becomes a navigation allowlist entry, not a footnote.

The output feeds `ops/recipes/app_recipes.json`, whose validator
(`ops/recipes/app_recipes.py`) rejects anything that misses the closed
vocabularies below. Fields are named exactly as the schema names them.

---

## THE PROMPT

You are researching one SaaS vendor's public documentation to fill in a machine
consumable record. You are a reader, not a user.

### Hard rules — violating any of these makes the whole result unusable

1. **Do not create an account, sign up, log in, or enter any credential**,
   including on a vendor you may already be signed into. If a page needs a
   session, record what it is and move on.
2. **Do not purchase anything, start a trial, or submit any form.**
3. **Never guess, infer, or reconstruct a URL from a pattern.** Every URL you
   report must be one you actually navigated to and watched load. If you cannot
   reach it, the value is `null` and you say why in `notes`. A plausible-looking
   URL that 404s is worse than `null` here, because it will be trusted.
4. **Report the final URL after redirects**, not the one you typed.
5. If a page is behind a login wall, that is a legitimate finding — report the
   URL you were redirected *from* as `credential_management` only if the
   redirect target is clearly the vendor's own login page (i.e. the deep link is
   real and merely gated). If you were bounced to a generic marketing homepage,
   the URL is wrong; report `null`.

### What you are answering

The single most important question, asked first:

> **Can a normal user of {{APP_NAME}} create a long-lived API key, personal
> access token, or bot token from a settings page in the web UI, entirely on
> their own, without contacting sales, without an approval queue, and without an
> OAuth app review?**

If yes, this app can be onboarded without any browser automation at all, and the
`credential_management` URL is the load-bearing fact. If no, say so plainly and
explain what the gate actually is.

### Output — one JSON object, nothing else

```json
{
  "app_slug": "{{APP_SLUG}}",
  "app_name": "{{APP_NAME}}",

  "self_serve_key_available": true,
  "self_serve_key_summary": "One or two sentences: what the credential is called in this product's own words, where it lives, and what (if anything) gates it.",

  "urls": {
    "login": null,
    "signup": null,
    "developer_portal": null,
    "credential_management": null,
    "contact": null
  },

  "credential_fields": [
    {"name": "api_key", "label": "API key", "kind": "api_key", "secret": true}
  ],

  "auth_styles": ["api_key"],

  "validation": {
    "endpoint": null,
    "method": "GET",
    "auth_scheme": null,
    "credential_field": "api_key",
    "header_name": null,
    "header_value_prefix": "",
    "account_identifier_paths": []
  },

  "capture_hints": {
    "shown_once": false,
    "reveal_control_label": null,
    "value_shape": null,
    "creation_control_labels": [],
    "page_heading": null,
    "path_prefix": null
  },

  "gates": [],

  "evidence_urls": [],
  "notes": "",
  "confidence": "high"
}
```

### Field rules — these are closed sets, do not invent members

**`urls.*`** — must be `https://`, must have a host, must contain no `@`
(userinfo) and no query parameter whose name looks like a secret (`token`,
`key`, `password`, `secret`). A `#fragment` **is** allowed — some products hide
the key page behind a hash route, and that is a real destination. Meanings:

| field | what it must point at |
|---|---|
| `login` | the sign-in form itself, not a "log in" marketing page |
| `signup` | the self-serve registration form; `null` if signup is sales-gated |
| `developer_portal` | the API/developer docs home |
| `credential_management` | **the deepest page where the key is actually created**, e.g. `.../settings/api`, `.../developers/tokens`. Not the doc page *describing* it |
| `contact` | developer/API support contact form or a support email as `mailto:` |

**`credential_fields[].kind`** — one of exactly:
`api_key`, `bearer_token`, `bot_token`, `personal_access_token`, `username`,
`password`, `client_id`, `client_secret`.
`secret` is `true` for anything that must be hidden, `false` for a non-secret
identifier such as a login name or account subdomain. If the credential is a
username+password pair (basic auth), list **both**, with the username
`"secret": false`.

**`auth_styles`** — subset of exactly:
`api_key`, `bearer_token`, `basic_auth`, `oauth2`, `personal_access_token`,
`bot_token`, `service_account`. List every style the product genuinely
supports, most self-serve first.

**`validation`** — a real HTTP request that proves a key works.
- `method` is always `"GET"`. If the only "who am I" endpoint requires POST,
  set `endpoint` to `null` and say so in `notes`.
- `auth_scheme` is one of exactly `bearer`, `api_key_header`, `basic_auth`.
- `header_name` is the literal header, e.g. `Authorization`, `X-Api-Key`.
- `header_value_prefix` is what precedes the secret in that header, **including
  the trailing space** — e.g. `"Bearer "`, or `""` when the raw key is the whole
  value. Get this exactly right; it is a common source of silent 401s.
- `endpoint` should be the cheapest authenticated read the API offers — the
  `/me`, `/user`, or `/account` shaped one. Never a write.
- `account_identifier_paths` are dotted paths into that response that identify
  the account, e.g. `["data.id", "data.company_id"]`.

**`capture_hints`** — for the browser automation, only if you can see the UI
described in public docs or screenshots. All fields optional; `null` when
unknown. `shown_once` is `true` if the docs warn the value is displayed only at
creation time. `creation_control_labels` are the literal button texts that mint
a key, e.g. `["Create new token", "Generate"]`. `value_shape` is a plain-English
description or a regex if the docs state the format, e.g. `"40 hex chars"` or
`"starts with sk-"`.

**`gates`** — every human obstacle between a fresh account and a working key.
Use only these names, and add a short parenthetical:
`captcha`, `email_otp`, `phone_otp`, `device_approval`, `passkey`,
`security_key`, `oauth_grant`, `legal_acceptance`, `account_selection`,
`billing`, `provider_verification`.
Example: `["billing (key creation requires a paid plan)", "email_otp"]`.

**`evidence_urls`** — every page you actually read to reach these conclusions.
Minimum two. This is the audit trail; a record without it gets rejected.

**`confidence`** — `high` only if you loaded the `credential_management` page
yourself (even if it redirected you to login) **and** read the authentication
docs. `medium` if you inferred the page from docs but could not load it. `low`
otherwise. Do not report `high` to be helpful; a wrong `high` costs more than an
honest `low`.

**`notes`** — where you were blocked, what was ambiguous, anything a human
reviewer should double-check. This field is read.

### If the answer is "no self-serve key"

Set `self_serve_key_available` to `false` and still fill in everything you can —
especially `contact`, `gates`, and a `notes` explaining the actual gate
(partner program, app review, sales call, enterprise tier). A well-documented
"no" is a useful result and closes the question.

---

## The 36 apps

**Group A — 25 `managed_auth`.** Currently OAuth-only in our catalog. The prize
is finding a static-key path, which would skip browser automation entirely.
Prioritise these; several are well known to have PATs.

| slug | name | slug | name |
|---|---|---|---|
| `github` | GitHub | `notion` | Notion |
| `airtable` | Airtable | `linear` | Linear |
| `sentry` | Sentry | `supabase` | Supabase |
| `stripe` | Stripe | `clickup` | ClickUp |
| `monday` | Monday.com | `asana` | Asana |
| `harvest` | Harvest | `zendesk` | Zendesk |
| `intercom` | Intercom | `mailchimp` | Mailchimp |
| `attio` | Attio | `gumroad` | Gumroad |
| `discord` | Discord | `gorgias` | Gorgias |
| `slack` | Slack | `hubspot` | HubSpot |
| `jira` | Jira | `salesforce` | Salesforce |
| `quickbooks` | QuickBooks | `fathom` | Fathom |
| `google-ads` | Google Ads | | |

**Group B — 11 `gated`.** These are believed to need a partner program or
review. The job here is to confirm or refute that, per app.

| slug | name | note |
|---|---|---|
| `plain` | Plain | believed strongest candidate for reclassification |
| `sendgrid` | SendGrid | believed strongest candidate |
| `help-scout` | Help Scout | believed strongest candidate |
| `close` | Close | confirm whether `/integrations/publish` is really required |
| `brex` | Brex | own-account admin tokens may be self-serve |
| `ahrefs` | Ahrefs | keys said to exist on eligible plans — which plans? |
| `freshdesk` | Freshdesk | per-tenant host `<domain>.freshdesk.com` — note the pattern |
| `snowflake` | Snowflake | per-tenant host — note the pattern |
| `ramp` | Ramp | check whether client-credentials is POST-only |
| `meta-ads` | Meta Ads | expected hard no; confirm and record the gate |
| `linkedin-ads` | LinkedIn Ads | expected hard no; confirm and record the gate |

For `freshdesk` and `snowflake`, the account-specific hostname is expected —
report the URL with a literal `{tenant}` placeholder in the host position and
describe the pattern in `notes`.
