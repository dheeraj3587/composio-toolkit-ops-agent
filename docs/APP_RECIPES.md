# Application recipes

`ops/recipes/app_recipes.json` is the data source for new canonical runs. `ops/recipes/app_recipes.py` validates it at startup against an exact 50-app matrix.

Current catalog:

- schema: `1.0`
- catalog ID: `approved-50-routes-2026-07-28`
- routes: 7 managed authentication, 23 managed key, 14 Playwright, 6 gated
- readiness: 30 `managed_auth_ready`, 9 `browser_ready`, 5 `owner_submit_ready`, 1 `outreach_ready`, 5 `outreach_review_required`

Recipe readiness describes reviewed automation scope. It is not evidence that a provider is configured, a user has authorized an account, or a live run has succeeded.

`readiness_tier`, `route_kind`, and `access_route` are three separate vocabularies and do not imply one another. `managed_auth_ready` covers both connection routes — `managed_auth` and `managed_key` — because the tier describes what is reviewed, not how the credential is obtained.

## Route contracts

### Managed authentication

A managed recipe has a reviewed Composio toolkit slug and OAuth evidence. It does not start a browser or handle raw OAuth tokens. A run completes only after Composio reports the connected account active.

These seven are the apps for which a redirect is the only route: no self-serve settings page mints a long-lived key, so an account is signed in rather than a secret pasted. Every other app that once sat here moved to `managed_key` on 2026-08-08.

| App | App slug | Toolkit slug |
| --- | --- | --- |
| Salesforce | `salesforce` | `salesforce` |
| Zendesk | `zendesk` | `zendesk` |
| Gorgias | `gorgias` | `gorgias` |
| Google Ads | `google-ads` | `googleads` |
| Monday.com | `monday` | `monday` |
| Stripe | `stripe` | `stripe` |
| QuickBooks | `quickbooks` | `quickbooks` |

Zendesk and Gorgias are here for a different reason than the other five: both mint self-serve API tokens, but only at a per-tenant host (`<subdomain>.zendesk.com`), which the exact-host allowlist cannot express. They move to `managed_key` when reviewed wildcard hosts land.

### Managed key

A managed-key recipe ends in the same place as a managed-auth one — an active Composio connected account — but gets there without a redirect and without a browser. The owner mints a long-lived key on the vendor's own settings page, submits it once, and it is published to Composio as a custom-auth connection. The Composio SDK returns `ACTIVE` synchronously for these auth schemes, so there is no consent screen, no callback, and no polling loop.

Every row was promoted off `managed_auth` or `gated` on 2026-08-08 against an evidenced `urls.credential_management` page. Membership is pinned explicitly by `MANAGED_KEY_SLUGS` in `ops/recipes/app_recipes.py`, so a promotion is always a deliberate edit rather than a side effect of the recipe's shape.

| App | App slug | Credential fields | Auth styles | Validation | Credential management |
| --- | --- | --- | --- | --- | --- |
| HubSpot | `hubspot` | `private_app_access_token` | bearer_token, oauth2, personal_access_token | yes | https://app.hubspot.com/settings/integrations/private-apps |
| Attio | `attio` | `api_key` | api_key, bearer_token | yes | https://app.attio.com/settings/developers |
| Intercom | `intercom` | `access_token` | bearer_token, oauth2 | yes | https://app.intercom.com/a/developer-hub |
| Slack | `slack` | `bot_token` | bearer_token, bot_token, oauth2 | yes | https://api.slack.com/apps |
| Discord | `discord` | `bot_token` | bot_token | yes | https://discord.com/developers/applications |
| Mailchimp | `mailchimp` | `api_key` | api_key, basic_auth | no | https://admin.mailchimp.com/account/api/ |
| Gumroad | `gumroad` | `access_token` | bearer_token, oauth2, personal_access_token | yes | https://app.gumroad.com/settings/advanced |
| GitHub | `github` | `personal_access_token` | bearer_token, personal_access_token | yes | https://github.com/settings/tokens |
| Supabase | `supabase` | `personal_access_token` | bearer_token, personal_access_token | yes | https://supabase.com/dashboard/account/tokens |
| Sentry | `sentry` | `user_auth_token` | bearer_token | yes | https://sentry.io/settings/account/api/auth-tokens/ |
| Notion | `notion` | `personal_access_token` | bearer_token, bot_token, personal_access_token | yes | https://www.notion.so/profile/connections |
| Airtable | `airtable` | `personal_access_token` | bearer_token, oauth2, personal_access_token | yes | https://airtable.com/create/tokens |
| Linear | `linear` | `personal_access_token` | api_key, bearer_token, personal_access_token | yes | https://linear.app/settings/account/security |
| Jira | `jira` | `username`, `api_token` | api_key, basic_auth | no | https://id.atlassian.com/manage-profile/security/api-tokens |
| Asana | `asana` | `personal_access_token` | bearer_token, oauth2, personal_access_token | yes | https://app.asana.com/0/my-apps |
| ClickUp | `clickup` | `personal_api_token` | api_key, personal_access_token | yes | https://app.clickup.com/settings/apps |
| Harvest | `harvest` | `personal_access_token`, `account_id` | bearer_token, personal_access_token | yes | https://id.getharvest.com/developers |
| Fathom | `fathom` | `api_key` | api_key, bearer_token | yes | https://app.usefathom.com/api |
| Close | `close` | `api_key` | api_key, basic_auth | yes | https://app.close.com/settings/developer/ |
| Plain | `plain` | `api_key` | api_key, bearer_token | yes | https://app.plain.com/settings/machine-users |
| SendGrid | `sendgrid` | `api_key` | api_key, bearer_token | yes | https://app.sendgrid.com/settings/api_keys |
| Ahrefs | `ahrefs` | `api_key` | api_key, bearer_token | yes | https://ahrefs.com/account/api-keys |
| Brex | `brex` | `user_api_token` | bearer_token, personal_access_token | yes | https://dashboard.brex.com/settings/developer |

**Validation is optional on this route, and its absence is not a defect.** A `browser_ready` recipe must carry a read-only validation endpoint because it claims the automation proved the credential works. A managed-key recipe claims no such thing — Composio validates on publish. Two recipes still carry none, and both are blocked on the host rather than on effort: Jira validates against a per-tenant `<site>.atlassian.net`, and Mailchimp's host embeds a per-account `{dc}` prefix. Neither is expressible as the single reviewed URL the schema requires.

Four more were promoted on 2026-08-09 once the schema grew what they needed. Linear is GraphQL-only and now probes by `POST` with a reviewed, static, secret-free body. Harvest needs a documented `User-Agent` on every request and now sends it as a static `extra_headers` entry. Close authenticates as HTTP basic with the key as the *username* against an empty password, which is now expressible as `basic_password_literal: ""` — the schema previously assumed the credential was always the password half.

Plain was the fourth, and it is worth separating out because the reason it had none was a claim about behaviour, not about schema: a GraphQL error is served as a `200` and would read as a pass. Probing established that this is not true of *authentication* — `https://core-api.uk.plain.com/graphql/v1` rejects a bad bearer at the transport with `401 {"message":"Unauthorized"}`, before any query executes. The 200-on-error hazard is real for a schema or permission error, and that is what the declared identity path is for. Plain publishes its complete SDL at `/graphql/v1/schema.graphql`, where `type Query` declares the no-argument `myWorkspace: Workspace` ("Returns the Workspace associated with the current API key or session … Returns null if no workspace is in context") over `type Workspace { id: ID! }`. So `{ myWorkspace { id } }` binds a working key to the workspace it belongs to, and every remaining way this can go wrong — a key with no workspace in context, or schema drift making the query invalid — lands on `validation_identity_unconfirmed` rather than on a false `valid`.

Notion carries `extra_headers` with `Notion-Version: 2022-06-28`; without it every request 400s regardless of the token.

#### Every validation policy was probed, and two were wrong

On 2026-08-09 all 29 recipes then carrying a validation policy were sent their own reviewed request with an obviously-invalid bearer token — forty zeroes, a value that authenticates to nothing — and the returned status compared against what `ops/credentials/validator.py` maps it to. This is worth doing because a validation policy is the one part of a recipe that makes a claim about a live third party, and nothing else in the repository can tell you whether that claim is still true.

The probe has to reproduce the validator's own request to mean anything. `ops/credentials/validator.py:211` sets `Accept: application/json` on every call it makes and `follow_redirects=False`; a hand-rolled probe that omits either one measures something the system never sends. A first pass here did omit the `Accept` header and produced one false positive, which is recorded below rather than quietly dropped, because it is the failure mode this kind of sweep invites.

26 of the 29 answered `401` or `403` and mapped to `invalid` exactly as intended. Plain's policy, authored the same day out of its own probe, brings the catalog to 30.

**Two were defects in the catalog, and both are now fixed.** Each named an endpoint that does not exist, which meant its validation could never return `valid` for *any* credential — a working key would have been reported as `validation_outcome_unknown` forever:

| App | Was | Is | Evidence |
| --- | --- | --- | --- |
| Sentry | `https://sentry.io/api/0/user/` — 404 for every caller | `https://sentry.io/api/0/users/me/` | answers a bad token `401 {"detail":"Invalid token"}`, so the route is real and authentication is checked on it |
| Ahrefs | `/v3/subscription-info/subscription-info` — the path segment was doubled, 404 | `/v3/subscription-info/limits-and-usage` | answers a bad key `401 ["Error","Unauthorized"]` |

Ahrefs keeps an empty `account_identifier_paths` on purpose: the success body's field names are not published anywhere reviewable, and a declared path that fails to bind turns a working key into `invalid`. The `401` is what proves rejection there. Sentry keeps its existing `("id", "email")` — if those turn out not to bind, the run reads `invalid` rather than `valid`, which is fail-closed and strictly better than the guaranteed 404 it replaced.

**Fathom looked like a third defect and was not.** It answers a request carrying no `Accept` header with `302` to `https://app.usefathom.com/login`, which the validator will not follow, so the first probe scored it `failed`. But the validator always sends `Accept: application/json`, and with that header the same request answers a clean `401`. Adding the header to `extra_headers` was attempted and is correctly refused: `CredentialValidationPolicy` reserves `accept` alongside the credential header and `content-type`, because the validator owns it. Fathom is unchanged, and the recipe schema caught the mistake before it shipped.

**The last two are not defects either, and they are the reason the identity-binding rule exists.** Slack's `auth.test` answers a bad token with HTTP **200** and `{"ok":false,"error":"invalid_auth"}`. Attio's `/v2/self` is an RFC 7662 introspection endpoint and answers a token-shaped-but-invalid value with HTTP **200** and `{"active":false}`. Under a naive "2xx means the credential works" reading, both would publish a dead credential as live. Both are caught: neither body contains the declared identifier, so `_extract_account_identifier` returns `None` and the 2xx becomes `invalid` / `validation_identity_unconfirmed`. That rule was written for Jira and is documented against Jira; it is now tested against two more providers rather than assumed.

The nine `browser_ready` recipes were probed the same way and all nine answered `401` or `403`, so no change was needed there. In particular Cloudflare's `/user/tokens/verify` answers `401`, not the `400` an earlier audit assumed — there is no gap in the `{401, 403}` mapping to widen, and widening it would have been actively harmful, since a `400` normally means *this request was malformed*, which is an authoring bug to be fixed rather than a credential to be blamed.

**Publishing is gated on a separate reviewed fact: the Composio auth scheme.** `POST /api/runs/{id}/managed-key` publishes the key under exactly one of `API_KEY` or `BEARER_TOKEN`, and that choice is a table — `MANAGED_KEY_AUTH_SCHEMES` — not a rule derived from `auth_styles`. Most rows above list two or three styles, so deriving one would be a guess, and a wrong guess does not fail loudly: Composio accepts the connection, reports it `ACTIVE`, and every later tool call fails authentication with nothing in this system pointing back at the cause. Each entry's evidence is the recipe's own reviewed validation policy, because that policy is a request already checked against the live vendor — `auth_scheme: "bearer"` with an empty prefix is `Authorization: Bearer <key>`, which is `BEARER_TOKEN`; `api_key_header` with an empty prefix is a raw key header, which is `API_KEY`.

19 of the 23 resolve today. The other 4 sit in `MANAGED_KEY_SCHEME_UNREVIEWED` with the reason recorded beside the slug, and the run's primary action is disabled with that reason rather than enabled and failing at the provider call:

| Blocked on | Apps | What promotes it |
| --- | --- | --- |
| `companion_consumption_unverified` | Harvest | The key needs a second non-secret value beside it (the account id) to reach the vendor's `Harvest-Account-Id` header. The connection-state type accepts the field, but accepting a field is not the same as forwarding it, and the SDK types do not establish that Composio's Harvest toolkit does. Jira left this state because `BASIC`'s `username` is consumed by the basic-auth header itself. |
| `header_prefix` | Discord | Sent as `Authorization: Bot <token>` — neither a bare key nor a Bearer token. Needs evidence of which scheme Composio's Discord toolkit expects. |
| `no_validation_evidence` | Mailchimp | No validation policy exists to read the scheme off, because the endpoint host embeds a per-account `{dc}` prefix and no single reviewed URL can stand for it. A reviewed probe promotes these — that is exactly how Linear left this table, and how Plain left it on 2026-08-09. |
| `basic_secret_position_unverified` | Close | The HTTP shape *is* reviewed now (key as basic username, empty password), but a basic pair maps to more than one Composio scheme depending on which side the toolkit expects the key on. Guessing produces a connection Composio reports `ACTIVE` that 401s on first use — the failure this table exists to prevent. |

`validate_matrix` enforces that these two tables exactly partition `MANAGED_KEY_SLUGS` and do not overlap, so promoting an app onto this route without deciding its scheme fails catalog load rather than surfacing later as a connection that authenticates against nothing.

### Complete Playwright flow

| App | App slug | Browser scope | Credential | Capture and validation |
| --- | --- | --- | --- | --- |
| Pipedrive | `pipedrive` | reviewed credential surface | `api_token` | automatic capture plus read-only API validation |
| Apify | `apify` | reviewed credential surface | `api_token` | automatic capture plus read-only API validation |
| Firecrawl | `firecrawl` | reviewed credential surface | `api_key` | automatic capture plus read-only API validation |
| Vercel | `vercel` | reviewed credential surface | `personal_access_token` | automatic capture plus read-only API validation |
| Cloudflare | `cloudflare` | reviewed credential surface | `api_token` | automatic capture plus read-only API validation |
| Datadog | `datadog` | reviewed credential surface | `api_key` | automatic capture plus read-only API validation |
| Coda | `coda` | reviewed credential surface | `api_token` | automatic capture plus read-only API validation |
| Klaviyo | `klaviyo` | reviewed credential surface | `private_api_key` | automatic capture plus read-only API validation |
| Bright Data | `bright-data` | reviewed credential surface | `api_token` | automatic capture plus read-only API validation |

A `browser_ready` recipe claims full browser readiness. Its contract requires:

- a reviewed login URL and credential-management URL;
- exact navigation hosts and identity-provider hosts;
- a structured success predicate;
- sensitive selectors that disable screenshots before capture;
- a bounded capture pattern;
- a read-only validation endpoint.

#### On tightening capture patterns

An earlier audit flagged Vercel's `value_pattern` — `[A-Za-z0-9]{24,64}` — as loose enough to capture something that is not the secret, and asked for tighter bounds and a `reveal_selector` across this tier. Neither is authorable today, and it is worth writing down why rather than leaving it as open work.

**Tighter patterns have no evidence behind them.** Neither Vercel nor Coda documents a token length or character set anywhere in its published API reference, and the capture spec is reviewed data — a regex written from a guess is not less risky than a loose one, it is more so. A pattern that is too narrow does not fail loudly: `auto_capture_credentials` simply finds no field that `fullmatch`es, returns `None`, and the run stalls with nothing pointing at the regex. A pattern that is slightly too wide, on this surface, is caught by four other conditions that all have evidence behind them.

Those four are what actually bound the capture, and all nine recipes carry every one of them:

- the page host must equal or be a subdomain of the recipe's `vendor_domain`;
- the path must start with `expected_path_prefix` (`/account/tokens`, `/profile/api-tokens`, and so on);
- `expected_heading` must appear in the page's visible text;
- the selector must match **exactly one** element — `worker.py` skips any selector whose `count()` is not 1, so a second read-only input on the page makes that selector unusable rather than ambiguous.

A value has to clear the host, the path, the heading, a unique selector, *and* the pattern before it is ever written to the vault. The regex is the weakest of the five and the only one that would have to be guessed.

**`reveal_selector` needs the authenticated page.** All nine are `null` today. For the display-once providers (Vercel, Cloudflare, Datadog) there is likely nothing to reveal, because the value is shown outright at creation and never again. For the rest, the control exists but its selector can only be read off a signed-in credential page, which is not something this repository can observe without an account on each vendor. It stays open, and it is owner-gated rather than unresolved.

#### Reviewed signup routes

A recipe may also declare `browser.signup`, which is what lets a run register an account rather than only sign one in. Without it `enter_signup` pauses with `signup_policy_absent`, so the policy's *presence* is the authorization and its `entry_submit_implies_legal_acceptance` flag is the reviewed reading of whether submitting the form accepts the vendor's terms.

Both fields are verbatim page text and are authored from a rendered pass over the live entry page, never from documentation — a guessed submit label silently disables the route, and a guessed legal reading either invents consent or forces a human gate that is not required.

| App | Entry paths | Flow | Submit label | Submitting accepts terms |
| --- | --- | --- | --- | --- |
| Pipedrive | `/en/register` | `email_first` | `Sign up in two minutes` | yes |
| Firecrawl | `/signup`, `/signin` | `dom_detected` | `Create Account` | yes |
| Vercel | `/signup` | `email_first` | `Continue with Email` | yes |
| Coda | `/signup` | `email_first` | `Continue` | yes |

The `flow` column is a claim about step ordering, and the two values are not interchangeable. `email_first` says a reviewer confirmed the route asks for an email alone and only then a password. `dom_detected` says the entry paths and the submit label are evidence-backed but the ordering is read off the live page, resolving to either shape. Firecrawl is `dom_detected` because the render showed email and password together on one form, so claiming `email_first` there would be a false reviewer claim rather than a cautious one.

Firecrawl also shows why these are rendered rather than read off a docs page: `firecrawl.dev/signup` **redirects to `/signin`**, which serves a combined Sign Up / Log In component. `_drive_dom_detected_signup` re-checks the current path against `entry_path_prefixes` on every poll, so a policy naming only `/signup` would have failed with `signup_entry_path_unreviewed` before it ever looked at the form. Both paths are declared.

Vercel is worth reading closely for the opposite reason, because its policy describes more than the page currently offers the automation. `vercel.com/signup` shows federated buttons only; the email form appears after a "Continue with Email" reveal click, which the recipe language cannot yet express. So today the driver finds no email form and takes its existing identity-provider branch, driving the authorized Google handoff. The label and path recorded above are the observed ones, so the same policy describes the email rung correctly once an in-page reveal action exists.

**Two `browser_ready` apps were rendered on 2026-08-09 and deliberately left without a policy.**

*Cloudflare* does not serve a signup form to a fresh browser at all. `dash.cloudflare.com/sign-up` serves a Turnstile interstitial — the document title is "Just a moment...", the headings read "Performing security verification", and the only input present is the hidden `cf-turnstile-response`. Neither required field is observable, and both must be verbatim page text. This is a finding rather than a gap: under the CAPTCHA policy a Cloudflare signup stops for a person at its first page, before a form exists, and that human moment is unavoidable by design.

*Datadog* is a near miss. The page renders completely and both facts are observable — label `Sign Up`, and "By signing up, you agree to the Master Subscription Agreement, Privacy Policy, and Cookie Policy" with no separate checkbox, so acceptance *is* implied by submitting. What stops it is the form: Datadog asks for `email`, `name`, `company`, `password` and `phone`. `_email_password_surfaces` would still match that form, because it requires a unique email and one or two passwords in the same `form` and does not reject extra text inputs. So a policy here would not pause — it would fill the two fields it knows, leave three required fields empty, and submit. The signup state latches submit-at-most-once, so that single doomed submit is the entire attempt. A route that pauses for a human is recoverable; one that spends its only submit on a form it cannot complete is not, which makes `signup_policy_absent` the better outcome until the signup vocabulary can supply a name, a company and a phone number.

A *researched* signup route may fill this in for an app that has none — see `ops/recipes/signup_overlay.py` — but only as a gap fill. An overlay is discarded when the reviewed recipe already declares a signup route, because a researched route cannot assert legal acceptance and would otherwise downgrade an unattended signup to one that stops for a person.

### Playwright entry plus owner submission

These recipes navigate only to the reviewed public entry URL. The success predicate proves that entry, not authentication or credential-page access. The owner obtains the credential outside the automation and submits it through the encrypted form.

| App | App slug | Owner-submitted fields |
| --- | --- | --- |
| Telegram | `telegram` | `bot_token` |
| Shopify | `shopify` | `admin_api_access_token` |
| DataForSEO | `dataforseo` | `login`, `password` |
| Neo4j | `neo4j` | `username`, `password` |
| Xero | `xero` | `client_id`, `client_secret` |

An owner-submit recipe must not contain a credential-management URL, automatic capture specification, or validation policy. Its bundle remains explicitly unvalidated.

Klaviyo and Bright Data left this route on 2026-08-09 for the credential-surface table above. What each was waiting on was a credential page evidenced deeply enough to prove itself: Klaviyo's `/settings/account/api-keys` is preserved through the vendor's own `?next=` login bounce, and Bright Data's `/cp/setting/users` is route-validated outright, since a sibling nonsense path under the same prefix `404`s.

The five that remain are blocked on the schema, not on research:

- **DataForSEO** needs a two-field capture (`login` and `password` are both read off the API Access tab), and both fields' selectors must be declared sensitive. The page is a client-rendered SPA behind login on a host that answers `200` for *every* path, so no unauthenticated request can observe its DOM, its literal control text, or a value shape. There is nothing to write down that would not be a guess, and a guessed success predicate is a run that hangs rather than one that fails.
- **Shopify** and **Neo4j** need per-tenant hosts (`<store>.myshopify.com`) and a URL fragment route respectively.
- **Xero**'s probe is now expressible — a client-credentials `POST` is basic auth over `client_id`/`client_secret` with a static `grant_type=client_credentials` body — but its credentials are not *captured*, they are minted by creating an OAuth app in the developer portal. That is an app-creation flow, not a key-reveal page, and no reviewed trace for it exists.
- **Telegram** issues its token through a chat conversation and validates with the secret in the URL *path*, which the header-only validation schema cannot express.

### Gated review

The gated recipes never start a browser. Only Freshdesk has a reviewed email contact and may prepare controlled-sink outreach after an explicit owner action. The other five have reviewed contact URLs but no reviewed email-send route, so they remain review-required.

Five apps left this route on 2026-08-08 — Close, Plain, SendGrid, Ahrefs, and Brex — once research established that each mints an own-account key from a settings page with no vendor approval in the loop. What had been read as a gate was a gate on *public partner distribution*, which is not what these runs do.

The six that remain were re-verified on 2026-08-09 against the vendors' own current documentation, on the theory that the newly added `POST` validation method might unblock the two OAuth ones. It does not. Each row below now records the specific reason rather than a category, and every one of the six is blocked by something outside this repository — a per-tenant host, a vendor approval queue, a token exchange that would have to carry a secret in a reviewed body, or a business verification that no code change reaches.

| App | App slug | Readiness | Gate |
| --- | --- | --- | --- |
| Freshdesk | `freshdesk` | `outreach_ready` | public Marketplace review; custom customer apps are not reviewed. Self-serve keys exist but only at the per-tenant `<domain>.freshdesk.com` host |
| Help Scout | `help-scout` | `outreach_review_required` | the self-serve credential is an OAuth `client_secret`, not a bearer token. Adding `POST` validation did not unblock it: Help Scout's token endpoint takes `client_id` and `client_secret` as **body** parameters and documents no HTTP Basic alternative, and no reviewed body here may carry a secret. There is no long-lived key — every token is a two-day bearer minted by that exchange |
| Snowflake | `snowflake` | `outreach_review_required` | Marketplace Connected App partner and security review; also a per-account host |
| Ramp | `ramp` | `outreach_review_required` | third-party production partner and security review. The `POST` relaxation does not unblock it either, for two independent reasons. The credential pair is *minted by registering an application* in the Ramp Developer Console — an app-creation flow like Xero's, not a key revealed on a settings page — and third-party production access is approved, not self-serve. And the token exchange itself cannot be authored from evidence: `docs.ramp.com` renders as a JavaScript shell, its machine-readable `llms-api.txt` carries the `/developer/v1/*` schemas with no authentication section at all, and `llms-full.txt` says only that Ramp *"typically"* uses HTTP Basic for `/developer/v1/token` while *"some clients may be configured to send `client_id` and `client_secret` in the form body instead"*. Hedged prose is not a reviewed auth method |
| Meta Ads | `meta-ads` | `outreach_review_required` | app review and business verification; `contact_email` is null, so outreach cannot reach it either |
| LinkedIn Ads | `linkedin-ads` | `outreach_review_required` | Advertising API approval; `contact_email` is null |

A controlled recipient override is not evidence of a vendor contact. It cannot promote a recipe to `outreach_ready`.

## Safety invariants

Every recipe must preserve these constraints:

- operational URLs are HTTPS and backed by explicit evidence;
- browser navigation hosts are exact. Wildcards are accepted only on the two
  fields that never name a navigation target — `static_resource_hosts` (CDN and
  egress) and the verification mail hosts — and `ops/recipes/app_recipes.py`
  validates `exact_hosts`, `identity_provider_hosts`, and `post_auth_hosts` with
  `wildcard=False`. A per-tenant vendor (`<store>.myshopify.com`) is therefore
  not expressible today; that is a known gap, not an oversight;
- research results cannot expand the browser allowlist;
- the first Playwright step opens the recipe's reviewed login URL;
- sensitive values never enter instructions, model context, screenshots, checkpoints, audit events, or API output;
- credential creation and capture remain inside the recipe's declared scope;
- CAPTCHA, MFA, account selection, billing, legal consent, device approval, and ambiguous actions are human gates;
- missing configuration fails closed without switching routes.

## Promoting readiness

Promotions require a recipe review, not merely a successful manual experiment.

To promote an entry-only recipe to `browser_ready`, add all of:

1. evidenced credential-management URL;
2. reviewed exact host policy;
3. deterministic login-to-credential steps;
4. structured success predicate;
5. sensitive selector set;
6. bounded capture specification;
7. read-only validation policy;
8. tests proving secret and retry boundaries.

To promote a gated recipe to `outreach_ready`, add a reviewed vendor contact and evidence while preserving the controlled-sink sending policy.

To promote any recipe to `managed_key`, add all of:

1. an evidenced `urls.credential_management` page the owner can reach unaided, on an exact host — a per-tenant host disqualifies the app until reviewed wildcards land;
2. `credential_fields` naming exactly what that page issues, with the secret marked as such;
3. `auth_styles` covering how the key is presented;
4. `capture.mode: "owner_submit"` and no `browser` block — this route never opens a page;
5. the slug added to `MANAGED_KEY_SLUGS` and removed from whichever tuple it left;
6. the slug added to exactly one of `MANAGED_KEY_AUTH_SCHEMES` (with the reviewed scheme) or `MANAGED_KEY_SCHEME_UNREVIEWED` (with the reason it is not publishable yet). `validate_matrix` fails catalog load if it is in neither or both. Do not add a plausible scheme to clear the check — an unreviewed app that refuses is correct, and a guessed one produces a connection that reports `ACTIVE` and fails on first use.

A read-only validation policy is welcome but not required, and omitting one is not a downgrade. Do not invent a `GET` endpoint to satisfy a checklist: a validation policy that cannot actually succeed is worse than none, because the run will report a credential failure the owner cannot act on.

## Validate changes

```bash
# `source .venv/bin/activate` silently falls back to a pytest-less interpreter.
./.venv/bin/python -m pytest -q tests/test_app_recipes.py
./.venv/bin/python -m ruff check ops/recipes/app_recipes.py tests/test_app_recipes.py
```

Catalog validation enforces the exact app set and the route assigned to each app. A count of 50 alone is not sufficient. File order is deliberately *not* enforced — `validate_matrix` compares sorted slugs — so a recipe can be rewritten in place and its slug moved between route tuples without reordering the JSON.
