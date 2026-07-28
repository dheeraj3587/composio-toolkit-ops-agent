# Application recipes

`ops/app_recipes.json` is the data source for new canonical runs. `ops/app_recipes.py` validates it at startup against an exact 50-app matrix.

Current catalog:

- schema: `1.0`
- catalog ID: `approved-50-routes-2026-07-28`
- routes: 25 managed authentication, 14 Playwright, 11 gated
- readiness: 25 `managed_auth_ready`, 1 `browser_ready`, 13 `owner_submit_ready`, 4 `outreach_ready`, 7 `outreach_review_required`

Recipe readiness describes reviewed automation scope. It is not evidence that a provider is configured, a user has authorized an account, or a live run has succeeded.

## Route contracts

### Managed authentication

A managed recipe has a reviewed Composio toolkit slug and OAuth evidence. It does not start a browser or handle raw OAuth tokens. A run completes only after Composio reports the connected account active.

| App | App slug | Toolkit slug |
| --- | --- | --- |
| Salesforce | `salesforce` | `salesforce` |
| HubSpot | `hubspot` | `hubspot` |
| Attio | `attio` | `attio` |
| Zendesk | `zendesk` | `zendesk` |
| Intercom | `intercom` | `intercom` |
| Gorgias | `gorgias` | `gorgias` |
| Slack | `slack` | `slack` |
| Discord | `discord` | `discord` |
| Google Ads | `google-ads` | `googleads` |
| Mailchimp | `mailchimp` | `mailchimp` |
| Gumroad | `gumroad` | `gumroad` |
| GitHub | `github` | `github` |
| Supabase | `supabase` | `supabase` |
| Sentry | `sentry` | `sentry` |
| Notion | `notion` | `notion` |
| Airtable | `airtable` | `airtable` |
| Linear | `linear` | `linear` |
| Jira | `jira` | `jira` |
| Asana | `asana` | `asana` |
| Monday.com | `monday` | `monday` |
| ClickUp | `clickup` | `clickup` |
| Harvest | `harvest` | `harvest` |
| Stripe | `stripe` | `stripe` |
| QuickBooks | `quickbooks` | `quickbooks` |
| Fathom | `fathom` | `fathom` |

### Complete Playwright flow

| App | App slug | Browser scope | Credential | Capture and validation |
| --- | --- | --- | --- | --- |
| Pipedrive | `pipedrive` | reviewed credential surface | `api_token` | automatic capture plus read-only API validation |

Pipedrive is the only recipe allowed to claim full browser readiness. Its contract requires:

- a reviewed login URL and credential-management URL;
- exact navigation hosts and identity-provider hosts;
- a structured success predicate;
- sensitive selectors that disable screenshots before capture;
- a bounded capture pattern;
- a read-only validation endpoint.

### Playwright entry plus owner submission

These recipes navigate only to the reviewed public entry URL. The success predicate proves that entry, not authentication or credential-page access. The owner obtains the credential outside the automation and submits it through the encrypted form.

| App | App slug | Owner-submitted fields |
| --- | --- | --- |
| Telegram | `telegram` | `bot_token` |
| Klaviyo | `klaviyo` | `private_api_key` |
| Shopify | `shopify` | `admin_api_access_token` |
| DataForSEO | `dataforseo` | `login`, `password` |
| Apify | `apify` | `api_token` |
| Firecrawl | `firecrawl` | `api_key` |
| Bright Data | `bright-data` | `api_token` |
| Vercel | `vercel` | `personal_access_token` |
| Cloudflare | `cloudflare` | `api_token` |
| Neo4j | `neo4j` | `username`, `password` |
| Datadog | `datadog` | `api_key`, `application_key` |
| Coda | `coda` | `api_token` |
| Xero | `xero` | `client_id`, `client_secret` |

An owner-submit recipe must not contain a credential-management URL, automatic capture specification, or validation policy. Its bundle remains explicitly unvalidated.

### Gated review

The gated recipes never start a browser. Close, Freshdesk, Ahrefs, and Brex have reviewed email contacts and may prepare controlled-sink outreach after an explicit owner action. Meta Ads, LinkedIn Ads, Snowflake, and Ramp have reviewed contact URLs but no reviewed email-send route, so they remain review-required. Plain, Help Scout, and SendGrid are self-serve for own-account credentials and remain disabled in this fixed matrix until they are deliberately reclassified.

| App | App slug | Gate |
| --- | --- | --- |
| Close | `close` | public cross-customer OAuth review; own-account keys are self-serve |
| Freshdesk | `freshdesk` | public Marketplace review; custom customer apps are not reviewed |
| Plain | `plain` | self-serve; awaiting route reclassification |
| Help Scout | `help-scout` | self-serve OAuth app; awaiting route reclassification |
| Meta Ads | `meta-ads` | app review and business verification |
| LinkedIn Ads | `linkedin-ads` | Advertising API approval |
| SendGrid | `sendgrid` | self-serve API key; awaiting route reclassification |
| Ahrefs | `ahrefs` | Ahrefs Connect public OAuth approval; direct eligible-plan keys are self-serve |
| Snowflake | `snowflake` | Marketplace Connected App partner and security review |
| Brex | `brex` | partner OAuth issuance; own-account admin tokens are self-serve |
| Ramp | `ramp` | third-party production partner and security review |

A controlled recipient override is not evidence of a vendor contact. It cannot promote a recipe to `outreach_ready`.

## Safety invariants

Every recipe must preserve these constraints:

- operational URLs are HTTPS and backed by explicit evidence;
- browser hosts are exact or explicitly reviewed wildcards;
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

## Validate changes

```bash
source .venv/bin/activate
python -m pytest -q tests/test_app_recipes.py
python -m ruff check ops/app_recipes.py tests/test_app_recipes.py
```

Catalog validation enforces the exact app order and route assignment. A count of 50 alone is not sufficient.
