import "server-only"

import { z } from "zod"

import * as base from "@/lib/api-schemas-base"

export {
  actionReceiptSchema,
  browserLifecycleSchema,
  browserProviderSchema,
  browserUiStateSchema,
  credentialCreationPolicySchema,
  healthResponseSchema,
  liveViewModeSchema,
  liveViewResponseSchema,
  operationalUrlClaim,
  operationalUrlField,
  snapshotHealthSchema,
  timelineResponseSchema,
} from "@/lib/api-schemas-base"

/**
 * Production API schemas added by the autonomous-signup policy work.
 *
 * The complete pre-existing response-validation layer lives in
 * `api-schemas-base.ts`, restored byte-for-byte from the reviewed base commit.
 * This module extends only the fields whose backend vocabulary changed. Keeping
 * the delta explicit prevents another broad schema replacement from silently
 * deleting strict validation at the API boundary.
 */
export const accountPolicySchema = z.enum(["reuse_existing", "create_if_missing"])
export const developerAppPolicySchema = z.enum(["reuse_existing", "create_if_missing"])
export const credentialPolicySchema = z.enum(["reuse_existing", "create_if_missing"])

const accessRouteSchema = z.enum([
  "self_serve",
  "self_serve_with_hitl",
  "approval_required",
  "partner_gated",
  "hybrid",
  "blocked",
  "unsupported",
  "unknown",
])

export const operationalResearchSchema = base.operationalResearchSchema.extend({
  access_route: accessRouteSchema,
})

export const runSummarySchema = base.runSummarySchema.extend({
  access_route: accessRouteSchema.nullish(),
  account_policy: accountPolicySchema.default("reuse_existing"),
  developer_app_policy: developerAppPolicySchema.default("reuse_existing"),
  credential_policy: credentialPolicySchema.default("reuse_existing"),
})

const routeDecisionSchema = z.strictObject({
  route: accessRouteSchema,
  reason_code: z.string().regex(/^[a-z0-9][a-z0-9_.:-]{0,119}$/i),
  explanation: z.string().min(1).max(1_000),
  is_final: z.boolean().optional(),
})

export const runDetailResponseSchema = base.runDetailResponseSchema.extend({
  run: runSummarySchema,
  research: operationalResearchSchema.nullable(),
  route_decision: routeDecisionSchema.nullish(),
})

export const runListResponseSchema = base.runListResponseSchema.extend({
  items: z.array(runSummarySchema).max(100),
})

const integratorBundleSchema = base.runOutputResponseSchema.shape.integrator_bundle.extend({
  access_route: accessRouteSchema,
})

export const runOutputResponseSchema = base.runOutputResponseSchema.extend({
  integrator_bundle: integratorBundleSchema,
})

export const appSearchItemSchema = base.appSearchItemSchema.extend({
  access_route: accessRouteSchema.nullable().default(null),
})

export const appSearchResponseSchema = base.appSearchResponseSchema.extend({
  items: z.array(appSearchItemSchema).max(100),
})

export const appCatalogResponseSchema = base.appCatalogResponseSchema.extend({
  items: z.array(appSearchItemSchema).max(500),
})

export const appResearchResponseSchema = base.appResearchResponseSchema.extend({
  app: appSearchItemSchema,
  research: operationalResearchSchema,
})
