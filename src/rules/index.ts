import type { Rule } from "./lookalikeAssetIssuer.js";
import { lookalikeAssetIssuerRule } from "./lookalikeAssetIssuer.js";

export const rules: readonly Rule[] = [lookalikeAssetIssuerRule];

export type { Rule, RuleContext, RuleResult } from "./lookalikeAssetIssuer.js";
