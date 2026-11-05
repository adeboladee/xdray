import { lookalikeAssetIssuerRule } from "./lookalikeAssetIssuer.js";
import { signerChangeRule } from "./signerChange.js";
import type { Rule } from "./types.js";

export const rules: readonly Rule[] = [
  lookalikeAssetIssuerRule,
  signerChangeRule,
];

export { lookalikeAssetIssuerRule } from "./lookalikeAssetIssuer.js";
export { signerChangeRule } from "./signerChange.js";
export type { Rule, RuleContext, RuleResult } from "./types.js";
