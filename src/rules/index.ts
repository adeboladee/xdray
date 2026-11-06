import { lookalikeAssetIssuerRule } from "./lookalikeAssetIssuer.js";
import { masterKeyWeightRule } from "./masterKeyWeight.js";
import { setOptionsCoverageRule } from "./setOptionsCoverage.js";
import { signerChangeRule } from "./signerChange.js";
import type { Rule } from "./types.js";

export const rules: readonly Rule[] = [
  lookalikeAssetIssuerRule,
  signerChangeRule,
  masterKeyWeightRule,
  setOptionsCoverageRule,
];

export { lookalikeAssetIssuerRule } from "./lookalikeAssetIssuer.js";
export { masterKeyWeightRule } from "./masterKeyWeight.js";
export { setOptionsCoverageRule } from "./setOptionsCoverage.js";
export { signerChangeRule } from "./signerChange.js";
export type { Rule, RuleContext, RuleResult } from "./types.js";
