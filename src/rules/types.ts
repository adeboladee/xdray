import type { StellarNetwork } from "../network.js";
import type {
  Finding,
  ParsedTransaction,
  UnhandledOperation,
  VerifiedAsset,
} from "../types.js";

export interface RuleContext {
  transaction: ParsedTransaction;
  network: StellarNetwork;
}

export interface RuleResult {
  findings: Finding[];
  verified: VerifiedAsset[];
  unhandled: UnhandledOperation[];
}

export interface Rule {
  readonly id: string;
  evaluate(context: RuleContext): Promise<RuleResult>;
}

