import type { OperationRecord } from "@stellar/stellar-sdk";

export type Severity = "warning" | "critical";

export type FindingReason =
  | "invalid-xdr"
  | "issuer-mismatch"
  | "asset-not-listed"
  | "unsupported-asset"
  | "account-unreachable"
  | "no-home-domain"
  | "invalid-home-domain"
  | "toml-unreachable"
  | "toml-malformed"
  | "lookup-limit-exceeded"
  | "analysis-failed";

export interface Finding {
  ruleId: "lookalike-asset-issuer" | "envelope-parse";
  severity: Severity;
  operationIndex: number | null;
  assetCode: string | null;
  issuer: string | null;
  reason: FindingReason;
  message: string;
}

export interface VerifiedAsset {
  ruleId: "lookalike-asset-issuer";
  operationIndex: number;
  assetCode: string;
  issuer: string;
  homeDomain: string;
  punycode: boolean;
  homeDomainUnicode?: string;
}

export interface ParsedTransaction {
  sourceAccount: string;
  operations: OperationRecord[];
  feeBumped: boolean;
}

export interface UnhandledOperation {
  operationIndex: number;
  reason: "liquidity-pool-trustline";
  message: string;
}

export interface AnalysisResult {
  transaction: ParsedTransaction | null;
  findings: Finding[];
  verified: VerifiedAsset[];
  unhandled: UnhandledOperation[];
}
