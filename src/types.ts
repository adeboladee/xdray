import type { OperationRecord } from "@stellar/stellar-sdk";

export type Severity = "critical" | "warning" | "info";

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
  | "analysis-failed"
  | "signer-removed"
  | "signer-ed25519"
  | "signer-hash-x"
  | "signer-pre-auth-tx"
  | "signer-signed-payload"
  | "unsupported-signer";

export interface Finding {
  ruleId: string;
  severity: Severity;
  operationIndex: number | null;
  assetCode: string | null;
  issuer: string | null;
  reason: FindingReason;
  message: string;
  account?: string;
}

export interface VerifiedAsset {
  ruleId: string;
  operationIndex: number;
  assetCode: string;
  issuer: string;
  homeDomain: string;
  punycode: boolean;
  homeDomainUnicode?: string;
}

export type ParsedOperation = OperationRecord & {
  readonly account: string;
};

export interface ParsedTransaction {
  sourceAccount: string;
  operations: ParsedOperation[];
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
