import type { StellarNetwork } from "./network.js";
import { parseEnvelope } from "./parseEnvelope.js";
import { lookalikeAssetIssuerRule } from "./rules/lookalikeAssetIssuer.js";
import type { AnalysisResult, Finding } from "./types.js";

function describeError(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

export async function analyzeTransaction(
  xdr: string,
  networkPassphrase: string,
  network: StellarNetwork,
): Promise<AnalysisResult> {
  let transaction;

  try {
    transaction = parseEnvelope(xdr, networkPassphrase);
  } catch (error) {
    const finding: Finding = {
      ruleId: "envelope-parse",
      severity: "warning",
      operationIndex: null,
      assetCode: null,
      issuer: null,
      reason: "invalid-xdr",
      message:
        "The transaction envelope could not be read, so it could not be checked for unsafe actions. " +
        `Details: ${describeError(error)}`,
    };

    return {
      transaction: null,
      findings: [finding],
      verified: [],
      unhandled: [],
    };
  }

  try {
    const result = await lookalikeAssetIssuerRule.evaluate({
      transaction,
      network,
    });

    return {
      transaction,
      findings: result.findings,
      verified: result.verified,
      unhandled: result.unhandled,
    };
  } catch (error) {
    const finding: Finding = {
      ruleId: "lookalike-asset-issuer",
      severity: "warning",
      operationIndex: null,
      assetCode: null,
      issuer: null,
      reason: "analysis-failed",
      message:
        "This transaction could not be fully checked for look-alike assets. " +
        `Details: ${describeError(error)}`,
    };

    return {
      transaction,
      findings: [finding],
      verified: [],
      unhandled: [],
    };
  }
}
