import type { StellarNetwork } from "./network.js";
import { parseEnvelope } from "./parseEnvelope.js";
import { rules } from "./rules/index.js";
import type {
  AnalysisResult,
  Finding,
  UnhandledOperation,
  VerifiedAsset,
} from "./types.js";

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

  const findings: Array<{ finding: Finding; ruleIndex: number }> = [];
  const verified: VerifiedAsset[] = [];
  const unhandled: UnhandledOperation[] = [];

  for (const [ruleIndex, rule] of rules.entries()) {
    try {
      const result = await rule.evaluate({ transaction, network });

      for (const finding of result.findings) {
        findings.push({ finding, ruleIndex });
      }

      verified.push(...result.verified);
      unhandled.push(...result.unhandled);
    } catch (error) {
      findings.push({
        ruleIndex,
        finding: {
          ruleId: rule.id,
          severity: "warning",
          operationIndex: null,
          assetCode: null,
          issuer: null,
          reason: "analysis-failed",
          message:
            `Rule ${rule.id} could not check this transaction. ` +
            `Details: ${describeError(error)}`,
        },
      });
    }
  }

  findings.sort((left, right) => {
    const leftOperation =
      left.finding.operationIndex ?? Number.POSITIVE_INFINITY;
    const rightOperation =
      right.finding.operationIndex ?? Number.POSITIVE_INFINITY;

    if (leftOperation !== rightOperation) {
      return leftOperation - rightOperation;
    }

    return left.ruleIndex - right.ruleIndex;
  });

  return {
    transaction,
    findings: findings.map(({ finding }) => finding),
    verified,
    unhandled,
  };
}
