import { StrKey } from "@stellar/stellar-sdk";

import type {
  Finding,
  FindingReason,
  ParsedOperation,
  Severity,
} from "../types.js";
import type { Rule, RuleContext, RuleResult } from "./types.js";

const RULE_ID = "signer-change" as const;

type SignerRecord = NonNullable<
  Extract<ParsedOperation, { type: "setOptions" }>["signer"]
>;

type SignerKeyType =
  | "ed25519"
  | "hash-x"
  | "pre-auth-tx"
  | "signed-payload";

interface SignerKeyInfo {
  keyStr: string;
  keyType: SignerKeyType;
}

function extractSignerKeyInfo(signer: SignerRecord): SignerKeyInfo | null {
  if (
    "ed25519PublicKey" in signer &&
    typeof signer.ed25519PublicKey === "string"
  ) {
    return {
      keyStr: signer.ed25519PublicKey,
      keyType: "ed25519",
    };
  }

  if ("sha256Hash" in signer && signer.sha256Hash instanceof Uint8Array) {
    const strkey = StrKey.encodeSha256Hash(signer.sha256Hash);
    const hex = Buffer.from(signer.sha256Hash).toString("hex");
    return {
      keyStr: `${strkey} (hex: ${hex})`,
      keyType: "hash-x",
    };
  }

  if ("preAuthTx" in signer && signer.preAuthTx instanceof Uint8Array) {
    const strkey = StrKey.encodePreAuthTx(signer.preAuthTx);
    const hex = Buffer.from(signer.preAuthTx).toString("hex");
    return {
      keyStr: `${strkey} (hex: ${hex})`,
      keyType: "pre-auth-tx",
    };
  }

  if (
    "ed25519SignedPayload" in signer &&
    typeof signer.ed25519SignedPayload === "string"
  ) {
    return {
      keyStr: signer.ed25519SignedPayload,
      keyType: "signed-payload",
    };
  }

  return null;
}

function resolveReason(
  keyType: SignerKeyType,
  weight: number,
): FindingReason {
  if (weight === 0) {
    return "signer-removed";
  }

  switch (keyType) {
    case "ed25519":
      return "signer-ed25519";
    case "hash-x":
      return "signer-hash-x";
    case "pre-auth-tx":
      return "signer-pre-auth-tx";
    case "signed-payload":
      return "signer-signed-payload";
  }
}

function buildMessage(
  account: string,
  keyStr: string,
  keyType: SignerKeyType,
  weight: number,
): string {
  if (weight === 0) {
    return `This operation removes signer ${keyStr} from account ${account} (weight 0).`;
  }

  const parts = [
    `This operation adds or changes signer ${keyStr} on account ${account} with weight ${weight}.`,
  ];

  if (weight === 255) {
    parts.push(
      "A weight of 255 lets this signer authorize every operation on the account by itself.",
    );
  }

  if (keyType === "hash-x") {
    parts.push(
      "Anyone who learns the secret value behind this hash can sign for the account, and that value becomes public the first time it is used.",
    );
  } else if (keyType === "pre-auth-tx") {
    parts.push(
      "This authorizes one specific, already-built transaction that cannot be inspected from this one. The signer is removed automatically when that transaction is applied.",
    );
  }

  parts.push("If you did not set this up yourself, do not sign.");

  return parts.join(" ");
}

export const signerChangeRule: Rule = {
  id: RULE_ID,

  evaluate({ transaction }: RuleContext): Promise<RuleResult> {
    const findings: Finding[] = [];

    for (const [operationIndex, operation] of transaction.operations.entries()) {
      if (operation.type !== "setOptions") {
        continue;
      }

      const signer = operation.signer;
      if (!signer) {
        continue;
      }

      const keyInfo = extractSignerKeyInfo(signer);
      const weight = signer.weight;
      const isValidWeight =
        typeof weight === "number" &&
        Number.isInteger(weight) &&
        weight >= 0 &&
        weight <= 255;

      if (!keyInfo || !isValidWeight) {
        findings.push({
          ruleId: RULE_ID,
          severity: "warning",
          operationIndex,
          assetCode: null,
          issuer: null,
          reason: "unsupported-signer",
          account: operation.account,
          message:
            `This operation changes a signer on account ${operation.account} in a form this tool could not read, so it could not be checked. ` +
            "If you did not set this up yourself, do not sign.",
        });
        continue;
      }

      const severity: Severity =
        weight === 0 ? "info" : weight === 255 ? "critical" : "warning";

      const reason = resolveReason(keyInfo.keyType, weight);
      const message = buildMessage(
        operation.account,
        keyInfo.keyStr,
        keyInfo.keyType,
        weight,
      );

      findings.push({
        ruleId: RULE_ID,
        severity,
        operationIndex,
        assetCode: null,
        issuer: null,
        reason,
        account: operation.account,
        message,
      });
    }

    return Promise.resolve({
      findings,
      verified: [],
      unhandled: [],
    });
  },
};
