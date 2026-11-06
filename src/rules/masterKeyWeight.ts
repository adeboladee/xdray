import type { Finding } from "../types.js";
import { extractSignerKeyInfo } from "./signerKey.js";
import type { Rule, RuleContext, RuleResult } from "./types.js";

const RULE_ID = "master-key-weight" as const;

interface AccountMasterWeightState {
  account: string;
  lastMasterWeightOp: {
    index: number;
    weight: unknown;
  } | null;
  signerTouchedKeys: string[];
}

export const masterKeyWeightRule: Rule = {
  id: RULE_ID,

  evaluate({ transaction }: RuleContext): Promise<RuleResult> {
    const findings: Finding[] = [];
    const accountsMap = new Map<string, AccountMasterWeightState>();

    for (const [operationIndex, operation] of transaction.operations.entries()) {
      if (operation.type !== "setOptions") {
        continue;
      }

      const account = operation.account;
      let state = accountsMap.get(account);
      if (!state) {
        state = {
          account,
          lastMasterWeightOp: null,
          signerTouchedKeys: [],
        };
        accountsMap.set(account, state);
      }

      if (operation.masterWeight !== undefined && operation.masterWeight !== null) {
        state.lastMasterWeightOp = {
          index: operationIndex,
          weight: operation.masterWeight,
        };
      }

      if (operation.signer !== undefined && operation.signer !== null) {
        const weight = operation.signer.weight;
        if (weight !== 0) {
          const isValidWeight =
            typeof weight === "number" &&
            Number.isInteger(weight) &&
            weight >= 0 &&
            weight <= 255;

          if (!isValidWeight) {
            state.signerTouchedKeys.push("a signer this tool could not read");
          } else {
            const keyInfo = extractSignerKeyInfo(operation.signer);
            if (keyInfo) {
              state.signerTouchedKeys.push(keyInfo.keyStr);
            } else {
              state.signerTouchedKeys.push("a signer this tool could not read");
            }
          }
        }
      }
    }

    for (const state of accountsMap.values()) {
      if (state.lastMasterWeightOp === null) {
        continue;
      }

      const { index: operationIndex, weight: finalMasterWeight } =
        state.lastMasterWeightOp;
      const account = state.account;

      const isValidMasterWeight =
        typeof finalMasterWeight === "number" &&
        Number.isInteger(finalMasterWeight) &&
        finalMasterWeight >= 0 &&
        finalMasterWeight <= 255;

      if (!isValidMasterWeight) {
        findings.push({
          ruleId: RULE_ID,
          severity: "warning",
          operationIndex,
          assetCode: null,
          issuer: null,
          reason: "master-weight-invalid",
          account,
          message:
            `This operation sets a master key weight on account ${account} that this tool could not read as a number from 0 to 255, so it could not be checked.`,
        });
        continue;
      }

      if (finalMasterWeight === 0) {
        const distinctKeys: string[] = [];
        for (const key of state.signerTouchedKeys) {
          if (!distinctKeys.includes(key)) {
            distinctKeys.push(key);
          }
        }

        if (distinctKeys.length === 0) {
          findings.push({
            ruleId: RULE_ID,
            severity: "critical",
            operationIndex,
            assetCode: null,
            issuer: null,
            reason: "master-key-disabled",
            account,
            message:
              `This operation sets the master key weight of account ${account} to 0. ` +
              "That key will no longer be able to sign anything for the account, even operations with a threshold of 0. " +
              "If no other signer on the account can reach its thresholds, the account is permanently locked. " +
              "This transaction cannot show the account's current signers, so only sign if you are sure other signers can control the account.",
          });
        } else {
          let keysText: string;
          if (distinctKeys.length <= 5) {
            keysText = distinctKeys.join(", ");
          } else {
            const first5 = distinctKeys.slice(0, 5);
            const remaining = distinctKeys.length - 5;
            keysText = `${first5.join(", ")}, and ${remaining} more`;
          }

          findings.push({
            ruleId: RULE_ID,
            severity: "critical",
            operationIndex,
            assetCode: null,
            issuer: null,
            reason: "control-handover",
            account,
            message:
              `This transaction switches off account ${account}'s own key (master key weight 0) and gives signing control to: ${keysText}. ` +
              "A legitimate key rotation looks exactly like this, so only sign if you control every key listed. " +
              "If you did not set this up yourself, do not sign.",
          });
        }
      } else {
        findings.push({
          ruleId: RULE_ID,
          severity: "info",
          operationIndex,
          assetCode: null,
          issuer: null,
          reason: "master-key-weight-changed",
          account,
          message:
            `This operation changes the master key weight of account ${account} to ${finalMasterWeight}.`,
        });
      }
    }

    return Promise.resolve({
      findings,
      verified: [],
      unhandled: [],
    });
  },
};

