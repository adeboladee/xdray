import type { UnhandledOperation } from "../types.js";
import type { Rule, RuleContext, RuleResult } from "./types.js";

const RULE_ID = "set-options-coverage" as const;

function formatFieldGroups(groups: string[]): string {
  if (groups.length === 1) {
    return groups[0]!;
  }
  if (groups.length === 2) {
    return `${groups[0]} and ${groups[1]}`;
  }
  return `${groups.slice(0, -1).join(", ")} and ${groups[groups.length - 1]}`;
}

export const setOptionsCoverageRule: Rule = {
  id: RULE_ID,

  evaluate({ transaction }: RuleContext): Promise<RuleResult> {
    const unhandled: UnhandledOperation[] = [];

    for (const [operationIndex, operation] of transaction.operations.entries()) {
      if (operation.type !== "setOptions") {
        continue;
      }

      const groups: string[] = [];

      const hasThresholds =
        (operation.lowThreshold !== undefined &&
          operation.lowThreshold !== null) ||
        (operation.medThreshold !== undefined &&
          operation.medThreshold !== null) ||
        (operation.highThreshold !== undefined &&
          operation.highThreshold !== null);

      if (hasThresholds) {
        groups.push("thresholds");
      }

      const hasHomeDomain =
        operation.homeDomain !== undefined && operation.homeDomain !== null;

      if (hasHomeDomain) {
        groups.push("home domain");
      }

      const hasFlags =
        (operation.setFlags !== undefined && operation.setFlags !== null) ||
        (operation.clearFlags !== undefined && operation.clearFlags !== null);

      if (hasFlags) {
        groups.push("account flags");
      }

      const hasInflationDest =
        operation.inflationDest !== undefined &&
        operation.inflationDest !== null;

      if (hasInflationDest) {
        groups.push("inflation destination");
      }

      if (groups.length > 0) {
        const groupsText = formatFieldGroups(groups);
        unhandled.push({
          operationIndex,
          reason: "set-options-fields-unchecked",
          message:
            `This setOptions operation changes ${groupsText} on account ${operation.account}. ` +
            "These fields are not checked yet, so a clean result does not cover them.",
        });
      }
    }

    return Promise.resolve({
      findings: [],
      verified: [],
      unhandled,
    });
  },
};

