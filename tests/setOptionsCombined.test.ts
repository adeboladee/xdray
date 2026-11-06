// No real mainnet set_options fixture is included yet (none were found in the 3,000 most recent operations); these transactions are built in code.

import { Networks, Operation } from "@stellar/stellar-sdk";
import { describe, expect, it } from "vitest";

import { analyzeTransaction } from "../src/index.js";
import { FakeStellarNetwork } from "./fakeNetwork.js";
import { changeTrust, ISSUER, SOURCE } from "./helpers.js";
import {
  buildSetOptionsEnvelope,
  testPublicKey,
} from "./setOptionsHelpers.js";

const emptyNetwork = () => new FakeStellarNetwork();

describe("setOptions fixtures & rule coexistence", () => {
  describe("synthetic setOptions tests", () => {
    it("case (a) synthetic: adds or changes a signer with weight > 0", async () => {
      const signerKey = testPublicKey(100);
      const envelope = buildSetOptionsEnvelope([
        Operation.setOptions({
          signer: {
            ed25519PublicKey: signerKey,
            weight: 10,
          },
        }),
      ]);

      const result = await analyzeTransaction(
        envelope,
        Networks.TESTNET,
        emptyNetwork(),
      );

      expect(result.findings).toHaveLength(1);
      expect(result.findings[0]).toMatchObject({
        ruleId: "signer-change",
        severity: "warning",
        operationIndex: 0,
        reason: "signer-ed25519",
        account: SOURCE,
      });
      expect(result.findings[0]?.message).toContain(signerKey);
      expect(result.findings[0]?.message).toContain("with weight 10");
    });

    it("case (b) synthetic: sets master_key_weight to 0", async () => {
      const envelope = buildSetOptionsEnvelope([
        Operation.setOptions({
          masterWeight: 0,
        }),
      ]);

      const result = await analyzeTransaction(
        envelope,
        Networks.TESTNET,
        emptyNetwork(),
      );

      const masterFindings = result.findings.filter(
        (f) => f.ruleId === "master-key-weight",
      );
      expect(masterFindings).toHaveLength(1);
      expect(masterFindings[0]).toMatchObject({
        ruleId: "master-key-weight",
        severity: "critical",
        operationIndex: 0,
        reason: "master-key-disabled",
        account: SOURCE,
      });
      expect(masterFindings[0]?.message).toContain(
        `This operation sets the master key weight of account ${SOURCE} to 0.`,
      );
    });
  });

  describe("rule coexistence", () => {
    it("proves rules coexist in a transaction containing both changeTrust and setOptions", async () => {
      const homeDomain = "verified-issuer.example";
      const network = new FakeStellarNetwork(
        { [ISSUER]: { homeDomain } },
        {
          [homeDomain]: {
            CURRENCIES: [{ code: "USDC", issuer: ISSUER }],
          },
        },
      );

      const newSigner = testPublicKey(101);
      const envelope = buildSetOptionsEnvelope([
        // Operation 0: changeTrust (verified by rule 001)
        changeTrust("USDC", ISSUER),
        // Operation 1: setOptions with signer add, master weight 0, and home domain
        Operation.setOptions({
          masterWeight: 0,
          signer: {
            ed25519PublicKey: newSigner,
            weight: 255,
          },
          homeDomain: "example.org",
        }),
      ]);

      const result = await analyzeTransaction(
        envelope,
        Networks.TESTNET,
        network,
      );

      // Rule 001: Verified asset
      expect(result.verified).toEqual([
        {
          ruleId: "lookalike-asset-issuer",
          operationIndex: 0,
          assetCode: "USDC",
          issuer: ISSUER,
          homeDomain,
          punycode: false,
        },
      ]);

      // Findings from rule 002 (signer-change) and rule 003 (master-key-weight)
      expect(result.findings).toHaveLength(2);

      // Rule 002 finding for operationIndex 1
      expect(result.findings[0]).toMatchObject({
        ruleId: "signer-change",
        operationIndex: 1,
        severity: "critical",
        reason: "signer-ed25519",
        account: SOURCE,
      });

      // Rule 003 finding for operationIndex 1 (control-handover because masterWeight=0 with a signer add)
      expect(result.findings[1]).toMatchObject({
        ruleId: "master-key-weight",
        operationIndex: 1,
        severity: "critical",
        reason: "control-handover",
        account: SOURCE,
      });
      expect(result.findings[1]?.message).toContain(newSigner);

      // Rule 004: Unhandled coverage for homeDomain
      expect(result.unhandled).toHaveLength(1);
      expect(result.unhandled[0]).toMatchObject({
        operationIndex: 1,
        reason: "set-options-fields-unchecked",
      });
      expect(result.unhandled[0]?.message).toContain("home domain");
    });
  });
});
