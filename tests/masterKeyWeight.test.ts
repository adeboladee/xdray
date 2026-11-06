import { Networks, Operation } from "@stellar/stellar-sdk";
import { describe, expect, it } from "vitest";

import { analyzeTransaction, masterKeyWeightRule } from "../src/index.js";
import type { ParsedOperation } from "../src/index.js";
import { FakeStellarNetwork } from "./fakeNetwork.js";
import { FEE_SOURCE, OTHER_ISSUER, SOURCE } from "./helpers.js";
import {
  buildFeeBumpedSetOptionsEnvelope,
  buildSetOptionsEnvelope,
  testPublicKey,
} from "./setOptionsHelpers.js";

const emptyNetwork = () => new FakeStellarNetwork();

describe("rule 003: master-key-weight", () => {
  it("reports master-key-disabled critical finding when master weight is set to 0 alone", async () => {
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

    const findings = result.findings.filter(
      (f) => f.ruleId === "master-key-weight",
    );
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      ruleId: "master-key-weight",
      severity: "critical",
      operationIndex: 0,
      reason: "master-key-disabled",
      account: SOURCE,
    });
    expect(findings[0]?.message).toContain(
      `This operation sets the master key weight of account ${SOURCE} to 0.`,
    );
    expect(findings[0]?.message).toContain("permanently locked");
    expect(findings[0]?.message).toContain(
      "only sign if you are sure other signers can control the account",
    );
  });

  describe("control-handover", () => {
    it("reports control-handover when signer op is BEFORE the weight 0 op", async () => {
      const signer = testPublicKey(10);
      const envelope = buildSetOptionsEnvelope([
        Operation.setOptions({
          signer: {
            ed25519PublicKey: signer,
            weight: 1,
          },
        }),
        Operation.setOptions({
          masterWeight: 0,
        }),
      ]);

      const result = await analyzeTransaction(
        envelope,
        Networks.TESTNET,
        emptyNetwork(),
      );

      const findings = result.findings.filter(
        (f) => f.ruleId === "master-key-weight",
      );
      expect(findings).toHaveLength(1);
      expect(findings[0]).toMatchObject({
        ruleId: "master-key-weight",
        severity: "critical",
        operationIndex: 1,
        reason: "control-handover",
        account: SOURCE,
      });
      expect(findings[0]?.message).toContain(
        `This transaction switches off account ${SOURCE}'s own key (master key weight 0) and gives signing control to: ${signer}.`,
      );
      expect(findings[0]?.message).toContain(
        "only sign if you control every key listed",
      );
      expect(findings[0]?.message).toContain(
        "If you did not set this up yourself, do not sign.",
      );
    });

    it("reports control-handover when signer op is AFTER the weight 0 op", async () => {
      const signer = testPublicKey(11);
      const envelope = buildSetOptionsEnvelope([
        Operation.setOptions({
          masterWeight: 0,
        }),
        Operation.setOptions({
          signer: {
            ed25519PublicKey: signer,
            weight: 1,
          },
        }),
      ]);

      const result = await analyzeTransaction(
        envelope,
        Networks.TESTNET,
        emptyNetwork(),
      );

      const findings = result.findings.filter(
        (f) => f.ruleId === "master-key-weight",
      );
      expect(findings).toHaveLength(1);
      expect(findings[0]).toMatchObject({
        ruleId: "master-key-weight",
        severity: "critical",
        operationIndex: 0,
        reason: "control-handover",
        account: SOURCE,
      });
      expect(findings[0]?.message).toContain(signer);
    });

    it("reports control-handover when both fields are in ONE operation", async () => {
      const signer = testPublicKey(12);
      const envelope = buildSetOptionsEnvelope([
        Operation.setOptions({
          masterWeight: 0,
          signer: {
            ed25519PublicKey: signer,
            weight: 1,
          },
        }),
      ]);

      const result = await analyzeTransaction(
        envelope,
        Networks.TESTNET,
        emptyNetwork(),
      );

      const findings = result.findings.filter(
        (f) => f.ruleId === "master-key-weight",
      );
      expect(findings).toHaveLength(1);
      expect(findings[0]).toMatchObject({
        ruleId: "master-key-weight",
        severity: "critical",
        operationIndex: 0,
        reason: "control-handover",
        account: SOURCE,
      });
      expect(findings[0]?.message).toContain(signer);
    });

    it("reports control-handover with an unreadable signer", async () => {
      const malformedOp = {
        type: "setOptions",
        account: SOURCE,
        signer: { unknownKey: "foo", weight: 1 } as unknown,
      } as unknown as ParsedOperation;

      const masterZeroOp = {
        type: "setOptions",
        account: SOURCE,
        masterWeight: 0,
      } as unknown as ParsedOperation;

      const result = await masterKeyWeightRule.evaluate({
        transaction: {
          sourceAccount: SOURCE,
          feeBumped: false,
          operations: [masterZeroOp, malformedOp],
        },
        network: emptyNetwork(),
      });

      expect(result.findings).toHaveLength(1);
      expect(result.findings[0]).toMatchObject({
        ruleId: "master-key-weight",
        severity: "critical",
        operationIndex: 0,
        reason: "control-handover",
        account: SOURCE,
      });
      expect(result.findings[0]?.message).toContain(
        "a signer this tool could not read",
      );
    });

    it("lists 5 keys and says 'and 2 more' when 7 distinct signers are touched", async () => {
      const signers = [
        testPublicKey(21),
        testPublicKey(22),
        testPublicKey(23),
        testPublicKey(24),
        testPublicKey(25),
        testPublicKey(26),
        testPublicKey(27),
      ];

      const ops = [
        Operation.setOptions({ masterWeight: 0 }),
        ...signers.map((s) =>
          Operation.setOptions({
            signer: {
              ed25519PublicKey: s,
              weight: 1,
            },
          }),
        ),
      ];

      const envelope = buildSetOptionsEnvelope(ops);
      const result = await analyzeTransaction(
        envelope,
        Networks.TESTNET,
        emptyNetwork(),
      );

      const findings = result.findings.filter(
        (f) => f.ruleId === "master-key-weight",
      );
      expect(findings).toHaveLength(1);
      expect(findings[0]?.reason).toBe("control-handover");

      const message = findings[0]?.message ?? "";
      expect(message).toContain(signers[0]);
      expect(message).toContain(signers[1]);
      expect(message).toContain(signers[2]);
      expect(message).toContain(signers[3]);
      expect(message).toContain(signers[4]);
      expect(message).not.toContain(signers[5]);
      expect(message).not.toContain(signers[6]);
      expect(message).toContain("and 2 more");
    });
  });

  describe("transaction order of masterWeight operations", () => {
    it("produces only the info finding when master weight is 0 then set back to 1", async () => {
      const envelope = buildSetOptionsEnvelope([
        Operation.setOptions({ masterWeight: 0 }),
        Operation.setOptions({ masterWeight: 1 }),
      ]);

      const result = await analyzeTransaction(
        envelope,
        Networks.TESTNET,
        emptyNetwork(),
      );

      const findings = result.findings.filter(
        (f) => f.ruleId === "master-key-weight",
      );
      expect(findings).toHaveLength(1);
      expect(findings[0]).toMatchObject({
        ruleId: "master-key-weight",
        severity: "info",
        operationIndex: 1,
        reason: "master-key-weight-changed",
        account: SOURCE,
      });
      expect(findings[0]?.message).toBe(
        `This operation changes the master key weight of account ${SOURCE} to 1.`,
      );
    });

    it("produces master-key-disabled when master weight is set to 1 then 0", async () => {
      const envelope = buildSetOptionsEnvelope([
        Operation.setOptions({ masterWeight: 1 }),
        Operation.setOptions({ masterWeight: 0 }),
      ]);

      const result = await analyzeTransaction(
        envelope,
        Networks.TESTNET,
        emptyNetwork(),
      );

      const findings = result.findings.filter(
        (f) => f.ruleId === "master-key-weight",
      );
      expect(findings).toHaveLength(1);
      expect(findings[0]).toMatchObject({
        ruleId: "master-key-weight",
        severity: "critical",
        operationIndex: 1,
        reason: "master-key-disabled",
        account: SOURCE,
      });
    });
  });

  describe("account boundaries", () => {
    it("reports master-key-disabled when master weight 0 is on account A and signer add is on account B", async () => {
      const signer = testPublicKey(30);
      const envelope = buildSetOptionsEnvelope([
        Operation.setOptions({ masterWeight: 0 }),
        Operation.setOptions({
          signer: {
            ed25519PublicKey: signer,
            weight: 1,
          },
          source: OTHER_ISSUER,
        }),
      ]);

      const result = await analyzeTransaction(
        envelope,
        Networks.TESTNET,
        emptyNetwork(),
      );

      const findings = result.findings.filter(
        (f) => f.ruleId === "master-key-weight",
      );
      expect(findings).toHaveLength(1);
      expect(findings[0]).toMatchObject({
        ruleId: "master-key-weight",
        severity: "critical",
        operationIndex: 0,
        reason: "master-key-disabled",
        account: SOURCE,
      });
      expect(findings[0]?.reason).not.toBe("control-handover");
    });

    it("reports master-key-disabled when master weight 0 is accompanied only by a signer removal", async () => {
      const signer = testPublicKey(31);
      const envelope = buildSetOptionsEnvelope([
        Operation.setOptions({ masterWeight: 0 }),
        Operation.setOptions({
          signer: {
            ed25519PublicKey: signer,
            weight: 0,
          },
        }),
      ]);

      const result = await analyzeTransaction(
        envelope,
        Networks.TESTNET,
        emptyNetwork(),
      );

      const findings = result.findings.filter(
        (f) => f.ruleId === "master-key-weight",
      );
      expect(findings).toHaveLength(1);
      expect(findings[0]).toMatchObject({
        ruleId: "master-key-weight",
        severity: "critical",
        operationIndex: 0,
        reason: "master-key-disabled",
        account: SOURCE,
      });
      expect(findings[0]?.reason).not.toBe("control-handover");
    });
  });

  describe("master weight values", () => {
    it("reports info when master weight is 100", async () => {
      const envelope = buildSetOptionsEnvelope([
        Operation.setOptions({ masterWeight: 100 }),
      ]);

      const result = await analyzeTransaction(
        envelope,
        Networks.TESTNET,
        emptyNetwork(),
      );

      const findings = result.findings.filter(
        (f) => f.ruleId === "master-key-weight",
      );
      expect(findings).toHaveLength(1);
      expect(findings[0]).toMatchObject({
        ruleId: "master-key-weight",
        severity: "info",
        operationIndex: 0,
        reason: "master-key-weight-changed",
        account: SOURCE,
      });
      expect(findings[0]?.message).toBe(
        `This operation changes the master key weight of account ${SOURCE} to 100.`,
      );
    });

    it("reports master-weight-invalid when master weight is invalid", async () => {
      const malformedOp = {
        type: "setOptions",
        account: SOURCE,
        masterWeight: 300 as unknown,
      } as unknown as ParsedOperation;

      const result = await masterKeyWeightRule.evaluate({
        transaction: {
          sourceAccount: SOURCE,
          feeBumped: false,
          operations: [malformedOp],
        },
        network: emptyNetwork(),
      });

      expect(result.findings).toHaveLength(1);
      expect(result.findings[0]).toMatchObject({
        ruleId: "master-key-weight",
        severity: "warning",
        operationIndex: 0,
        reason: "master-weight-invalid",
        account: SOURCE,
      });
      expect(result.findings[0]?.message).toBe(
        `This operation sets a master key weight on account ${SOURCE} that this tool could not read as a number from 0 to 255, so it could not be checked.`,
      );
    });
  });

  describe("fee-bump and non-setOptions transactions", () => {
    it("evaluates master key weight inside a fee-bumped transaction using the inner source", async () => {
      const envelope = buildFeeBumpedSetOptionsEnvelope([
        Operation.setOptions({ masterWeight: 50 }),
      ]);

      const result = await analyzeTransaction(
        envelope,
        Networks.TESTNET,
        emptyNetwork(),
      );

      expect(result.transaction?.feeBumped).toBe(true);
      const findings = result.findings.filter(
        (f) => f.ruleId === "master-key-weight",
      );
      expect(findings).toHaveLength(1);
      expect(findings[0]?.account).toBe(SOURCE);
      expect(findings[0]?.account).not.toBe(FEE_SOURCE);
      expect(findings[0]?.reason).toBe("master-key-weight-changed");
    });

    it("produces no findings for non-setOptions transactions", async () => {
      const envelope = buildSetOptionsEnvelope([
        Operation.manageData({ name: "foo", value: "bar" }),
      ]);

      const result = await analyzeTransaction(
        envelope,
        Networks.TESTNET,
        emptyNetwork(),
      );

      const findings = result.findings.filter(
        (f) => f.ruleId === "master-key-weight",
      );
      expect(findings).toHaveLength(0);
    });

    it("produces no findings from master-key-weight for a setOptions op that sets only homeDomain", async () => {
      const envelope = buildSetOptionsEnvelope([
        Operation.setOptions({ homeDomain: "example.com" }),
      ]);

      const result = await analyzeTransaction(
        envelope,
        Networks.TESTNET,
        emptyNetwork(),
      );

      const findings = result.findings.filter(
        (f) => f.ruleId === "master-key-weight",
      );
      expect(findings).toHaveLength(0);
    });
  });
});

