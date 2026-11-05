import { Networks, Operation } from "@stellar/stellar-sdk";
import { describe, expect, it } from "vitest";

import { analyzeTransaction, signerChangeRule } from "../src/index.js";
import type { ParsedOperation } from "../src/index.js";
import { FakeStellarNetwork } from "./fakeNetwork.js";
import { changeTrust, ISSUER, SOURCE } from "./helpers.js";
import {
  buildFeeBumpedSetOptionsEnvelope,
  buildSetOptionsEnvelope,
  createSignedPayloadSigner,
  testPreAuthTx,
  testPublicKey,
  testSha256Hash,
} from "./setOptionsHelpers.js";

const emptyNetwork = () => new FakeStellarNetwork();

describe("rule 002: signer-change", () => {
  describe("ed25519 signer", () => {
    it("reports warning when weight is 1", async () => {
      const signerKey = testPublicKey(10);
      const envelope = buildSetOptionsEnvelope([
        Operation.setOptions({
          signer: {
            ed25519PublicKey: signerKey,
            weight: 1,
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
        assetCode: null,
        issuer: null,
        reason: "signer-ed25519",
        account: SOURCE,
      });
      expect(result.findings[0]?.message).toContain(SOURCE);
      expect(result.findings[0]?.message).toContain(signerKey);
      expect(result.findings[0]?.message).toContain("with weight 1");
      expect(result.findings[0]?.message).toContain("do not sign");
      expect(result.findings[0]?.message).not.toContain("by itself");
    });

    it("reports critical when weight is 255", async () => {
      const signerKey = testPublicKey(11);
      const envelope = buildSetOptionsEnvelope([
        Operation.setOptions({
          signer: {
            ed25519PublicKey: signerKey,
            weight: 255,
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
        severity: "critical",
        operationIndex: 0,
        reason: "signer-ed25519",
        account: SOURCE,
      });
      expect(result.findings[0]?.message).toContain("by itself");
      expect(result.findings[0]?.message).toContain("do not sign");
    });
  });

  describe("sha256Hash signer (hash-x)", () => {
    it("reports warning when weight is 1", async () => {
      const hash = testSha256Hash(20);
      const envelope = buildSetOptionsEnvelope([
        Operation.setOptions({
          signer: {
            sha256Hash: hash,
            weight: 1,
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
        reason: "signer-hash-x",
        account: SOURCE,
      });
      expect(result.findings[0]?.message).toContain("becomes public");
      expect(result.findings[0]?.message).toContain("do not sign");
      expect(result.findings[0]?.message).not.toContain("by itself");
    });

    it("reports critical when weight is 255", async () => {
      const hash = testSha256Hash(21);
      const envelope = buildSetOptionsEnvelope([
        Operation.setOptions({
          signer: {
            sha256Hash: hash,
            weight: 255,
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
        severity: "critical",
        operationIndex: 0,
        reason: "signer-hash-x",
        account: SOURCE,
      });
      expect(result.findings[0]?.message).toContain("by itself");
      expect(result.findings[0]?.message).toContain("becomes public");
      expect(result.findings[0]?.message).toContain("do not sign");
    });
  });

  describe("preAuthTx signer", () => {
    it("reports warning when weight is 1", async () => {
      const txHash = testPreAuthTx(30);
      const envelope = buildSetOptionsEnvelope([
        Operation.setOptions({
          signer: {
            preAuthTx: txHash,
            weight: 1,
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
        reason: "signer-pre-auth-tx",
        account: SOURCE,
      });
      expect(result.findings[0]?.message).toContain("already-built");
      expect(result.findings[0]?.message).toContain("do not sign");
      expect(result.findings[0]?.message).not.toContain("by itself");
    });

    it("reports critical when weight is 255", async () => {
      const txHash = testPreAuthTx(31);
      const envelope = buildSetOptionsEnvelope([
        Operation.setOptions({
          signer: {
            preAuthTx: txHash,
            weight: 255,
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
        severity: "critical",
        operationIndex: 0,
        reason: "signer-pre-auth-tx",
        account: SOURCE,
      });
      expect(result.findings[0]?.message).toContain("by itself");
      expect(result.findings[0]?.message).toContain("already-built");
      expect(result.findings[0]?.message).toContain("do not sign");
    });
  });

  describe("ed25519SignedPayload signer", () => {
    it("reports warning when weight is 1", async () => {
      const payloadSigner = createSignedPayloadSigner(40);
      expect(payloadSigner.startsWith("P")).toBe(true);

      const envelope = buildSetOptionsEnvelope([
        Operation.setOptions({
          signer: {
            ed25519SignedPayload: payloadSigner,
            weight: 1,
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
        reason: "signer-signed-payload",
        account: SOURCE,
      });
      expect(result.findings[0]?.message).toContain(payloadSigner);
      expect(result.findings[0]?.message).toContain("do not sign");
      expect(result.findings[0]?.message).not.toContain("by itself");
    });

    it("reports critical when weight is 255", async () => {
      const payloadSigner = createSignedPayloadSigner(41);
      expect(payloadSigner.startsWith("P")).toBe(true);

      const envelope = buildSetOptionsEnvelope([
        Operation.setOptions({
          signer: {
            ed25519SignedPayload: payloadSigner,
            weight: 255,
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
        severity: "critical",
        operationIndex: 0,
        reason: "signer-signed-payload",
        account: SOURCE,
      });
      expect(result.findings[0]?.message).toContain(payloadSigner);
      expect(result.findings[0]?.message).toContain("by itself");
      expect(result.findings[0]?.message).toContain("do not sign");
    });
  });

  describe("weight 0 (signer removed)", () => {
    it("reports info finding when an ed25519 signer weight is set to 0", async () => {
      const signerKey = testPublicKey(50);
      const envelope = buildSetOptionsEnvelope([
        Operation.setOptions({
          signer: {
            ed25519PublicKey: signerKey,
            weight: 0,
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
        severity: "info",
        operationIndex: 0,
        reason: "signer-removed",
        account: SOURCE,
      });
      expect(result.findings[0]?.message).toContain("removes signer");
      expect(result.findings[0]?.message).toContain(signerKey);
      expect(result.findings[0]?.message).toContain(SOURCE);
      expect(result.findings[0]?.message).toContain("weight 0");
      expect(result.findings[0]?.message).not.toContain("do not sign");
    });

    it("reports info finding when a hash-x signer weight is set to 0", async () => {
      const hash = testSha256Hash(51);
      const envelope = buildSetOptionsEnvelope([
        Operation.setOptions({
          signer: {
            sha256Hash: hash,
            weight: 0,
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
        severity: "info",
        operationIndex: 0,
        reason: "signer-removed",
        account: SOURCE,
      });
      expect(result.findings[0]?.message).toContain("removes signer");
      expect(result.findings[0]?.message).toContain(SOURCE);
      expect(result.findings[0]?.message).toContain("weight 0");
      expect(result.findings[0]?.message).not.toContain("do not sign");
    });

    it("reports info finding when a pre-auth signer weight is set to 0", async () => {
      const txHash = testPreAuthTx(52);
      const envelope = buildSetOptionsEnvelope([
        Operation.setOptions({
          signer: {
            preAuthTx: txHash,
            weight: 0,
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
        severity: "info",
        operationIndex: 0,
        reason: "signer-removed",
        account: SOURCE,
      });
      expect(result.findings[0]?.message).toContain("removes signer");
      expect(result.findings[0]?.message).toContain(SOURCE);
      expect(result.findings[0]?.message).toContain("weight 0");
      expect(result.findings[0]?.message).not.toContain("do not sign");
    });

    it("reports info finding when a signed-payload signer weight is set to 0", async () => {
      const payloadSigner = createSignedPayloadSigner(53);
      const envelope = buildSetOptionsEnvelope([
        Operation.setOptions({
          signer: {
            ed25519SignedPayload: payloadSigner,
            weight: 0,
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
        severity: "info",
        operationIndex: 0,
        reason: "signer-removed",
        account: SOURCE,
      });
      expect(result.findings[0]?.message).toContain("removes signer");
      expect(result.findings[0]?.message).toContain(payloadSigner);
      expect(result.findings[0]?.message).toContain(SOURCE);
      expect(result.findings[0]?.message).toContain("weight 0");
      expect(result.findings[0]?.message).not.toContain("do not sign");
    });
  });

  describe("unsupported signer", () => {
    it("produces exactly one unsupported-signer warning for a signer with an unknown shape", async () => {
      const malformedOp = {
        type: "setOptions",
        account: SOURCE,
        signer: { unknownKey: "foobar", weight: 1 } as unknown,
      } as unknown as ParsedOperation;

      const result = await signerChangeRule.evaluate({
        transaction: {
          sourceAccount: SOURCE,
          feeBumped: false,
          operations: [malformedOp],
        },
        network: emptyNetwork(),
      });

      expect(result.findings).toHaveLength(1);
      expect(result.findings[0]).toMatchObject({
        ruleId: "signer-change",
        severity: "warning",
        operationIndex: 0,
        assetCode: null,
        issuer: null,
        reason: "unsupported-signer",
        account: SOURCE,
      });
      expect(result.findings[0]?.message).toBe(
        `This operation changes a signer on account ${SOURCE} in a form this tool could not read, so it could not be checked. If you did not set this up yourself, do not sign.`,
      );
    });

    it.each([
      undefined,
      null,
      -1,
      256,
      1.5,
      "10",
      Number.NaN,
    ])(
      "produces exactly one unsupported-signer warning when signer weight is %s",
      async (weight) => {
        const malformedOp = {
          type: "setOptions",
          account: SOURCE,
          signer: {
            ed25519PublicKey: testPublicKey(10),
            weight: weight as unknown,
          } as unknown,
        } as unknown as ParsedOperation;

        const result = await signerChangeRule.evaluate({
          transaction: {
            sourceAccount: SOURCE,
            feeBumped: false,
            operations: [malformedOp],
          },
          network: emptyNetwork(),
        });

        expect(result.findings).toHaveLength(1);
        expect(result.findings[0]).toMatchObject({
          ruleId: "signer-change",
          severity: "warning",
          operationIndex: 0,
          assetCode: null,
          issuer: null,
          reason: "unsupported-signer",
          account: SOURCE,
        });
        expect(result.findings[0]?.message).toBe(
          `This operation changes a signer on account ${SOURCE} in a form this tool could not read, so it could not be checked. If you did not set this up yourself, do not sign.`,
        );
      },
    );
  });

  describe("operation source account handling", () => {
    it("uses the operation's own source account for finding.account", async () => {
      const opSource = testPublicKey(60);
      const signerKey = testPublicKey(61);
      const envelope = buildSetOptionsEnvelope([
        Operation.setOptions({
          signer: {
            ed25519PublicKey: signerKey,
            weight: 5,
          },
          source: opSource,
        }),
      ]);

      const result = await analyzeTransaction(
        envelope,
        Networks.TESTNET,
        emptyNetwork(),
      );

      expect(result.findings).toHaveLength(1);
      expect(result.findings[0]?.account).toBe(opSource);
      expect(result.findings[0]?.account).not.toBe(SOURCE);
      expect(result.findings[0]?.message).toContain(opSource);
    });
  });

  describe("fee-bump transactions", () => {
    it("analyzes signer change inside a fee-bumped transaction using the inner source", async () => {
      const signerKey = testPublicKey(70);
      const envelope = buildFeeBumpedSetOptionsEnvelope([
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

      expect(result.transaction?.feeBumped).toBe(true);
      expect(result.findings).toHaveLength(1);
      expect(result.findings[0]?.account).toBe(SOURCE);
      expect(result.findings[0]?.reason).toBe("signer-ed25519");
      expect(result.findings[0]?.severity).toBe("warning");
    });
  });

  describe("multiple signer operations", () => {
    it("produces one finding per signer operation with correct operationIndex", async () => {
      const signer1 = testPublicKey(80);
      const signer2 = testPublicKey(81);
      const envelope = buildSetOptionsEnvelope([
        Operation.setOptions({
          signer: {
            ed25519PublicKey: signer1,
            weight: 1,
          },
        }),
        Operation.setOptions({
          signer: {
            ed25519PublicKey: signer2,
            weight: 255,
          },
        }),
      ]);

      const result = await analyzeTransaction(
        envelope,
        Networks.TESTNET,
        emptyNetwork(),
      );

      expect(result.findings).toHaveLength(2);
      expect(result.findings[0]).toMatchObject({
        ruleId: "signer-change",
        operationIndex: 0,
        severity: "warning",
        reason: "signer-ed25519",
      });
      expect(result.findings[0]?.message).toContain(signer1);

      expect(result.findings[1]).toMatchObject({
        ruleId: "signer-change",
        operationIndex: 1,
        severity: "critical",
        reason: "signer-ed25519",
      });
      expect(result.findings[1]?.message).toContain(signer2);
    });
  });

  describe("non-setOptions operations", () => {
    it("produces no findings for non-setOptions operations", async () => {
      const envelope = buildSetOptionsEnvelope([
        Operation.manageData({
          name: "config",
          value: "test",
        }),
      ]);

      const result = await analyzeTransaction(
        envelope,
        Networks.TESTNET,
        emptyNetwork(),
      );

      const signerFindings = result.findings.filter(
        (f) => f.ruleId === "signer-change",
      );
      expect(signerFindings).toHaveLength(0);
    });

    it("produces no findings for setOptions operations without a signer", async () => {
      const envelope = buildSetOptionsEnvelope([
        Operation.setOptions({
          homeDomain: "example.com",
          masterWeight: 10,
        }),
      ]);

      const result = await analyzeTransaction(
        envelope,
        Networks.TESTNET,
        emptyNetwork(),
      );

      const signerFindings = result.findings.filter(
        (f) => f.ruleId === "signer-change",
      );
      expect(signerFindings).toHaveLength(0);
    });
  });

  describe("combined changeTrust and signer change", () => {
    it("allows rule 001 to behave while rule 002 adds its own finding", async () => {
      const homeDomain = "issuer.example";
      const network = new FakeStellarNetwork(
        { [ISSUER]: { homeDomain } },
        {
          [homeDomain]: {
            CURRENCIES: [{ code: "USDC", issuer: ISSUER }],
          },
        },
      );

      const newSigner = testPublicKey(90);
      const envelope = buildSetOptionsEnvelope([
        changeTrust("USDC", ISSUER),
        Operation.setOptions({
          signer: {
            ed25519PublicKey: newSigner,
            weight: 1,
          },
        }),
      ]);

      const result = await analyzeTransaction(
        envelope,
        Networks.TESTNET,
        network,
      );

      // Rule 001 verifies the asset at operationIndex 0
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

      // Rule 002 produces a finding for operationIndex 1
      expect(result.findings).toHaveLength(1);
      expect(result.findings[0]).toMatchObject({
        ruleId: "signer-change",
        operationIndex: 1,
        severity: "warning",
        reason: "signer-ed25519",
        account: SOURCE,
      });
      expect(result.findings[0]?.message).toContain(newSigner);
    });
  });
});
