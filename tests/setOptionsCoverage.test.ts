import { Networks, Operation } from "@stellar/stellar-sdk";
import { describe, expect, it } from "vitest";

import { analyzeTransaction } from "../src/index.js";
import { FakeStellarNetwork } from "./fakeNetwork.js";
import { ISSUER, SOURCE } from "./helpers.js";
import {
  buildSetOptionsEnvelope,
  testPublicKey,
} from "./setOptionsHelpers.js";

const emptyNetwork = () => new FakeStellarNetwork();

describe("rule: set-options-coverage", () => {
  it("reports thresholds only in unhandled entry", async () => {
    const envelope = buildSetOptionsEnvelope([
      Operation.setOptions({
        lowThreshold: 1,
        medThreshold: 2,
        highThreshold: 3,
      }),
    ]);

    const result = await analyzeTransaction(
      envelope,
      Networks.TESTNET,
      emptyNetwork(),
    );

    expect(result.unhandled).toHaveLength(1);
    expect(result.unhandled[0]).toMatchObject({
      operationIndex: 0,
      reason: "set-options-fields-unchecked",
    });
    expect(result.unhandled[0]?.message).toBe(
      `This setOptions operation changes thresholds on account ${SOURCE}. These fields are not checked yet, so a clean result does not cover them.`,
    );
  });

  it("reports home domain only and does NOT echo the home domain value in the message", async () => {
    const domain = "secret-domain.example";
    const envelope = buildSetOptionsEnvelope([
      Operation.setOptions({
        homeDomain: domain,
      }),
    ]);

    const result = await analyzeTransaction(
      envelope,
      Networks.TESTNET,
      emptyNetwork(),
    );

    expect(result.unhandled).toHaveLength(1);
    expect(result.unhandled[0]).toMatchObject({
      operationIndex: 0,
      reason: "set-options-fields-unchecked",
    });
    expect(result.unhandled[0]?.message).toBe(
      `This setOptions operation changes home domain on account ${SOURCE}. These fields are not checked yet, so a clean result does not cover them.`,
    );
    expect(result.unhandled[0]?.message).not.toContain(domain);
  });

  it("reports account flags only in unhandled entry", async () => {
    const envelope = buildSetOptionsEnvelope([
      Operation.setOptions({
        setFlags: 1,
        clearFlags: 2,
      }),
    ]);

    const result = await analyzeTransaction(
      envelope,
      Networks.TESTNET,
      emptyNetwork(),
    );

    expect(result.unhandled).toHaveLength(1);
    expect(result.unhandled[0]).toMatchObject({
      operationIndex: 0,
      reason: "set-options-fields-unchecked",
    });
    expect(result.unhandled[0]?.message).toBe(
      `This setOptions operation changes account flags on account ${SOURCE}. These fields are not checked yet, so a clean result does not cover them.`,
    );
  });

  it("reports all fields together in unhandled entry", async () => {
    const domain = "all-fields.example";
    const envelope = buildSetOptionsEnvelope([
      Operation.setOptions({
        lowThreshold: 1,
        homeDomain: domain,
        setFlags: 1,
        inflationDest: ISSUER,
      }),
    ]);

    const result = await analyzeTransaction(
      envelope,
      Networks.TESTNET,
      emptyNetwork(),
    );

    expect(result.unhandled).toHaveLength(1);
    expect(result.unhandled[0]).toMatchObject({
      operationIndex: 0,
      reason: "set-options-fields-unchecked",
    });
    expect(result.unhandled[0]?.message).toBe(
      `This setOptions operation changes thresholds, home domain, account flags and inflation destination on account ${SOURCE}. These fields are not checked yet, so a clean result does not cover them.`,
    );
    expect(result.unhandled[0]?.message).not.toContain(domain);
  });

  it("produces NO unhandled entry for a signer-only operation", async () => {
    const envelope = buildSetOptionsEnvelope([
      Operation.setOptions({
        signer: {
          ed25519PublicKey: testPublicKey(10),
          weight: 1,
        },
      }),
    ]);

    const result = await analyzeTransaction(
      envelope,
      Networks.TESTNET,
      emptyNetwork(),
    );

    expect(result.unhandled).toHaveLength(0);
  });
});

