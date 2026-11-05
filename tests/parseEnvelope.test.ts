import {
  Asset,
  BASE_FEE,
  MuxedAccount,
  Networks,
  Operation,
  TransactionBuilder,
} from "@stellar/stellar-sdk";
import { describe, expect, it } from "vitest";

import { parseEnvelope } from "../src/index.js";
import {
  account,
  buildEnvelope,
  buildFeeBumpedEnvelope,
  changeTrust,
  FEE_SOURCE,
  ISSUER,
  OTHER_ISSUER,
  SOURCE,
} from "./helpers.js";

describe("parseEnvelope affected account", () => {
  it("uses an operation's own source account", () => {
    const envelope = buildEnvelope([
      Operation.changeTrust({
        asset: new Asset("USDC", ISSUER),
        source: OTHER_ISSUER,
      }),
    ]);

    const parsed = parseEnvelope(envelope, Networks.TESTNET);

    expect(parsed.operations).toHaveLength(1);
    expect(parsed.operations[0]?.source).toBe(OTHER_ISSUER);
    expect(parsed.operations[0]?.account).toBe(OTHER_ISSUER);
  });

  it("falls back to the transaction source when the operation has none", () => {
    const envelope = buildEnvelope([changeTrust("USDC", ISSUER)], SOURCE);

    const parsed = parseEnvelope(envelope, Networks.TESTNET);

    expect(parsed.operations).toHaveLength(1);
    expect(parsed.operations[0]?.source).toBeUndefined();
    expect(parsed.operations[0]?.account).toBe(SOURCE);
  });

  it("normalizes a muxed operation source to its underlying account", () => {
    const muxedSource = new MuxedAccount(account(OTHER_ISSUER), "7").accountId();
    const envelope = buildEnvelope([
      Operation.changeTrust({
        asset: new Asset("USDC", ISSUER),
        source: muxedSource,
      }),
    ]);

    const parsed = parseEnvelope(envelope, Networks.TESTNET);

    expect(muxedSource.startsWith("M")).toBe(true);
    expect(parsed.operations[0]?.source).toBe(muxedSource);
    expect(parsed.operations[0]?.account).toBe(OTHER_ISSUER);
  });

  it("normalizes a muxed transaction source for the fallback account", () => {
    const muxedSource = new MuxedAccount(account(SOURCE), "9");
    const envelope = new TransactionBuilder(muxedSource, {
      fee: BASE_FEE,
      networkPassphrase: Networks.TESTNET,
    })
      .addOperation(changeTrust("USDC", ISSUER))
      .setTimeout(30)
      .build()
      .toXDR();

    const parsed = parseEnvelope(envelope, Networks.TESTNET);

    expect(parsed.sourceAccount).toBe(muxedSource.accountId());
    expect(parsed.operations[0]?.account).toBe(SOURCE);
  });

  it("uses the inner transaction source for a fee bump", () => {
    const envelope = buildFeeBumpedEnvelope(
      [changeTrust("USDC", ISSUER)],
      SOURCE,
    );

    const parsed = parseEnvelope(envelope, Networks.TESTNET);

    expect(parsed.feeBumped).toBe(true);
    expect(parsed.sourceAccount).toBe(SOURCE);
    expect(parsed.operations[0]?.account).toBe(SOURCE);
    expect(parsed.operations[0]?.account).not.toBe(FEE_SOURCE);
  });
});
