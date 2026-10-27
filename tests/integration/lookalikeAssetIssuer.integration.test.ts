import fs from "node:fs";
import path from "node:path";

import { Networks } from "@stellar/stellar-sdk";
import { describe, expect, it } from "vitest";

import { analyzeTransaction, HorizonStellarNetwork } from "../../src/index.js";

const describeIntegration =
  process.env.XDRAY_INTEGRATION === "1" ? describe : describe.skip;

describeIntegration("rule 001 against the public Stellar network", () => {
  it("checks a real mainnet changeTrust envelope with live lookups", async () => {
    const xdr = fs
      .readFileSync(
        path.join(__dirname, "..", "fixtures", "mainnet-change-trust.xdr"),
        "utf8",
      )
      .trim();

    const result = await analyzeTransaction(
      xdr,
      Networks.PUBLIC,
      new HorizonStellarNetwork(),
    );

    expect(result.transaction).not.toBeNull();
    expect(result.transaction?.operations[0]?.type).toBe("changeTrust");
    expect(Array.isArray(result.findings)).toBe(true);
    expect(result.unhandled).toEqual([]);
  });
});
