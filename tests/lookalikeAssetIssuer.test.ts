import fs from "node:fs";
import path from "node:path";

import {
  Asset,
  Keypair,
  LiquidityPoolAsset,
  Networks,
  Operation,
} from "@stellar/stellar-sdk";
import { describe, expect, it } from "vitest";

import {
  analyzeTransaction,
  MAX_ISSUER_LOOKUPS,
  parseEnvelope,
} from "../src/index.js";
import { FakeStellarNetwork } from "./fakeNetwork.js";
import {
  buildEnvelope,
  buildFeeBumpedEnvelope,
  changeTrust,
  ISSUER,
  OTHER_ISSUER,
  SOURCE,
} from "./helpers.js";

const HOME_DOMAIN = "issuer.example";

function publicKey(fill: number): string {
  return Keypair.fromRawEd25519Seed(new Uint8Array(32).fill(fill)).publicKey();
}

function networkListing(code = "USDC", listedIssuer = ISSUER) {
  return new FakeStellarNetwork(
    { [ISSUER]: { homeDomain: HOME_DOMAIN } },
    {
      [HOME_DOMAIN]: {
        CURRENCIES: [{ code, issuer: listedIssuer }],
      },
    },
  );
}

describe("rule 001: look-alike asset issuer on changeTrust", () => {
  it("does not warn when stellar.toml lists the exact code and issuer", async () => {
    const network = networkListing();
    const envelope = buildEnvelope([changeTrust("USDC", ISSUER)]);

    const result = await analyzeTransaction(
      envelope,
      Networks.TESTNET,
      network,
    );

    expect(result.findings).toEqual([]);
    expect(result.verified).toEqual([
      {
        ruleId: "lookalike-asset-issuer",
        operationIndex: 0,
        assetCode: "USDC",
        issuer: ISSUER,
        homeDomain: HOME_DOMAIN,
      },
    ]);
    expect(result.unhandled).toEqual([]);
    expect(result.transaction?.sourceAccount).toBe(SOURCE);
    expect(result.transaction?.feeBumped).toBe(false);
  });

  it("exposes a self-attested attacker domain instead of treating it as trustworthy", async () => {
    // Known limitation: this passes SEP-1 self-consistency. Without a known-domain
    // list, the wallet must show the domain so the user can judge it.
    const attackerIssuer = publicKey(20);
    const attackerDomain = "attacker.example";
    const network = new FakeStellarNetwork(
      { [attackerIssuer]: { homeDomain: attackerDomain } },
      {
        [attackerDomain]: {
          CURRENCIES: [{ code: "USDC", issuer: attackerIssuer }],
        },
      },
    );
    const envelope = buildEnvelope([changeTrust("USDC", attackerIssuer)]);

    const result = await analyzeTransaction(
      envelope,
      Networks.TESTNET,
      network,
    );

    expect(result.findings).toEqual([]);
    expect(result.verified).toEqual([
      {
        ruleId: "lookalike-asset-issuer",
        operationIndex: 0,
        assetCode: "USDC",
        issuer: attackerIssuer,
        homeDomain: attackerDomain,
      },
    ]);
  });

  it("warns when the code matches but the issuer differs", async () => {
    const network = networkListing("USDC", OTHER_ISSUER);
    const envelope = buildEnvelope([changeTrust("USDC", ISSUER)]);

    const result = await analyzeTransaction(
      envelope,
      Networks.TESTNET,
      network,
    );

    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]).toMatchObject({
      ruleId: "lookalike-asset-issuer",
      severity: "critical",
      operationIndex: 0,
      assetCode: "USDC",
      issuer: ISSUER,
      reason: "issuer-mismatch",
    });
    expect(result.findings[0]?.message).toContain("different account");
  });

  it("warns when the issuer has no home_domain", async () => {
    const network = new FakeStellarNetwork({
      [ISSUER]: { homeDomain: null },
    });
    const envelope = buildEnvelope([changeTrust("USDC", ISSUER)]);

    const result = await analyzeTransaction(
      envelope,
      Networks.TESTNET,
      network,
    );

    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]).toMatchObject({
      operationIndex: 0,
      assetCode: "USDC",
      issuer: ISSUER,
      reason: "no-home-domain",
    });
    expect(network.tomlCalls).toEqual([]);
  });

  it("warns when stellar.toml is unreachable and does not throw", async () => {
    const network = new FakeStellarNetwork(
      { [ISSUER]: { homeDomain: HOME_DOMAIN } },
      { [HOME_DOMAIN]: new Error("network down") },
    );
    const envelope = buildEnvelope([changeTrust("USDC", ISSUER)]);

    const result = await analyzeTransaction(
      envelope,
      Networks.TESTNET,
      network,
    );

    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]).toMatchObject({
      operationIndex: 0,
      reason: "toml-unreachable",
    });
  });

  it("warns when stellar.toml is malformed and does not throw", async () => {
    const network = new FakeStellarNetwork(
      { [ISSUER]: { homeDomain: HOME_DOMAIN } },
      { [HOME_DOMAIN]: { CURRENCIES: "not-an-array" } },
    );
    const envelope = buildEnvelope([changeTrust("USDC", ISSUER)]);

    const result = await analyzeTransaction(
      envelope,
      Networks.TESTNET,
      network,
    );

    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]).toMatchObject({
      operationIndex: 0,
      reason: "toml-malformed",
    });
  });

  it("still verifies when a malformed entry appears before the valid match", async () => {
    const network = new FakeStellarNetwork(
      { [ISSUER]: { homeDomain: HOME_DOMAIN } },
      {
        [HOME_DOMAIN]: {
          CURRENCIES: [
            null,
            { code: 42, issuer: ISSUER },
            { code: "USDC", issuer: ISSUER },
          ],
        },
      },
    );
    const envelope = buildEnvelope([changeTrust("USDC", ISSUER)]);

    const result = await analyzeTransaction(
      envelope,
      Networks.TESTNET,
      network,
    );

    expect(result.findings).toEqual([]);
    expect(result.verified).toEqual([
      expect.objectContaining({
        operationIndex: 0,
        assetCode: "USDC",
        issuer: ISSUER,
        homeDomain: HOME_DOMAIN,
      }),
    ]);
  });

  it("still verifies when a malformed entry appears after the valid match", async () => {
    const network = new FakeStellarNetwork(
      { [ISSUER]: { homeDomain: HOME_DOMAIN } },
      {
        [HOME_DOMAIN]: {
          CURRENCIES: [
            { code: "USDC", issuer: ISSUER },
            null,
            { code: "USDC", issuer: 123 },
          ],
        },
      },
    );
    const envelope = buildEnvelope([changeTrust("USDC", ISSUER)]);

    const result = await analyzeTransaction(
      envelope,
      Networks.TESTNET,
      network,
    );

    expect(result.findings).toEqual([]);
    expect(result.verified).toHaveLength(1);
  });

  it("reports asset-not-listed when only malformed entries exist and nothing matches", async () => {
    const network = new FakeStellarNetwork(
      { [ISSUER]: { homeDomain: HOME_DOMAIN } },
      {
        [HOME_DOMAIN]: {
          CURRENCIES: [
            null,
            { code: 42, issuer: ISSUER },
            { code: "USDC", issuer: 123 },
          ],
        },
      },
    );
    const envelope = buildEnvelope([changeTrust("USDC", ISSUER)]);

    const result = await analyzeTransaction(
      envelope,
      Networks.TESTNET,
      network,
    );

    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]).toMatchObject({
      operationIndex: 0,
      reason: "asset-not-listed",
    });
    expect(result.verified).toEqual([]);
  });

  it("warns when stellar.toml does not list the asset", async () => {
    const network = networkListing("EURC", ISSUER);
    const envelope = buildEnvelope([changeTrust("USDC", ISSUER)]);

    const result = await analyzeTransaction(
      envelope,
      Networks.TESTNET,
      network,
    );

    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]).toMatchObject({
      operationIndex: 0,
      reason: "asset-not-listed",
    });
  });

  it("warns when the issuer account cannot be loaded", async () => {
    const network = new FakeStellarNetwork({
      [ISSUER]: new Error("account not found"),
    });
    const envelope = buildEnvelope([changeTrust("USDC", ISSUER)]);

    const result = await analyzeTransaction(
      envelope,
      Networks.TESTNET,
      network,
    );

    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]).toMatchObject({
      operationIndex: 0,
      reason: "account-unreachable",
    });
  });

  it("looks up a repeated issuer and domain only once per analysis", async () => {
    const network = networkListing();
    const envelope = buildEnvelope([
      changeTrust("USDC", ISSUER),
      changeTrust("USDC", ISSUER),
      changeTrust("USDC", ISSUER),
    ]);

    const result = await analyzeTransaction(
      envelope,
      Networks.TESTNET,
      network,
    );

    expect(result.findings).toEqual([]);
    expect(result.verified).toHaveLength(3);
    expect(network.accountCalls).toEqual([ISSUER]);
    expect(network.tomlCalls).toEqual([HOME_DOMAIN]);
  });

  it("looks up two issuers sharing one home domain with one TOML fetch", async () => {
    const secondIssuer = publicKey(21);
    const network = new FakeStellarNetwork(
      {
        [ISSUER]: { homeDomain: HOME_DOMAIN },
        [secondIssuer]: { homeDomain: HOME_DOMAIN },
      },
      {
        [HOME_DOMAIN]: {
          CURRENCIES: [
            { code: "USDC", issuer: ISSUER },
            { code: "EURC", issuer: secondIssuer },
          ],
        },
      },
    );
    const envelope = buildEnvelope([
      changeTrust("USDC", ISSUER),
      changeTrust("EURC", secondIssuer),
    ]);

    const result = await analyzeTransaction(
      envelope,
      Networks.TESTNET,
      network,
    );

    expect(result.findings).toEqual([]);
    expect(result.verified).toHaveLength(2);
    expect(network.accountCalls).toEqual([ISSUER, secondIssuer]);
    expect(network.tomlCalls).toEqual([HOME_DOMAIN]);
  });

  it("stops looking up issuers after MAX_ISSUER_LOOKUPS", async () => {
    const accounts: Record<string, { homeDomain: string }> = {};
    const tomls: Record<string, unknown> = {};
    const operations: ReturnType<typeof changeTrust>[] = [];
    const issuers: string[] = [];

    for (let index = 0; index <= MAX_ISSUER_LOOKUPS; index += 1) {
      const issuer = publicKey(30 + index);
      const homeDomain = `issuer-${index}.example`;
      issuers.push(issuer);
      accounts[issuer] = { homeDomain };
      tomls[homeDomain] = {
        CURRENCIES: [{ code: "USDC", issuer }],
      };
      operations.push(changeTrust("USDC", issuer));
    }

    const network = new FakeStellarNetwork(accounts, tomls);
    const envelope = buildEnvelope(operations);

    const result = await analyzeTransaction(
      envelope,
      Networks.TESTNET,
      network,
    );

    expect(network.accountCalls).toEqual(
      issuers.slice(0, MAX_ISSUER_LOOKUPS),
    );
    expect(network.tomlCalls).toHaveLength(MAX_ISSUER_LOOKUPS);
    expect(result.verified).toHaveLength(MAX_ISSUER_LOOKUPS);
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]).toMatchObject({
      operationIndex: MAX_ISSUER_LOOKUPS,
      assetCode: "USDC",
      issuer: issuers[MAX_ISSUER_LOOKUPS],
      reason: "lookup-limit-exceeded",
      severity: "warning",
    });
  });

  it("ignores non-changeTrust operations", async () => {
    const network = new FakeStellarNetwork();
    const envelope = buildEnvelope([
      Operation.payment({
        destination: OTHER_ISSUER,
        asset: Asset.native(),
        amount: "1",
      }),
    ]);

    const result = await analyzeTransaction(
      envelope,
      Networks.TESTNET,
      network,
    );

    expect(result.findings).toEqual([]);
    expect(result.unhandled).toEqual([]);
    expect(network.accountCalls).toEqual([]);
    expect(network.tomlCalls).toEqual([]);
  });

  it("applies the rule to the inner transaction of a fee bump", async () => {
    const network = networkListing("USDC", OTHER_ISSUER);
    const envelope = buildFeeBumpedEnvelope([changeTrust("USDC", ISSUER)]);

    const result = await analyzeTransaction(
      envelope,
      Networks.TESTNET,
      network,
    );

    expect(result.transaction?.feeBumped).toBe(true);
    expect(result.transaction?.sourceAccount).toBe(SOURCE);
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]).toMatchObject({
      operationIndex: 0,
      assetCode: "USDC",
      issuer: ISSUER,
      reason: "issuer-mismatch",
    });
  });

  it("reports a finding for unreadable XDR instead of throwing", async () => {
    const result = await analyzeTransaction(
      "not-base64-xdr",
      Networks.TESTNET,
      new FakeStellarNetwork(),
    );

    expect(result.transaction).toBeNull();
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]).toMatchObject({
      ruleId: "envelope-parse",
      severity: "warning",
      operationIndex: null,
      reason: "invalid-xdr",
    });
  });

  it("notes liquidity-pool trustlines as unhandled without warning", async () => {
    const firstAsset = new Asset("AAA", ISSUER);
    const secondAsset = new Asset("ZZZ", OTHER_ISSUER);
    const [assetA, assetB] =
      Asset.compare(firstAsset, secondAsset) <= 0
        ? [firstAsset, secondAsset]
        : [secondAsset, firstAsset];
    const pool = new LiquidityPoolAsset(assetA, assetB, 30);
    const envelope = buildEnvelope([
      Operation.changeTrust({ asset: pool }),
    ]);

    const result = await analyzeTransaction(
      envelope,
      Networks.TESTNET,
      new FakeStellarNetwork(),
    );

    expect(result.findings).toEqual([]);
    expect(result.unhandled).toEqual([
      expect.objectContaining({
        operationIndex: 0,
        reason: "liquidity-pool-trustline",
      }),
    ]);
  });
});

describe("real mainnet fixture", () => {
  it("parses a genuine mainnet changeTrust envelope", () => {
    const xdr = fs
      .readFileSync(
        path.join(__dirname, "fixtures", "mainnet-change-trust.xdr"),
        "utf8",
      )
      .trim();

    const parsed = parseEnvelope(xdr, Networks.PUBLIC);

    expect(parsed.feeBumped).toBe(false);
    expect(parsed.sourceAccount).toBe(
      "GCRKND5YSHWQTSEWN3I6EWYRZWAGUPVNHG3DIFJYHXKCE6G4OYJHS54L",
    );
    expect(parsed.operations).toHaveLength(1);
    expect(parsed.operations[0]?.type).toBe("changeTrust");
  });
});
