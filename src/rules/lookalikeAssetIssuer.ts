import type { AccountInfo, StellarNetwork } from "../network.js";
import type {
  Finding,
  FindingReason,
  ParsedTransaction,
  UnhandledOperation,
  VerifiedAsset,
} from "../types.js";

export interface RuleContext {
  transaction: ParsedTransaction;
  network: StellarNetwork;
}

export interface RuleResult {
  findings: Finding[];
  verified: VerifiedAsset[];
  unhandled: UnhandledOperation[];
}

export interface Rule {
  readonly id: "lookalike-asset-issuer";
  evaluate(context: RuleContext): Promise<RuleResult>;
}

interface AssetDetails {
  code: string;
  issuer: string;
}

type AssetReadResult =
  | { kind: "asset"; asset: AssetDetails }
  | { kind: "liquidity-pool" }
  | { kind: "unreadable" };

type VerificationResult =
  | { verified: true; homeDomain: string }
  | { verified: false; reason: FindingReason; message: string };

interface LookupCaches {
  accounts: Map<string, Promise<AccountInfo>>;
  tomls: Map<string, Promise<unknown>>;
}

export const MAX_ISSUER_LOOKUPS = 10;

const RULE_ID = "lookalike-asset-issuer" as const;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function cachedLoadAccount(
  caches: LookupCaches,
  network: StellarNetwork,
  accountId: string,
): Promise<AccountInfo> {
  const cached = caches.accounts.get(accountId);

  if (cached) {
    return cached;
  }

  const promise = Promise.resolve().then(() => network.loadAccount(accountId));
  caches.accounts.set(accountId, promise);

  return promise;
}

function cachedFetchStellarToml(
  caches: LookupCaches,
  network: StellarNetwork,
  domain: string,
): Promise<unknown> {
  const cached = caches.tomls.get(domain);

  if (cached) {
    return cached;
  }

  const promise = Promise.resolve().then(() =>
    network.fetchStellarToml(domain),
  );
  caches.tomls.set(domain, promise);

  return promise;
}

function readAsset(line: unknown): AssetReadResult {
  if (typeof line !== "object" || line === null) {
    return { kind: "unreadable" };
  }

  const candidate = line as {
    getAssetType?: () => string;
    getCode?: () => string;
    getIssuer?: () => string | undefined;
  };

  try {
    if (candidate.getAssetType?.() === "liquidity_pool_shares") {
      return { kind: "liquidity-pool" };
    }

    const code = candidate.getCode?.();
    const issuer = candidate.getIssuer?.();

    if (!code || !issuer) {
      return { kind: "unreadable" };
    }

    return { kind: "asset", asset: { code, issuer } };
  } catch {
    return { kind: "unreadable" };
  }
}

function readCurrencies(
  document: unknown,
): { ok: true; currencies: unknown[] } | { ok: false } {
  if (!isRecord(document)) {
    return { ok: false };
  }

  if (!("CURRENCIES" in document)) {
    return { ok: true, currencies: [] };
  }

  if (!Array.isArray(document.CURRENCIES)) {
    return { ok: false };
  }

  return { ok: true, currencies: document.CURRENCIES };
}

function malformedToml(
  asset: AssetDetails,
  homeDomain: string,
): VerificationResult {
  return {
    verified: false,
    reason: "toml-malformed",
    message:
      `This trustline is for ${asset.code} issued by ${asset.issuer}. ` +
      `The issuer's website (${homeDomain}) publishes an asset list we could not read, so the asset could not be verified.`,
  };
}

async function verifyAsset(
  asset: AssetDetails,
  network: StellarNetwork,
  caches: LookupCaches,
): Promise<VerificationResult> {
  let homeDomain: string | null;

  try {
    const account = await cachedLoadAccount(caches, network, asset.issuer);
    homeDomain = account.homeDomain?.trim() || null;
  } catch {
    return {
      verified: false,
      reason: "account-unreachable",
      message:
        `This trustline is for ${asset.code} issued by ${asset.issuer}. ` +
        "We could not look up the issuer account, so the asset could not be verified.",
    };
  }

  if (!homeDomain) {
    return {
      verified: false,
      reason: "no-home-domain",
      message:
        `This trustline is for ${asset.code} issued by ${asset.issuer}. ` +
        "That issuer does not publish a home domain, so the asset cannot be verified as legitimate.",
    };
  }

  let document: unknown;

  try {
    document = await cachedFetchStellarToml(caches, network, homeDomain);
  } catch {
    return {
      verified: false,
      reason: "toml-unreachable",
      message:
        `This trustline is for ${asset.code} issued by ${asset.issuer}. ` +
        `The issuer's website (${homeDomain}) could not be reached to verify the asset.`,
    };
  }

  const currencies = readCurrencies(document);

  if (!currencies.ok) {
    return malformedToml(asset, homeDomain);
  }

  let sawSameCode = false;

  for (const entry of currencies.currencies) {
    if (!isRecord(entry)) {
      continue;
    }

    const { code, issuer } = entry;

    if (typeof code !== "string" || typeof issuer !== "string") {
      continue;
    }

    if (code !== asset.code) {
      continue;
    }

    sawSameCode = true;

    if (issuer === asset.issuer) {
      return { verified: true, homeDomain };
    }
  }

  if (sawSameCode) {
    return {
      verified: false,
      reason: "issuer-mismatch",
      message:
        `This trustline is for ${asset.code} issued by ${asset.issuer}. ` +
        `The issuer's website (${homeDomain}) lists ${asset.code} under a different account, ` +
        "so this may be a look-alike asset rather than the real one.",
    };
  }

  return {
    verified: false,
    reason: "asset-not-listed",
    message:
      `This trustline is for ${asset.code} issued by ${asset.issuer}. ` +
      `The issuer's website (${homeDomain}) does not list this exact code and issuer, so the asset could not be verified.`,
  };
}

function findingForUnverifiedAsset(
  operationIndex: number,
  asset: AssetDetails,
  result: Extract<VerificationResult, { verified: false }>,
): Finding {
  return {
    ruleId: RULE_ID,
    severity: result.reason === "issuer-mismatch" ? "critical" : "warning",
    operationIndex,
    assetCode: asset.code,
    issuer: asset.issuer,
    reason: result.reason,
    message: result.message,
  };
}

export const lookalikeAssetIssuerRule: Rule = {
  id: RULE_ID,

  async evaluate({ transaction, network }: RuleContext): Promise<RuleResult> {
    const findings: Finding[] = [];
    const verified: VerifiedAsset[] = [];
    const unhandled: UnhandledOperation[] = [];
    const caches: LookupCaches = {
      accounts: new Map(),
      tomls: new Map(),
    };

    for (const [operationIndex, operation] of transaction.operations.entries()) {
      if (operation.type !== "changeTrust") {
        continue;
      }

      const read = readAsset(operation.line);

      if (read.kind === "liquidity-pool") {
        unhandled.push({
          operationIndex,
          reason: "liquidity-pool-trustline",
          message:
            "This changeTrust operation is for a liquidity-pool trustline. " +
            "Liquidity-pool trustlines are not checked by this rule yet.",
        });
        continue;
      }

      if (read.kind === "unreadable") {
        findings.push({
          ruleId: RULE_ID,
          severity: "warning",
          operationIndex,
          assetCode: null,
          issuer: null,
          reason: "unsupported-asset",
          message:
            "This changeTrust operation uses an asset we could not read, so it could not be verified.",
        });
        continue;
      }

      const issuerAlreadyCached = caches.accounts.has(read.asset.issuer);

      if (
        !issuerAlreadyCached &&
        caches.accounts.size >= MAX_ISSUER_LOOKUPS
      ) {
        findings.push({
          ruleId: RULE_ID,
          severity: "warning",
          operationIndex,
          assetCode: read.asset.code,
          issuer: read.asset.issuer,
          reason: "lookup-limit-exceeded",
          message:
            `This trustline is for ${read.asset.code} issued by ${read.asset.issuer}. ` +
            `It was not checked because the transaction references more than ${MAX_ISSUER_LOOKUPS} different issuers.`,
        });
        continue;
      }

      const result = await verifyAsset(read.asset, network, caches);

      if (result.verified) {
        verified.push({
          ruleId: RULE_ID,
          operationIndex,
          assetCode: read.asset.code,
          issuer: read.asset.issuer,
          homeDomain: result.homeDomain,
        });
      } else {
        findings.push(
          findingForUnverifiedAsset(operationIndex, read.asset, result),
        );
      }
    }

    return { findings, verified, unhandled };
  },
};
