import { Horizon, StellarToml } from "@stellar/stellar-sdk";

import { validateHomeDomain } from "./homeDomain.js";
import { withTimeout } from "./timeout.js";

export interface AccountInfo {
  homeDomain: string | null;
}

export interface StellarNetwork {
  loadAccount(accountId: string): Promise<AccountInfo>;
  fetchStellarToml(domain: string): Promise<unknown>;
}

export interface HorizonStellarNetworkOptions {
  horizonUrl?: string;
  timeoutMs?: number;
}

export class HorizonStellarNetwork implements StellarNetwork {
  private readonly server: Horizon.Server;
  private readonly timeoutMs: number;

  constructor(options: HorizonStellarNetworkOptions = {}) {
    this.server = new Horizon.Server(
      options.horizonUrl ?? "https://horizon.stellar.org",
    );
    this.timeoutMs = options.timeoutMs ?? 10_000;
  }

  async loadAccount(accountId: string): Promise<AccountInfo> {
    const account = await withTimeout(
      this.server.loadAccount(accountId),
      this.timeoutMs,
      `Horizon account lookup for ${accountId}`,
    );

    return { homeDomain: account.home_domain || null };
  }

  async fetchStellarToml(domain: string): Promise<unknown> {
    const validation = validateHomeDomain(domain);

    if (!validation.ok) {
      throw new Error("Invalid home domain");
    }

    return StellarToml.Resolver.resolve(validation.host, {
      allowHttp: false,
      timeout: this.timeoutMs,
    });
  }
}
