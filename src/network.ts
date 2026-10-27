import { Horizon, StellarToml } from "@stellar/stellar-sdk";

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
    const account = await this.server.loadAccount(accountId);
    const homeDomain = account.home_domain?.trim();

    return { homeDomain: homeDomain ? homeDomain : null };
  }

  async fetchStellarToml(domain: string): Promise<unknown> {
    return StellarToml.Resolver.resolve(domain, {
      allowHttp: false,
      timeout: this.timeoutMs,
    });
  }
}
