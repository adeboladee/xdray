import type { AccountInfo, StellarNetwork } from "../src/network.js";

type AccountResponse = AccountInfo | Error;
type TomlResponse = unknown | Error;

export class FakeStellarNetwork implements StellarNetwork {
  readonly accountCalls: string[] = [];
  readonly tomlCalls: string[] = [];

  constructor(
    private readonly accounts: Record<string, AccountResponse> = {},
    private readonly tomls: Record<string, TomlResponse> = {},
  ) {}

  async loadAccount(accountId: string): Promise<AccountInfo> {
    this.accountCalls.push(accountId);
    const response = this.accounts[accountId];

    if (response === undefined) {
      throw new Error(`No fake account configured for ${accountId}`);
    }

    if (response instanceof Error) {
      throw response;
    }

    return response;
  }

  async fetchStellarToml(domain: string): Promise<unknown> {
    this.tomlCalls.push(domain);
    const response = this.tomls[domain];

    if (response === undefined) {
      throw new Error(`No fake stellar.toml configured for ${domain}`);
    }

    if (response instanceof Error) {
      throw response;
    }

    return response;
  }
}
