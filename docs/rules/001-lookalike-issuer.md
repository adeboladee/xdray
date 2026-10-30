# Rule 001: look-alike asset issuer

**Rule id:** `lookalike-asset-issuer` · **Operation checked:** `changeTrust`

## Why this rule exists

On Stellar an asset is identified by its code plus its issuer account. Anyone can create an asset with the code `USDC`, so a signer who approves a trustline cannot tell from the code alone whether they are adding the real asset or a look-alike. This rule checks whether the issuer is backed by a domain that lists that exact asset.

## How the rule decides

For each `changeTrust` operation in the envelope (fee-bump envelopes are unwrapped first):

1. Read the asset code and issuer. Liquidity-pool trustlines are reported in `unhandled`, not checked.
2. Load the issuer account from Horizon and read its `home_domain`.
3. Validate the `home_domain` as a public hostname (see below). Skip any request if it fails.
4. Fetch `https://<home_domain>/.well-known/stellar.toml` and read `CURRENCIES` ([SEP-1](https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0001.md)).
5. The asset is **verified** only if a `CURRENCIES` entry matches both the code and the exact issuer account.

A verified asset produces no finding. It appears in `result.verified` with the home domain that vouched for it, so a wallet can show "USDC issued by circle.com".

## Findings

| Reason | Severity | Meaning |
| ------ | -------- | ------- |
| `issuer-mismatch` | critical | The domain lists this code under a different issuer. The strongest look-alike signal. |
| `asset-not-listed` | warning | The domain's `stellar.toml` does not list this code and issuer. |
| `no-home-domain` | warning | The issuer publishes no home domain, so there is nothing to verify against. |
| `invalid-home-domain` | warning | The issuer's home domain is not a valid public hostname. No request was made. |
| `account-unreachable` | warning | The issuer account could not be loaded (not found, timeout, network error). |
| `toml-unreachable` | warning | The domain's `stellar.toml` could not be fetched. |
| `toml-malformed` | warning | The file parsed, but is not an object or `CURRENCIES` is not an array. |
| `lookup-limit-exceeded` | warning | The transaction references more than 10 distinct issuers; the extras were not checked. |
| `unsupported-asset` | warning | The asset in the operation could not be read. |

Messages never include the raw `home_domain` string, because it is attacker-controlled.

## Results against mainnet

Run on 2026-10-30 against public Horizon and the live `circle.com` `stellar.toml`, using Circle's USDC issuer `GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN` (listed in circle.com's own `stellar.toml`):

| Trustline tested | Result |
| ---------------- | ------ |
| `USDC` under that issuer | No finding. `verified` shows home domain `circle.com`. |
| `USDX` under that issuer | `asset-not-listed` |
| `EURC` under that issuer | `issuer-mismatch` (critical): circle.com lists `EURC` under a different account |
| `USDC` under an unrelated account whose home domain is `lobstr.co` | `asset-not-listed` |

The parser was also checked against a real mainnet transaction (`tests/fixtures/mainnet-change-trust.xdr`): it contains one `changeTrust` for asset `XAU`, and the asset code and issuer the parser extracts match Horizon's record of the transaction.

## What this rule does not prove

Read this before relying on a clean result.

1. **A domain vouching for an asset is not the same as the asset being legitimate.** An attacker can register their own domain, publish a `stellar.toml` that lists a fake `USDC` under their own issuer, and set that issuer's `home_domain` to it. The rule will report that asset as verified. It only proves the issuer and its claimed domain agree. This is why `verified` returns the domain: a wallet should show it to the user, who can notice `circle-usdc.example` is not `circle.com`. For punycode (`xn--`) domains the result also carries `punycode: true` and `homeDomainUnicode` so both forms can be shown. A list of known-good domains for well-known assets is a possible later addition and is not built.
2. **Some legitimate assets get a warning.** The rule only matches `CURRENCIES` entries that give a literal `code` and `issuer`. Entries that use `code_template` wildcards, or that link to a separate file through `toml=`, are not followed, so assets listed that way come back as `asset-not-listed`.
3. **Host-name checks cannot stop DNS tricks.** The rule rejects IP literals, `localhost`, internal-style suffixes and ports. It cannot stop a public-looking name that resolves to a private address (wildcard DNS services, DNS rebinding). Anyone running this on a server should also restrict outbound network access.
4. **No overall deadline.** Each lookup is bounded individually (10-second timeout), and at most 10 distinct issuers are looked up per analysis. A single analysis can still take a long time in the worst case. The Horizon timeout bounds how long the analysis waits; it does not cancel the underlying request.
5. **The answer is only as honest as the Horizon server you point it at.** The issuer's `home_domain` comes from Horizon. A malicious or compromised server could return a false one.
6. **Narrow scope.** Only `changeTrust` is checked. Liquidity-pool trustlines are not evaluated. Trial runs covered mainnet only.

## Fetch protections

The `stellar.toml` request uses the Stellar SDK's resolver with HTTPS only, a 10-second timeout, a 100 KiB response cap and no redirects. This was audited from the SDK source at the time of writing and should be re-checked when the SDK is upgraded.

## Home-domain validation

`src/homeDomain.ts` normalizes and validates every `home_domain` before use. It rejects, rather than trims, anything with whitespace, non-ASCII characters, ports, userinfo, paths or underscores, IP literals in decimal, hex and shorthand form as well as dotted form, single-label names, `localhost`, and internal-style suffixes (`.local`, `.internal`, `.lan` and similar). Characters are checked before lowercasing, so characters that lowercase into ASCII (such as the Kelvin sign) are rejected. The validated, normalized host is used for the request, the cache key and the output.