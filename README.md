# XDRay

An X-ray for Stellar transactions. XDRay takes an unsigned transaction envelope (XDR) and reports, in plain language, anything in it that could hurt the account about to sign it.

Stellar wallets and signing flows often show users opaque XDR or a terse list of operations that is hard to judge by eye. Stellar also has risks that depend on how its operations work: a trustline to a look-alike issuer, a change to an account's signers or thresholds, an asset the issuer can claw back. XDRay is a library that wallets and tools can call before asking a user to sign, with each risk written up as a documented rule.

> **Status: early.** One rule is implemented. The project is not published to npm and is not a security guarantee. A clean result means no implemented rule found a problem, not that a transaction is safe.

## Implemented rules

| Rule | Detects | Doc |
| ---- | ------- | --- |
| 001 `lookalike-asset-issuer` | A `changeTrust` to an asset whose issuer cannot be verified through the issuer's `stellar.toml` | [docs/rules/001-lookalike-issuer.md](docs/rules/001-lookalike-issuer.md) |

Planned, not yet built: rules for the `setOptions` family (signer changes, master key weight, thresholds, home domain). Each rule gets its own doc and its own issue.

## Usage

```bash
git clone https://github.com/adeboladee/xdray.git
cd xdray
npm install
```

```ts
import { Networks } from "@stellar/stellar-sdk";
import { analyzeTransaction, HorizonStellarNetwork } from "./src/index.js";

const network = new HorizonStellarNetwork(); // public Horizon by default
const result = await analyzeTransaction(envelopeXdr, Networks.PUBLIC, network);

console.log(result.findings);   // problems the rules found
console.log(result.verified);   // assets that checked out, with the domain that vouched for them
console.log(result.unhandled);  // operations the rules could not evaluate
```

`result.transaction` holds the parsed source account and whether the envelope was fee-bumped. `analyzeTransaction` does not throw on bad input: unreadable XDR and rule failures come back as findings.

The network passphrase is used to parse the envelope. Lookups go to the Horizon server you give `HorizonStellarNetwork`, which defaults to public mainnet Horizon. For testnet, pass `{ horizonUrl: "https://horizon-testnet.stellar.org" }`. You can also supply your own object implementing `StellarNetwork` (`loadAccount` and `fetchStellarToml`).

## Design principles

- **Input is hostile.** Values such as an issuer's `home_domain` are attacker-controlled, so they are validated before any request is made.
- **No hardcoded trust.** The library contains no list of "official" issuer addresses. Verification comes from live lookups.
- **Failures are findings.** Network errors, malformed files and bad XDR produce a result, never an uncaught exception.
- **Network access is injectable.** Unit tests run against a fake network and make no live calls.

## Development

| Command | What it does |
| ------- | ------------ |
| `npm test` | Unit tests (fake network, no live calls) |
| `npm run test:integration` | One test against live Horizon |
| `npm run lint` | ESLint |
| `npm run typecheck` | TypeScript type check |
| `npm run build` | Compile to `dist/` |

Needs a current Node.js LTS release.

`typescript-eslint` does not yet support TypeScript 7, so ESLint runs on `typescript@6` while `typecheck` and `build` use TypeScript 7 through the `typescript7` alias in `package.json`.

## Contributing

Each rule lives in `src/rules/` with a matching doc in `docs/rules/` that explains what it detects, how it decides, and what it does not prove. A new rule should ship with its doc and tests built from real transactions where possible. Check the open issues for scoped tasks.

## License

MIT