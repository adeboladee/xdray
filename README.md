# XDRay

[![CI](https://github.com/adeboladee/xdray/actions/workflows/ci.yml/badge.svg)](https://github.com/adeboladee/xdray/actions/workflows/ci.yml)

An X-ray for Stellar transactions. XDRay takes an unsigned transaction envelope (XDR) and reports, in plain language, anything in it that could hurt the account about to sign it.

Stellar wallets and signing flows often show users opaque XDR or a terse list of operations that is hard to judge by eye. Stellar also has risks that depend on how its operations work: a trustline to a look-alike issuer, a change to an account's signers, a master key being switched off. XDRay is a library that wallets and tools can call before asking a user to sign, with each risk written up as a documented rule.

> **Status: early.** Three rules are implemented, plus a coverage report for what is not checked yet. The project is not published to npm and is not a security guarantee. A clean result means no implemented rule found a problem, not that a transaction is safe.

## Implemented rules

| Rule | Detects | Doc |
| ---- | ------- | --- |
| 001 `lookalike-asset-issuer` | A `changeTrust` to an asset whose issuer cannot be verified through the issuer's `stellar.toml` | [docs/rules/001-lookalike-issuer.md](docs/rules/001-lookalike-issuer.md) |
| 002 `signer-change` | A `setOptions` that adds, changes or removes a signer. Critical at weight 255, which can authorize everything alone. Hash(x) and pre-authorized-transaction signers get extra explanation. | [docs/rules/002-signer-change.md](docs/rules/002-signer-change.md) |
| 003 `master-key-weight` | A `setOptions` that changes the master key weight. Critical at 0: either the key is disabled, or signing control is handed to other keys in the same transaction. | [docs/rules/003-master-key-weight.md](docs/rules/003-master-key-weight.md) |

A fourth rule, `set-options-coverage`, reports `setOptions` fields that no rule checks yet (thresholds, home domain, account flags, inflation destination) as `unhandled`, so a clean result does not hide them.

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
console.log(result.unhandled);  // operations or fields no rule could evaluate
```

`result.transaction` holds the parsed source account and whether the envelope was fee-bumped, and is `null` if the XDR could not be read. `analyzeTransaction` does not throw on bad input: unreadable XDR and rule failures come back as findings.

The network passphrase is used to parse the envelope. Lookups go to the Horizon server you give `HorizonStellarNetwork`, which defaults to public mainnet Horizon. For testnet, pass `{ horizonUrl: "https://horizon-testnet.stellar.org" }`. You can also supply your own object implementing `StellarNetwork` (`loadAccount` and `fetchStellarToml`).

### What a finding contains

| Field | Meaning |
| ----- | ------- |
| `ruleId` | The rule that produced it, for example `signer-change` |
| `severity` | `critical`, `warning` or `info` |
| `operationIndex` | Which operation in the transaction (`null` for envelope-level problems) |
| `account` | The account the operation acts on: the operation's own source if it has one, otherwise the transaction source (muxed addresses are normalized to the underlying `G...` account) |
| `reason` | A stable code such as `control-handover` or `issuer-mismatch` |
| `message` | A plain-language explanation for the person signing |

Findings are sorted by operation index, then by rule order.

## What a clean result does not mean

- **Static analysis only.** The `setOptions` rules read the transaction, not the account's current signers or thresholds. They cannot tell a legitimate key rotation from a takeover, so messages say what the transaction does and ask the signer to verify.
- **Not every field is checked.** See `unhandled` and the roadmap below.
- **A domain vouching for an asset is not proof the asset is legitimate.** See the rule 001 doc.
- **Node.js only for now.** The library uses `Buffer` and `node:` modules.
- **Tests for `setOptions` use synthetic transactions.** Real mainnet fixtures are tracked as an issue.

## Design principles

- **Input is hostile.** Values such as an issuer's `home_domain` are attacker-controlled, so they are validated before any request is made.
- **No hardcoded trust.** The library contains no list of "official" issuer addresses. Verification comes from live lookups.
- **Failures are findings.** Network errors, malformed files and bad XDR produce a result, never an uncaught exception. A signer or weight the tool cannot read produces a warning, not silence.
- **Network access is injectable.** Unit tests run against a fake network and make no live calls.

## Adding a rule

Each rule lives in `src/rules/` and implements the `Rule` interface from `src/rules/types.ts`: an `id` and an `evaluate({ transaction, network })` that returns `{ findings, verified, unhandled }`.

1. Create `src/rules/yourRule.ts` and export the rule.
2. Register it in `src/rules/index.ts` and export it from `src/index.ts`.
3. Add any new reason codes to `FindingReason` in `src/types.ts`.
4. Add tests in a new file under `tests/`, calling `analyzeTransaction` with the `FakeStellarNetwork` helper. Prefer real mainnet transactions as fixtures, and label synthetic ones.
5. Add `docs/rules/NNN-name.md`: what it detects, how it decides, and what it does not prove.

Messages must only contain fixed text and values produced by strict encoders (strkeys, hex, integers), never raw strings from the transaction.

## Roadmap

Tracked as issues: threshold changes, `home_domain` changes on an account, account flags (including clawback), clawback-enabled trustlines, path payments with no slippage protection, state-aware lockout detection using the account's current signers, and browser compatibility.

## Development

| Command | What it does |
| ------- | ------------ |
| `npm test` | Unit tests (fake network, no live calls) |
| `npm run test:integration` | One test against live Horizon |
| `npm run lint` | ESLint |
| `npm run typecheck` | TypeScript type check |
| `npm run build` | Compile to `dist/` |

Needs Node.js 22.13 or newer. CI runs lint, typecheck, tests and build on that version and the current LTS.

`typescript-eslint` does not yet support TypeScript 7, so ESLint runs on `typescript@6` while `typecheck` and `build` use TypeScript 7 through the `typescript7` alias in `package.json`.

## License

MIT