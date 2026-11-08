# Contributing to XDRay

XDRay reads an unsigned Stellar transaction and explains, in plain language, what could hurt the account signing it. Most contributions are one of: a new rule, a better test, a real-transaction fixture, or a documentation fix. Small, scoped pull requests are easiest to review.

## Setup

You need Node.js 22.13 or newer.

```bash
git clone https://github.com/adeboladee/xdray.git
cd xdray
npm install
```

| Command | What it does |
| ------- | ------------ |
| `npm test` | Unit tests. They use a fake network and make no live calls. |
| `npm run lint` | ESLint |
| `npm run typecheck` | TypeScript type check |
| `npm run build` | Compile to `dist/` |
| `npm run test:integration` | One test against live Horizon (set `XDRAY_INTEGRATION=1`; not run in CI) |

Please run lint, typecheck, test and build before opening a pull request. CI runs the same four on every pull request.

Line endings are LF, enforced by `.gitattributes`.

## How the code is organised

- `src/parseEnvelope.ts` reads the XDR and works out, for every operation, the account it acts on (the operation's own source, otherwise the transaction source).
- `src/rules/` holds one file per rule, registered in `src/rules/index.ts`.
- `src/analyze.ts` runs every registered rule and merges the results. A rule that throws becomes a finding, never a crash.
- `src/types.ts` defines findings, severities and reason codes.
- `docs/rules/` holds one document per rule.

## Adding a rule

A rule implements `Rule` from `src/rules/types.ts`: an `id` and an `evaluate({ transaction, network })` that returns `{ findings, verified, unhandled }`.

1. Create `src/rules/yourRule.ts` and export the rule.
2. Register it in `src/rules/index.ts` and export it from `src/index.ts`.
3. Add any new reason codes to `FindingReason` in `src/types.ts`.
4. Add tests in a new file under `tests/` that calls `analyzeTransaction` with the `FakeStellarNetwork` helper from `tests/fakeNetwork.ts`.
5. Add `docs/rules/NNN-name.md` and a row in the README table.

Rule 002 (`src/rules/signerChange.ts`) is the best small example. Rule 001 shows a rule that makes network lookups.

### Rules every rule follows

- **Input is hostile.** Anything that comes from a transaction or from the ledger (a home domain, a memo, an asset code) is attacker-controlled. Validate it before using it. Never put such a string into a finding message: use fixed text and values produced by strict encoders (strkeys, hex, integers).
- **Fail loudly, never quietly.** If a value cannot be read, emit a finding or an `unhandled` entry. A rule that silently skips something unreadable makes a risky transaction look clean.
- **No hardcoded trust.** Do not add lists of "official" issuer addresses from memory. If a list is needed, open an issue to discuss where it comes from.
- **Say what the transaction does, not what the signer intends.** Legitimate rotations and attacks can look identical. Messages should state the effect and ask the signer to verify.
- **No claims the rule cannot back up.** If a rule needs account state it does not fetch, say so in its doc.

## Tests and fixtures

- Prefer **real mainnet transactions** as fixtures. Fetch the `envelope_xdr` for a transaction from Horizon, save it under `tests/fixtures/`, and write the expected values from Horizon's own JSON, not from XDRay's output.
- Transactions built in code are fine, but label them as synthetic in the test names.
- Do not edit or skip an existing test to make a change pass. If a test must change, explain why in the pull request.
- Unit tests must not make network calls.

## Pull requests

- One change per pull request, linked to an issue where there is one.
- Say what changed and why, and mention anything you could not verify.
- Docs for any new or changed behaviour are part of the change.
- Commit messages follow the existing style: `feat(rule-004): ...`, `fix: ...`, `docs: ...`, `test: ...`.

## Finding issues to work on

Look for the `good first issue` and `help wanted` labels. Each issue states its scope and what "done" looks like. If something is unclear, ask on the issue before starting.

## Reporting a security problem

If you find a way a crafted transaction can make XDRay report something unsafe as clean, please open an issue with the transaction (XDR is public data) and the output you got. There are no secrets in this project.

## License

By contributing you agree that your work is released under the MIT license.