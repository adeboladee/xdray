import {
  Account,
  Asset,
  BASE_FEE,
  Keypair,
  Networks,
  Operation,
  TransactionBuilder,
} from "@stellar/stellar-sdk";

const seed = (fill: number) =>
  new Uint8Array(32).fill(fill);

export const SOURCE = Keypair.fromRawEd25519Seed(seed(1)).publicKey();
export const FEE_SOURCE = Keypair.fromRawEd25519Seed(seed(2)).publicKey();
export const ISSUER = Keypair.fromRawEd25519Seed(seed(3)).publicKey();
export const OTHER_ISSUER = Keypair.fromRawEd25519Seed(seed(4)).publicKey();

export function account(accountId: string): Account {
  return new Account(accountId, "1");
}

export function buildEnvelope(
  operations: ReturnType<typeof Operation.changeTrust>[],
  source = SOURCE,
): string {
  const builder = new TransactionBuilder(account(source), {
    fee: BASE_FEE,
    networkPassphrase: Networks.TESTNET,
  });

  for (const operation of operations) {
    builder.addOperation(operation);
  }

  return builder.setTimeout(30).build().toXDR();
}

export function buildFeeBumpedEnvelope(
  operations: ReturnType<typeof Operation.changeTrust>[],
  source = SOURCE,
): string {
  const inner = new TransactionBuilder(account(source), {
    fee: BASE_FEE,
    networkPassphrase: Networks.TESTNET,
  });

  for (const operation of operations) {
    inner.addOperation(operation);
  }

  const innerTransaction = inner.setTimeout(30).build();
  const feeBump = TransactionBuilder.buildFeeBumpTransaction(
    FEE_SOURCE,
    BASE_FEE,
    innerTransaction,
    Networks.TESTNET,
  );

  return feeBump.toXDR();
}

export function changeTrust(code: string, issuer: string) {
  return Operation.changeTrust({
    asset: new Asset(code, issuer),
  });
}
