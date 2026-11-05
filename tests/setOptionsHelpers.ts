import {
  BASE_FEE,
  Keypair,
  Networks,
  Operation,
  StrKey,
  TransactionBuilder,
  xdr,
} from "@stellar/stellar-sdk";

import { account, FEE_SOURCE, SOURCE } from "./helpers.js";

const seed = (fill: number) => new Uint8Array(32).fill(fill);

export function testKeypair(fill: number): Keypair {
  return Keypair.fromRawEd25519Seed(seed(fill));
}

export function testPublicKey(fill: number): string {
  return testKeypair(fill).publicKey();
}

export function testSha256Hash(fill: number): Uint8Array {
  return seed(fill);
}

export function testPreAuthTx(fill: number): Uint8Array {
  return seed(fill);
}

export function createSignedPayloadSigner(
  fill: number,
  payloadBytes: Uint8Array = new Uint8Array([1, 2, 3, 4]),
): string {
  const rawKey = testKeypair(fill).rawPublicKey();
  const signedPayload = new xdr.SignerKeyEd25519SignedPayload({
    ed25519: rawKey,
    payload: Buffer.from(payloadBytes),
  });
  return StrKey.encodeSignedPayload(signedPayload.toXdr());
}

export function buildSetOptionsEnvelope(
  operations: ReturnType<
    | typeof Operation.setOptions
    | typeof Operation.changeTrust
    | typeof Operation.payment
    | typeof Operation.manageData
  >[],
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

export function buildFeeBumpedSetOptionsEnvelope(
  operations: ReturnType<
    | typeof Operation.setOptions
    | typeof Operation.changeTrust
    | typeof Operation.payment
    | typeof Operation.manageData
  >[],
  source = SOURCE,
  feeSource = FEE_SOURCE,
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
    feeSource,
    BASE_FEE,
    innerTransaction,
    Networks.TESTNET,
  );

  return feeBump.toXDR();
}

