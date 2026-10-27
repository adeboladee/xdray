import {
  FeeBumpTransaction,
  TransactionBuilder,
} from "@stellar/stellar-sdk";

import type { ParsedTransaction } from "./types.js";

export function parseEnvelope(
  xdr: string,
  networkPassphrase: string,
): ParsedTransaction {
  const parsed = TransactionBuilder.fromXDR(xdr, networkPassphrase);
  const feeBumped = parsed instanceof FeeBumpTransaction;
  const transaction = feeBumped ? parsed.innerTransaction : parsed;

  return {
    sourceAccount: transaction.source,
    operations: transaction.operations,
    feeBumped,
  };
}
