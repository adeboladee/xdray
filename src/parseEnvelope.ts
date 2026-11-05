import {
  FeeBumpTransaction,
  TransactionBuilder,
  extractBaseAddress,
} from "@stellar/stellar-sdk";

import type { ParsedOperation, ParsedTransaction } from "./types.js";

export function parseEnvelope(
  xdr: string,
  networkPassphrase: string,
): ParsedTransaction {
  const parsed = TransactionBuilder.fromXDR(xdr, networkPassphrase);
  const feeBumped = parsed instanceof FeeBumpTransaction;
  const transaction = feeBumped ? parsed.innerTransaction : parsed;
  const operations = transaction.operations.map(
    (operation): ParsedOperation => ({
      ...operation,
      account: extractBaseAddress(operation.source ?? transaction.source),
    }),
  );

  return {
    sourceAccount: transaction.source,
    operations,
    feeBumped,
  };
}
