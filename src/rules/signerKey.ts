import { StrKey } from "@stellar/stellar-sdk";

import type { ParsedOperation } from "../types.js";

export type SignerRecord = NonNullable<
  Extract<ParsedOperation, { type: "setOptions" }>["signer"]
>;

export type SignerKeyType =
  | "ed25519"
  | "hash-x"
  | "pre-auth-tx"
  | "signed-payload";

export interface SignerKeyInfo {
  keyStr: string;
  keyType: SignerKeyType;
}

export function extractSignerKeyInfo(signer: SignerRecord): SignerKeyInfo | null {
  if (
    "ed25519PublicKey" in signer &&
    typeof signer.ed25519PublicKey === "string"
  ) {
    return {
      keyStr: signer.ed25519PublicKey,
      keyType: "ed25519",
    };
  }

  if ("sha256Hash" in signer && signer.sha256Hash instanceof Uint8Array) {
    const strkey = StrKey.encodeSha256Hash(signer.sha256Hash);
    const hex = Buffer.from(signer.sha256Hash).toString("hex");
    return {
      keyStr: `${strkey} (hex: ${hex})`,
      keyType: "hash-x",
    };
  }

  if ("preAuthTx" in signer && signer.preAuthTx instanceof Uint8Array) {
    const strkey = StrKey.encodePreAuthTx(signer.preAuthTx);
    const hex = Buffer.from(signer.preAuthTx).toString("hex");
    return {
      keyStr: `${strkey} (hex: ${hex})`,
      keyType: "pre-auth-tx",
    };
  }

  if (
    "ed25519SignedPayload" in signer &&
    typeof signer.ed25519SignedPayload === "string"
  ) {
    return {
      keyStr: signer.ed25519SignedPayload,
      keyType: "signed-payload",
    };
  }

  return null;
}

