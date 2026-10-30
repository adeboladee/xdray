import { isIP } from "node:net";

export type HomeDomainValidation =
  | { ok: true; host: string }
  | { ok: false };

const MAX_HOST_LENGTH = 253;
const MAX_LABEL_LENGTH = 63;
const VALID_CHARS = /^[A-Za-z0-9.-]+$/;
const FORBIDDEN_SUFFIXES = [
  "localhost",
  "local",
  "internal",
  "localdomain",
  "lan",
  "home",
  "corp",
  "intranet",
];

export function validateHomeDomain(raw: string): HomeDomainValidation {
  let host = raw;

  if (host.endsWith(".")) {
    host = host.slice(0, -1);
  }

  if (host.length === 0 || host.length > MAX_HOST_LENGTH) {
    return { ok: false };
  }

  if (!VALID_CHARS.test(host)) {
    return { ok: false };
  }

  host = host.toLowerCase();

  const labels = host.split(".");

  if (labels.length < 2) {
    return { ok: false };
  }

  for (const label of labels) {
    if (
      label.length === 0 ||
      label.length > MAX_LABEL_LENGTH ||
      label.startsWith("-") ||
      label.endsWith("-")
    ) {
      return { ok: false };
    }
  }

  const lastLabel = labels[labels.length - 1];

  if (!lastLabel || !/^[a-z]/.test(lastLabel)) {
    return { ok: false };
  }

  if (isIP(host) !== 0) {
    return { ok: false };
  }

  if (
    host === "localhost" ||
    FORBIDDEN_SUFFIXES.some(
      (suffix) => host === suffix || host.endsWith(`.${suffix}`),
    )
  ) {
    return { ok: false };
  }

  try {
    if (new URL(`https://${host}`).hostname !== host) {
      return { ok: false };
    }
  } catch {
    return { ok: false };
  }

  return { ok: true, host };
}
