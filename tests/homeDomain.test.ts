import { describe, expect, it } from "vitest";

import { validateHomeDomain } from "../src/homeDomain.js";
import { HorizonStellarNetwork } from "../src/index.js";

const LONG_HOST = [
  "a".repeat(63),
  "a".repeat(63),
  "a".repeat(63),
  "a".repeat(62),
].join(".");

describe("validateHomeDomain", () => {
  it.each([
    ["circle.com", "circle.com"],
    ["Sub.Domain.Example", "sub.domain.example"],
    ["EXAMPLE.COM", "example.com"],
    ["issuer.example.", "issuer.example"],
    ["xn--bcher-kva.example", "xn--bcher-kva.example"],
  ])("accepts %s as %s", (raw, host) => {
    expect(validateHomeDomain(raw)).toEqual({ ok: true, host });
  });

  it.each([
    "127.0.0.1",
    "10.0.0.5",
    "169.254.169.254",
    "2130706433",
    "127.1",
    "0x7f.0.0.1",
    "[::1]",
    "::1",
    "localhost",
    "a.localhost",
    "intranet",
    "host.local",
    "svc.internal",
    "example.com:8443",
    "user@example.com",
    "example.com/path",
    "example.com?x=1",
    "exa mple.com",
    "exämple.com",
    "exam\u212Aple.com",
    "\u0130ssuer.example",
    " example.com",
    "example.com ",
    "example\u00A0.com",
    "under_score.com",
    "-bad.com",
    "bad-.com",
    "",
    LONG_HOST,
    `${"a".repeat(64)}.com`,
  ])("rejects %s", (raw) => {
    expect(validateHomeDomain(raw)).toEqual({ ok: false });
  });
});

describe("HorizonStellarNetwork home domain validation", () => {
  it("rejects an invalid domain before fetching", async () => {
    const network = new HorizonStellarNetwork();

    await expect(network.fetchStellarToml("127.0.0.1")).rejects.toThrow(
      "Invalid home domain",
    );
  });
});
