import { afterEach, describe, expect, it, vi } from "vitest";

import { withTimeout } from "../src/timeout.js";

describe("withTimeout", () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  it("resolves before the deadline and clears the timer", async () => {
    vi.useFakeTimers();

    const result = withTimeout(Promise.resolve("ok"), 1_000, "lookup");

    await expect(result).resolves.toBe("ok");
    expect(vi.getTimerCount()).toBe(0);
  });

  it("propagates an early rejection and clears the timer", async () => {
    vi.useFakeTimers();

    const result = withTimeout(
      Promise.reject(new Error("boom")),
      1_000,
      "lookup",
    );

    await expect(result).rejects.toThrow("boom");
    expect(vi.getTimerCount()).toBe(0);
  });

  it("rejects after the deadline and clears the timer", async () => {
    vi.useFakeTimers();

    const result = withTimeout(
      new Promise<string>(() => {}),
      1_000,
      "lookup",
    );
    const expectation = expect(result).rejects.toThrow(
      "lookup timed out after 1000ms",
    );

    await vi.advanceTimersByTimeAsync(1_000);
    await expectation;
    expect(vi.getTimerCount()).toBe(0);
  });
});
