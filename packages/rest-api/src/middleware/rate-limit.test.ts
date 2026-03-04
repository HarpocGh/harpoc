import { describe, it, expect } from "vitest";
import { RateLimiter } from "./rate-limit.js";

describe("RateLimiter", () => {
  it("allows requests within the global limit", () => {
    const limiter = new RateLimiter(10, 5, 5);
    for (let i = 0; i < 10; i++) {
      limiter.checkGlobal();
    }
    // 11th should throw
    expect(() => limiter.checkGlobal()).toThrow("Global rate limit exceeded");
  });

  it("allows requests within the per-secret limit", () => {
    const limiter = new RateLimiter(1000, 3, 3);
    for (let i = 0; i < 3; i++) {
      limiter.checkSecret("secret-1");
    }
    expect(() => limiter.checkSecret("secret-1")).toThrow("Per-secret rate limit exceeded");
  });

  it("tracks per-secret limits independently", () => {
    const limiter = new RateLimiter(1000, 2, 2);
    limiter.checkSecret("secret-1");
    limiter.checkSecret("secret-1");
    expect(() => limiter.checkSecret("secret-1")).toThrow();

    // Different secret should still work
    limiter.checkSecret("secret-2");
    limiter.checkSecret("secret-2");
    expect(() => limiter.checkSecret("secret-2")).toThrow();
  });

  it("uses useSecretLimit when isUseSecret is true", () => {
    const limiter = new RateLimiter(1000, 10, 2);
    limiter.checkSecret("secret-1", true);
    limiter.checkSecret("secret-1", true);
    expect(() => limiter.checkSecret("secret-1", true)).toThrow();

    // Regular access still has higher limit
    limiter.checkSecret("secret-2", false);
    limiter.checkSecret("secret-2", false);
    // perSecretLimit is 10, so this should work
    limiter.checkSecret("secret-2", false);
  });
});
