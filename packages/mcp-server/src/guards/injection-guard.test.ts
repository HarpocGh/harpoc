import { describe, it, expect } from "vitest";
import { InjectionGuard } from "./injection-guard.js";

describe("InjectionGuard", () => {
  it("returns clean content unchanged", () => {
    const guard = new InjectionGuard();
    const input = '{"status": "ok", "data": "hello world"}';
    expect(guard.sanitize(input)).toBe(input);
    expect(guard.totalRedactions).toBe(0);
  });

  it("redacts Bearer tokens", () => {
    const guard = new InjectionGuard();
    const input = 'Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.something.signature';
    const result = guard.sanitize(input);
    expect(result).toBe("Authorization: [REDACTED]");
    expect(guard.totalRedactions).toBe(1);
  });

  it("redacts Basic auth", () => {
    const guard = new InjectionGuard();
    const input = 'Authorization: Basic dXNlcjpwYXNzd29yZA==';
    const result = guard.sanitize(input);
    expect(result).toBe("Authorization: [REDACTED]");
    expect(guard.totalRedactions).toBe(1);
  });

  it("redacts API key patterns", () => {
    const guard = new InjectionGuard();
    const input = 'api_key=sk_live_1234567890abcdef';
    const result = guard.sanitize(input);
    expect(result).toBe("api_key=[REDACTED]");
  });

  it("redacts token patterns", () => {
    const guard = new InjectionGuard();
    const input = 'token: "ghp_ABCDEFghijklmnop1234"';
    const result = guard.sanitize(input);
    expect(result).toContain("[REDACTED]");
  });

  it("redacts secret patterns", () => {
    const guard = new InjectionGuard();
    const input = 'secret="sk_test_abcdefghijklmnop"';
    const result = guard.sanitize(input);
    expect(result).toContain("[REDACTED]");
  });

  it("preserves non-matching content", () => {
    const guard = new InjectionGuard();
    const input = 'Some normal text with api mentions and short tokens like abc';
    expect(guard.sanitize(input)).toBe(input);
  });

  it("handles multiple patterns in one string", () => {
    const guard = new InjectionGuard();
    const input = 'Bearer eyJhbGciOiJIUzI1NiJ9.x.y and api_key=sk_1234567890abcdef';
    const result = guard.sanitize(input);
    expect(result).toContain("[REDACTED]");
    expect(result).not.toContain("eyJhbG");
    expect(result).not.toContain("sk_1234567890abcdef");
    expect(guard.totalRedactions).toBe(2);
  });

  it("accumulates redaction count across calls", () => {
    const guard = new InjectionGuard();
    guard.sanitize("Bearer eyJhbGciOiJIUzI1NiJ9.x.y");
    guard.sanitize("Basic dXNlcjpwYXNzd29yZA==");
    expect(guard.totalRedactions).toBe(2);
  });
});
