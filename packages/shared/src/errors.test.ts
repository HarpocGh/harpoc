import { describe, expect, it } from "vitest";

import { ErrorCode, VaultError } from "./errors.js";

describe("VaultError", () => {
  it("is an instance of Error", () => {
    const err = new VaultError(ErrorCode.INTERNAL_ERROR, "test");
    expect(err).toBeInstanceOf(Error);
    expect(err).toBeInstanceOf(VaultError);
  });

  it("preserves code, message, and statusCode", () => {
    const err = new VaultError(ErrorCode.SECRET_NOT_FOUND, "gone");
    expect(err.code).toBe(ErrorCode.SECRET_NOT_FOUND);
    expect(err.message).toBe("gone");
    expect(err.statusCode).toBe(404);
    expect(err.name).toBe("VaultError");
  });

  it("preserves details", () => {
    const details = { key: "value" };
    const err = new VaultError(ErrorCode.INTERNAL_ERROR, "oops", details);
    expect(err.details).toEqual({ key: "value" });
  });

  it("has undefined details when not provided", () => {
    const err = new VaultError(ErrorCode.INTERNAL_ERROR, "oops");
    expect(err.details).toBeUndefined();
  });
});

describe("HTTP status mapping", () => {
  it.each([
    [ErrorCode.VAULT_LOCKED, 423],
    [ErrorCode.VAULT_NOT_FOUND, 404],
    [ErrorCode.VAULT_CORRUPTED, 500],
    [ErrorCode.INVALID_PASSWORD, 401],
    [ErrorCode.ACCESS_DENIED, 403],
    [ErrorCode.LOCKOUT_ACTIVE, 429],
    [ErrorCode.SECRET_NOT_FOUND, 404],
    [ErrorCode.AMBIGUOUS_HANDLE, 409],
    [ErrorCode.DUPLICATE_SECRET, 409],
    [ErrorCode.SECRET_EXPIRED, 410],
    [ErrorCode.URL_INVALID, 400],
    [ErrorCode.SSRF_BLOCKED, 403],
    [ErrorCode.TLS_ERROR, 502],
    [ErrorCode.TIMEOUT, 504],
    [ErrorCode.INVALID_INPUT, 400],
    [ErrorCode.POLICY_NOT_FOUND, 404],
    [ErrorCode.DATABASE_ERROR, 500],
    [ErrorCode.ENCRYPTION_ERROR, 500],
  ] as const)("%s → %d", (code, expected) => {
    const err = new VaultError(code, "test");
    expect(err.statusCode).toBe(expected);
  });
});

describe("factory methods", () => {
  it("vaultLocked()", () => {
    const err = VaultError.vaultLocked();
    expect(err.code).toBe(ErrorCode.VAULT_LOCKED);
    expect(err.statusCode).toBe(423);
  });

  it("secretNotFound() without handle", () => {
    const err = VaultError.secretNotFound();
    expect(err.code).toBe(ErrorCode.SECRET_NOT_FOUND);
    expect(err.message).toBe("Secret not found");
  });

  it("secretNotFound() with handle", () => {
    const err = VaultError.secretNotFound("secret://my-key");
    expect(err.message).toBe("Secret not found: secret://my-key");
  });

  it("accessDenied() with detail", () => {
    const err = VaultError.accessDenied("no use permission");
    expect(err.code).toBe(ErrorCode.ACCESS_DENIED);
    expect(err.statusCode).toBe(403);
    expect(err.message).toBe("Access denied: no use permission");
  });

  it("invalidInput()", () => {
    const err = VaultError.invalidInput("bad data");
    expect(err.code).toBe(ErrorCode.INVALID_INPUT);
    expect(err.statusCode).toBe(400);
  });

  it("invalidHandle()", () => {
    const err = VaultError.invalidHandle("nope");
    expect(err.code).toBe(ErrorCode.INVALID_HANDLE);
    expect(err.message).toBe("Invalid handle: nope");
  });

  it("lockoutActive() includes retry_after_ms", () => {
    const err = VaultError.lockoutActive(30_000);
    expect(err.code).toBe(ErrorCode.LOCKOUT_ACTIVE);
    expect(err.details).toEqual({ retry_after_ms: 30_000 });
  });

  it("duplicateSecret()", () => {
    const err = VaultError.duplicateSecret("my-key");
    expect(err.code).toBe(ErrorCode.DUPLICATE_SECRET);
    expect(err.statusCode).toBe(409);
  });
});
