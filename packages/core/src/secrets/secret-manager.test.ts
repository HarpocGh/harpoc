import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { ErrorCode, VaultError } from "@harpoc/shared";
import { createVaultKeys } from "../crypto/key-hierarchy.js";
import { SqliteStore } from "../storage/sqlite-store.js";
import { SecretManager } from "./secret-manager.js";

let store: SqliteStore;
let manager: SecretManager;
let kek: Uint8Array;

beforeEach(async () => {
  store = new SqliteStore(":memory:");
  const keys = await createVaultKeys("test-password");
  kek = keys.kek;
  manager = new SecretManager(store, kek);
});

afterEach(() => {
  store.close();
});

describe("createSecret", () => {
  it("creates a secret with a value (status: created)", () => {
    const result = manager.createSecret({
      name: "github-token",
      type: "api_key",
      value: new Uint8Array(Buffer.from("ghp_123456")),
    });

    expect(result.handle).toBe("secret://github-token");
    expect(result.status).toBe("created");
  });

  it("creates a pending secret without a value", () => {
    const result = manager.createSecret({
      name: "my-key",
      type: "api_key",
    });

    expect(result.status).toBe("pending");
    expect(result.handle).toBe("secret://my-key");
  });

  it("creates a secret with a project", () => {
    const result = manager.createSecret({
      name: "token",
      type: "api_key",
      project: "my-project",
      value: new Uint8Array(Buffer.from("val")),
    });

    expect(result.handle).toBe("secret://my-project/token");
  });

  it("rejects duplicate name+project", () => {
    manager.createSecret({
      name: "dup",
      type: "api_key",
      value: new Uint8Array(Buffer.from("v1")),
    });

    expect(() =>
      manager.createSecret({
        name: "dup",
        type: "api_key",
        value: new Uint8Array(Buffer.from("v2")),
      }),
    ).toThrow(VaultError);
  });

  it("allows same name in different projects", () => {
    manager.createSecret({
      name: "token",
      type: "api_key",
      project: "proj-a",
      value: new Uint8Array(Buffer.from("v1")),
    });

    expect(() =>
      manager.createSecret({
        name: "token",
        type: "api_key",
        project: "proj-b",
        value: new Uint8Array(Buffer.from("v2")),
      }),
    ).not.toThrow();
  });
});

describe("setSecretValue", () => {
  it("transitions pending secret to active", () => {
    manager.createSecret({ name: "pending-key", type: "api_key" });

    manager.setSecretValue("secret://pending-key", new Uint8Array(Buffer.from("the-value")));

    const info = manager.getSecretInfo("secret://pending-key");
    expect(info.status).toBe("active");
  });

  it("rejects setting value on active secret", () => {
    manager.createSecret({
      name: "active-key",
      type: "api_key",
      value: new Uint8Array(Buffer.from("v")),
    });

    expect(() =>
      manager.setSecretValue("secret://active-key", new Uint8Array(Buffer.from("new"))),
    ).toThrow("not pending");
  });
});

describe("getSecretInfo", () => {
  it("returns metadata without the value", () => {
    manager.createSecret({
      name: "info-test",
      type: "api_key",
      value: new Uint8Array(Buffer.from("secret")),
    });

    const info = manager.getSecretInfo("secret://info-test");
    expect(info.name).toBe("info-test");
    expect(info.type).toBe("api_key");
    expect(info.status).toBe("active");
    expect(info.version).toBe(1);
    expect(info).not.toHaveProperty("ciphertext");
    expect(info).not.toHaveProperty("wrapped_dek");
  });
});

describe("getSecretValue", () => {
  it("decrypts and returns the secret value", () => {
    manager.createSecret({
      name: "decrypt-test",
      type: "api_key",
      value: new Uint8Array(Buffer.from("my-api-key-123")),
    });

    const value = manager.getSecretValue("secret://decrypt-test");
    expect(Buffer.from(value).toString()).toBe("my-api-key-123");
  });

  it("throws for revoked secret", () => {
    manager.createSecret({
      name: "revoked",
      type: "api_key",
      value: new Uint8Array(Buffer.from("v")),
    });
    manager.revokeSecret("secret://revoked");

    expect(() => manager.getSecretValue("secret://revoked")).toThrow(VaultError);
  });

  it("throws for pending secret", () => {
    manager.createSecret({ name: "pend", type: "api_key" });

    expect(() => manager.getSecretValue("secret://pend")).toThrow("no value set");
  });
});

describe("listSecrets", () => {
  it("lists all secrets", () => {
    manager.createSecret({
      name: "a",
      type: "api_key",
      value: new Uint8Array(Buffer.from("v")),
    });
    manager.createSecret({
      name: "b",
      type: "api_key",
      value: new Uint8Array(Buffer.from("v")),
    });

    const list = manager.listSecrets();
    expect(list.length).toBe(2);
  });

  it("filters by project", () => {
    manager.createSecret({
      name: "a",
      type: "api_key",
      project: "p1",
      value: new Uint8Array(Buffer.from("v")),
    });
    manager.createSecret({
      name: "b",
      type: "api_key",
      project: "p2",
      value: new Uint8Array(Buffer.from("v")),
    });

    const list = manager.listSecrets("p1");
    expect(list.length).toBe(1);
    expect(list[0]?.project).toBe("p1");
  });
});

describe("rotateSecret", () => {
  it("rotates with new DEK and increments version", () => {
    manager.createSecret({
      name: "rotate-me",
      type: "api_key",
      value: new Uint8Array(Buffer.from("old-value")),
    });

    manager.rotateSecret("secret://rotate-me", new Uint8Array(Buffer.from("new-value")));

    const info = manager.getSecretInfo("secret://rotate-me");
    expect(info.version).toBe(2);
    expect(info.rotatedAt).not.toBeNull();

    const value = manager.getSecretValue("secret://rotate-me");
    expect(Buffer.from(value).toString()).toBe("new-value");
  });

  it("throws for revoked secret", () => {
    manager.createSecret({
      name: "rev",
      type: "api_key",
      value: new Uint8Array(Buffer.from("v")),
    });
    manager.revokeSecret("secret://rev");

    expect(() =>
      manager.rotateSecret("secret://rev", new Uint8Array(Buffer.from("new"))),
    ).toThrow(VaultError);
  });
});

describe("revokeSecret", () => {
  it("sets status to revoked", () => {
    manager.createSecret({
      name: "revoke-me",
      type: "api_key",
      value: new Uint8Array(Buffer.from("v")),
    });

    manager.revokeSecret("secret://revoke-me");

    const info = manager.getSecretInfo("secret://revoke-me");
    expect(info.status).toBe("revoked");
  });

  it("throws when already revoked", () => {
    manager.createSecret({
      name: "already",
      type: "api_key",
      value: new Uint8Array(Buffer.from("v")),
    });
    manager.revokeSecret("secret://already");

    try {
      manager.revokeSecret("secret://already");
      expect.fail("Should throw");
    } catch (e) {
      expect((e as VaultError).code).toBe(ErrorCode.SECRET_REVOKED);
    }
  });
});

describe("resolveHandle", () => {
  it("resolves a simple handle", () => {
    manager.createSecret({
      name: "test",
      type: "api_key",
      value: new Uint8Array(Buffer.from("v")),
    });

    const secret = manager.resolveHandle("secret://test");
    expect(secret.id).toBeTruthy();
  });

  it("resolves a project-scoped handle", () => {
    manager.createSecret({
      name: "key",
      type: "api_key",
      project: "myproj",
      value: new Uint8Array(Buffer.from("v")),
    });

    const secret = manager.resolveHandle("secret://myproj/key");
    expect(secret.project).toBe("myproj");
  });

  it("throws SECRET_NOT_FOUND for nonexistent handle", () => {
    try {
      manager.resolveHandle("secret://nonexistent");
      expect.fail("Should throw");
    } catch (e) {
      expect((e as VaultError).code).toBe(ErrorCode.SECRET_NOT_FOUND);
    }
  });

  it("throws INVALID_HANDLE for malformed handle", () => {
    try {
      manager.resolveHandle("not-a-handle");
      expect.fail("Should throw");
    } catch (e) {
      expect((e as VaultError).code).toBe(ErrorCode.INVALID_HANDLE);
    }
  });
});
