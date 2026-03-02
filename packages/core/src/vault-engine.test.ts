import { createServer } from "node:http";
import type { Server } from "node:http";
import { mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { AuditEventType, ErrorCode, VaultError, VaultState } from "@harpoc/shared";
import { VaultEngine } from "./vault-engine.js";

let tempDir: string;
let dbPath: string;
let sessionPath: string;
let engine: VaultEngine;

// Test HTTP server
let server: Server;
let baseUrl: string;

beforeAll(async () => {
  server = createServer((req, res) => {
    const auth = req.headers["authorization"] ?? "none";
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ authorization: auth, path: req.url }));
  });

  await new Promise<void>((resolve) => {
    server.listen(0, "127.0.0.1", () => resolve());
  });
  const addr = server.address() as { port: number };
  baseUrl = `http://127.0.0.1:${addr.port}`;
});

afterAll(() => {
  server.close();
});

beforeEach(() => {
  tempDir = join(tmpdir(), `harpoc-ve-${Date.now()}-${Math.random().toString(36).slice(2)}`);
  mkdirSync(tempDir, { recursive: true });
  dbPath = join(tempDir, "test.vault.db");
  sessionPath = join(tempDir, "session.json");
  engine = new VaultEngine({ dbPath, sessionPath });
});

afterEach(async () => {
  await engine.destroy();
  try {
    rmSync(tempDir, { recursive: true, force: true });
  } catch {
    // Ignore
  }
});

describe("lifecycle", () => {
  it("starts sealed", () => {
    expect(engine.getState()).toBe(VaultState.SEALED);
  });

  it("initializes and unlocks a new vault", async () => {
    const { vaultId } = await engine.initVault("password");
    expect(vaultId).toBeTruthy();
    expect(engine.getState()).toBe(VaultState.UNLOCKED);
  });

  it("locks and seals", async () => {
    await engine.initVault("password");
    await engine.lock();
    expect(engine.getState()).toBe(VaultState.SEALED);
  });

  it("unlocks an existing vault", async () => {
    await engine.initVault("my-pass");
    await engine.lock();

    const engine2 = new VaultEngine({ dbPath, sessionPath });
    await engine2.unlock("my-pass");
    expect(engine2.getState()).toBe(VaultState.UNLOCKED);
    await engine2.destroy();
  });

  it("rejects wrong password on unlock", async () => {
    await engine.initVault("correct");
    await engine.lock();

    const engine2 = new VaultEngine({ dbPath, sessionPath });
    await expect(engine2.unlock("wrong")).rejects.toThrow(VaultError);

    try {
      await engine2.unlock("wrong");
    } catch (e) {
      expect((e as VaultError).code).toBe(ErrorCode.INVALID_PASSWORD);
    }
    await engine2.destroy();
  });

  it("rejects operations when sealed", async () => {
    expect(() => engine.listSecrets()).toThrow(VaultError);

    try {
      engine.listSecrets();
    } catch (e) {
      expect((e as VaultError).code).toBe(ErrorCode.VAULT_LOCKED);
    }
  });

  it("loadSession closes store on vault_id mismatch (no handle leak)", async () => {
    await engine.initVault("password");
    // destroy preserves session file, unlike lock which erases it
    await engine.destroy();

    // Tamper session file vault_id
    const raw = readFileSync(sessionPath, "utf-8");
    const session = JSON.parse(raw);
    session.vault_id = "tampered-vault-id";
    writeFileSync(sessionPath, JSON.stringify(session));

    const engine2 = new VaultEngine({ dbPath, sessionPath });
    const result = await engine2.loadSession();
    expect(result).toBe(false);
    expect(engine2.getState()).toBe(VaultState.SEALED);
    // engine2 should not have a store to close — no leaked handle
    await engine2.destroy();
  });
});

describe("secrets", () => {
  beforeEach(async () => {
    await engine.initVault("password");
  });

  it("creates and lists secrets", () => {
    engine.createSecret({
      name: "test-key",
      type: "api_key",
      value: new Uint8Array(Buffer.from("secret-value")),
    });

    const list = engine.listSecrets();
    expect(list.length).toBe(1);
    expect(list[0]?.name).toBe("test-key");
  });

  it("creates and retrieves secret info", () => {
    engine.createSecret({
      name: "info-key",
      type: "api_key",
      value: new Uint8Array(Buffer.from("val")),
    });

    const info = engine.getSecretInfo("secret://info-key");
    expect(info.name).toBe("info-key");
    expect(info.status).toBe("active");
  });

  it("creates and retrieves secret value", () => {
    engine.createSecret({
      name: "get-val",
      type: "api_key",
      value: new Uint8Array(Buffer.from("the-secret")),
    });

    const value = engine.getSecretValue("secret://get-val");
    expect(Buffer.from(value).toString()).toBe("the-secret");
  });

  it("handles pending → set value flow", () => {
    engine.createSecret({ name: "pending", type: "api_key" });
    engine.setSecretValue("secret://pending", new Uint8Array(Buffer.from("now-set")));

    const info = engine.getSecretInfo("secret://pending");
    expect(info.status).toBe("active");
  });

  it("rotates a secret", () => {
    engine.createSecret({
      name: "rotate-me",
      type: "api_key",
      value: new Uint8Array(Buffer.from("old")),
    });

    engine.rotateSecret("secret://rotate-me", new Uint8Array(Buffer.from("new")));

    const info = engine.getSecretInfo("secret://rotate-me");
    expect(info.version).toBe(2);

    const value = engine.getSecretValue("secret://rotate-me");
    expect(Buffer.from(value).toString()).toBe("new");
  });

  it("revokes a secret", () => {
    engine.createSecret({
      name: "rev",
      type: "api_key",
      value: new Uint8Array(Buffer.from("v")),
    });

    engine.revokeSecret("secret://rev");

    const info = engine.getSecretInfo("secret://rev");
    expect(info.status).toBe("revoked");
  });
});

describe("error propagation through VaultEngine", () => {
  beforeEach(async () => {
    await engine.initVault("password");
  });

  it("getSecretInfo throws SECRET_NOT_FOUND for non-existent handle", () => {
    try {
      engine.getSecretInfo("secret://nonexistent");
      expect.fail("Should throw");
    } catch (e) {
      expect((e as VaultError).code).toBe(ErrorCode.SECRET_NOT_FOUND);
    }
  });

  it("getSecretValue throws SECRET_NOT_FOUND for non-existent handle", () => {
    try {
      engine.getSecretValue("secret://nonexistent");
      expect.fail("Should throw");
    } catch (e) {
      expect((e as VaultError).code).toBe(ErrorCode.SECRET_NOT_FOUND);
    }
  });

  it("getSecretInfo throws INVALID_HANDLE for malformed handle", () => {
    try {
      engine.getSecretInfo("not-a-handle");
      expect.fail("Should throw");
    } catch (e) {
      expect((e as VaultError).code).toBe(ErrorCode.INVALID_HANDLE);
    }
  });

  it("getSecretValue throws SECRET_REVOKED for revoked secret", () => {
    engine.createSecret({
      name: "rev",
      type: "api_key",
      value: new Uint8Array(Buffer.from("v")),
    });
    engine.revokeSecret("secret://rev");

    try {
      engine.getSecretValue("secret://rev");
      expect.fail("Should throw");
    } catch (e) {
      expect((e as VaultError).code).toBe(ErrorCode.SECRET_REVOKED);
    }
  });

  it("getSecretValue throws SECRET_VALUE_REQUIRED for pending secret", () => {
    engine.createSecret({ name: "pend", type: "api_key" });

    try {
      engine.getSecretValue("secret://pend");
      expect.fail("Should throw");
    } catch (e) {
      expect((e as VaultError).code).toBe(ErrorCode.SECRET_VALUE_REQUIRED);
    }
  });

  it("createSecret throws DUPLICATE_SECRET for duplicate name", () => {
    engine.createSecret({
      name: "dup",
      type: "api_key",
      value: new Uint8Array(Buffer.from("v")),
    });

    try {
      engine.createSecret({
        name: "dup",
        type: "api_key",
        value: new Uint8Array(Buffer.from("v2")),
      });
      expect.fail("Should throw");
    } catch (e) {
      expect((e as VaultError).code).toBe(ErrorCode.DUPLICATE_SECRET);
    }
  });

  it("rotateSecret throws SECRET_REVOKED for revoked secret", () => {
    engine.createSecret({
      name: "rot-rev",
      type: "api_key",
      value: new Uint8Array(Buffer.from("v")),
    });
    engine.revokeSecret("secret://rot-rev");

    try {
      engine.rotateSecret("secret://rot-rev", new Uint8Array(Buffer.from("new")));
      expect.fail("Should throw");
    } catch (e) {
      expect((e as VaultError).code).toBe(ErrorCode.SECRET_REVOKED);
    }
  });

  it("useSecret throws SECRET_NOT_FOUND for non-existent handle", async () => {
    try {
      await engine.useSecret(
        "secret://nonexistent",
        { method: "GET", url: `${baseUrl}/test` },
        { type: "bearer" },
      );
      expect.fail("Should throw");
    } catch (e) {
      expect((e as VaultError).code).toBe(ErrorCode.SECRET_NOT_FOUND);
    }
  });

  it("useSecret throws SECRET_REVOKED for revoked secret", async () => {
    engine.createSecret({
      name: "use-rev",
      type: "api_key",
      value: new Uint8Array(Buffer.from("v")),
    });
    engine.revokeSecret("secret://use-rev");

    try {
      await engine.useSecret(
        "secret://use-rev",
        { method: "GET", url: `${baseUrl}/test` },
        { type: "bearer" },
      );
      expect.fail("Should throw");
    } catch (e) {
      expect((e as VaultError).code).toBe(ErrorCode.SECRET_REVOKED);
    }
  });

  it("useSecret throws URL_INVALID for invalid URL", async () => {
    engine.createSecret({
      name: "url-test",
      type: "api_key",
      value: new Uint8Array(Buffer.from("v")),
    });

    try {
      await engine.useSecret(
        "secret://url-test",
        { method: "GET", url: "not-a-url" },
        { type: "bearer" },
      );
      expect.fail("Should throw");
    } catch (e) {
      expect((e as VaultError).code).toBe(ErrorCode.URL_INVALID);
    }
  });

  it("useSecret throws SSRF_BLOCKED for private IP", async () => {
    engine.createSecret({
      name: "ssrf-test",
      type: "api_key",
      value: new Uint8Array(Buffer.from("v")),
    });

    try {
      await engine.useSecret(
        "secret://ssrf-test",
        { method: "GET", url: "https://10.0.0.1/api" },
        { type: "bearer" },
      );
      expect.fail("Should throw");
    } catch (e) {
      expect((e as VaultError).code).toBe(ErrorCode.SSRF_BLOCKED);
    }
  });
});

describe("useSecret (HTTP injection)", () => {
  beforeEach(async () => {
    await engine.initVault("password");
  });

  it("injects bearer token and returns response", async () => {
    engine.createSecret({
      name: "api-token",
      type: "api_key",
      value: new Uint8Array(Buffer.from("my-bearer-token")),
    });

    const response = await engine.useSecret(
      "secret://api-token",
      { method: "GET", url: `${baseUrl}/test` },
      { type: "bearer" },
    );

    expect(response.status).toBe(200);
    const body = JSON.parse(response.body ?? "{}") as Record<string, string>;
    expect(body.authorization).toBe("Bearer my-bearer-token");
  });
});

describe("policies", () => {
  beforeEach(async () => {
    await engine.initVault("password");
    engine.createSecret({
      name: "policy-test",
      type: "api_key",
      value: new Uint8Array(Buffer.from("v")),
    });
  });

  it("grants and lists policies", () => {
    // resolveHandle doesn't return the id, but we can use the internal secret
    // For testing, we grant by resolving the handle internally
    const secretId = (engine as unknown as { secretManager: { resolveHandle: (h: string) => { id: string } } })
      .secretManager.resolveHandle("secret://policy-test").id;

    const policy = engine.grantPolicy(
      {
        secretId,
        principalType: "agent",
        principalId: "agent-1",
        permissions: ["read", "use"],
      },
      "admin",
    );

    expect(policy.id).toBeTruthy();

    const policies = engine.listPolicies(secretId);
    expect(policies.length).toBe(1);
  });

  it("revokes a policy", () => {
    const secretId = (engine as unknown as { secretManager: { resolveHandle: (h: string) => { id: string } } })
      .secretManager.resolveHandle("secret://policy-test").id;

    const policy = engine.grantPolicy(
      {
        secretId,
        principalType: "agent",
        principalId: "agent-1",
        permissions: ["read"],
      },
      "admin",
    );

    engine.revokePolicy(policy.id);
    expect(engine.listPolicies(secretId).length).toBe(0);
  });
});

describe("JWT tokens", () => {
  beforeEach(async () => {
    await engine.initVault("password");
  });

  it("creates and verifies a token", () => {
    const token = engine.createToken("user-1", ["read", "use"]);
    const decoded = engine.verifyToken(token);

    expect(decoded.sub).toBe("user-1");
    expect(decoded.scope).toEqual(["read", "use"]);
  });

  it("rejects invalid token", () => {
    expect(() => engine.verifyToken("bad.token.here")).toThrow(VaultError);
  });

  it("revokes a token", () => {
    const token = engine.createToken("user-1", ["read"]);
    const decoded = engine.verifyToken(token);

    engine.revokeToken(decoded.jti);

    expect(() => engine.verifyToken(token)).toThrow("revoked");
  });

  it("revoked token persists across engine restart", async () => {
    const token = engine.createToken("user-1", ["read"]);
    const decoded = engine.verifyToken(token);
    engine.revokeToken(decoded.jti);
    await engine.lock();

    // Re-open engine, same DB
    const engine2 = new VaultEngine({ dbPath, sessionPath });
    await engine2.unlock("password");

    expect(() => engine2.verifyToken(token)).toThrow("revoked");
    await engine2.destroy();
  });

  it("rejects token from different vault (vault_id mismatch)", async () => {
    const token = engine.createToken("user-1", ["read"]);
    await engine.destroy();

    // Create a second vault
    const tempDir2 = join(tempDir, "vault2");
    mkdirSync(tempDir2, { recursive: true });
    const engine2 = new VaultEngine({
      dbPath: join(tempDir2, "test.vault.db"),
      sessionPath: join(tempDir2, "session.json"),
    });
    await engine2.initVault("password");

    try {
      engine2.verifyToken(token);
      expect.fail("Should throw");
    } catch (e) {
      expect((e as VaultError).code).toBe(ErrorCode.INVALID_TOKEN);
    }
    await engine2.destroy();
  });

  it("rejects expired token", () => {
    // Create token with 0 TTL (immediately expired)
    const token = engine.createToken("user-1", ["read"], 0);

    try {
      engine.verifyToken(token);
      expect.fail("Should throw");
    } catch (e) {
      expect((e as VaultError).code).toBe(ErrorCode.TOKEN_EXPIRED);
    }
  });
});

describe("JWT edge cases", () => {
  beforeEach(async () => {
    await engine.initVault("password");
  });

  it("rejects token with tampered signature", () => {
    const token = engine.createToken("user-1", ["read"]);
    const parts = token.split(".");
    // Flip last character of signature
    const sig = parts[2] as string;
    const tampered = `${parts[0]}.${parts[1]}.${sig.slice(0, -1)}${sig.endsWith("A") ? "B" : "A"}`;

    try {
      engine.verifyToken(tampered);
      expect.fail("Should throw");
    } catch (e) {
      expect((e as VaultError).code).toBe(ErrorCode.INVALID_TOKEN);
    }
  });

  it("rejects token with tampered payload", () => {
    const token = engine.createToken("user-1", ["read"]);
    const parts = token.split(".");
    // Replace payload with a different one
    const fakePayload = Buffer.from(JSON.stringify({ sub: "hacker" })).toString("base64url");
    const tampered = `${parts[0]}.${fakePayload}.${parts[2]}`;

    try {
      engine.verifyToken(tampered);
      expect.fail("Should throw");
    } catch (e) {
      expect((e as VaultError).code).toBe(ErrorCode.INVALID_TOKEN);
    }
  });

  it("rejects 2-part token", () => {
    try {
      engine.verifyToken("header.body");
      expect.fail("Should throw");
    } catch (e) {
      expect((e as VaultError).code).toBe(ErrorCode.INVALID_TOKEN);
    }
  });

  it("rejects 4-part token", () => {
    try {
      engine.verifyToken("a.b.c.d");
      expect.fail("Should throw");
    } catch (e) {
      expect((e as VaultError).code).toBe(ErrorCode.INVALID_TOKEN);
    }
  });

  it("rejects empty-segment token", () => {
    try {
      engine.verifyToken("..");
      expect.fail("Should throw");
    } catch (e) {
      expect((e as VaultError).code).toBe(ErrorCode.INVALID_TOKEN);
    }
  });
});

describe("audit trail", () => {
  beforeEach(async () => {
    await engine.initVault("password");
  });

  it("logs vault unlock event", () => {
    const events = engine.queryAudit({ eventType: AuditEventType.VAULT_UNLOCK });
    expect(events.length).toBeGreaterThanOrEqual(1);
  });

  it("logs secret creation", () => {
    engine.createSecret({
      name: "audit-test",
      type: "api_key",
      value: new Uint8Array(Buffer.from("v")),
    });

    const events = engine.queryAudit({ eventType: AuditEventType.SECRET_CREATE });
    expect(events.length).toBe(1);
    expect(events[0]?.detail?.handle).toBe("secret://audit-test");
  });

  it("logs getSecretValue with action: get_value", () => {
    engine.createSecret({
      name: "audit-getval",
      type: "api_key",
      value: new Uint8Array(Buffer.from("v")),
    });

    engine.getSecretValue("secret://audit-getval");

    const events = engine.queryAudit({ eventType: AuditEventType.SECRET_READ });
    const getValEvents = events.filter((e) => e.detail?.action === "get_value");
    expect(getValEvents.length).toBe(1);
    expect(getValEvents[0]?.detail?.handle).toBe("secret://audit-getval");
  });
});

describe("audit trail for failed useSecret", () => {
  beforeEach(async () => {
    await engine.initVault("password");
    engine.createSecret({
      name: "audit-use",
      type: "api_key",
      value: new Uint8Array(Buffer.from("val")),
    });
  });

  it("logs DNS failure with success=false", async () => {
    await engine.useSecret(
      "secret://audit-use",
      { method: "GET", url: "https://this-host-does-not-exist-xyz123.invalid/api" },
      { type: "bearer" },
    );

    const events = engine.queryAudit({ eventType: AuditEventType.SECRET_USE });
    expect(events.length).toBeGreaterThanOrEqual(1);
    const last = events[0];
    expect(last?.detail?.error).toBe("DNS_RESOLUTION_FAILED");
  });

  it("logs successful request with success=true", async () => {
    await engine.useSecret(
      "secret://audit-use",
      { method: "GET", url: `${baseUrl}/test` },
      { type: "bearer" },
    );

    const events = engine.queryAudit({ eventType: AuditEventType.SECRET_USE });
    expect(events.length).toBeGreaterThanOrEqual(1);
    const last = events[0];
    expect(last?.detail?.method).toBe("GET");
    expect(last?.detail?.status).toBe(200);
  });

  it("logs connection refused with success=false", async () => {
    await engine.useSecret(
      "secret://audit-use",
      { method: "GET", url: "http://127.0.0.1:2/api", timeoutMs: 5000 },
      { type: "bearer" },
    );

    const events = engine.queryAudit({ eventType: AuditEventType.SECRET_USE });
    expect(events.length).toBeGreaterThanOrEqual(1);
    const last = events[0];
    expect(last?.detail?.error).toBeDefined();
  });
});

describe("session loading", () => {
  it("loads session after restart", async () => {
    await engine.initVault("password");
    engine.createSecret({
      name: "persist",
      type: "api_key",
      value: new Uint8Array(Buffer.from("val")),
    });

    // Simulate restart — destroy engine, create new one
    await engine.destroy();

    const engine2 = new VaultEngine({ dbPath, sessionPath });
    const loaded = await engine2.loadSession();
    expect(loaded).toBe(true);
    expect(engine2.getState()).toBe(VaultState.UNLOCKED);

    const list = engine2.listSecrets();
    expect(list.length).toBe(1);

    await engine2.destroy();
  });

  it("session restore preserves audit log decryptability", async () => {
    await engine.initVault("password");
    engine.createSecret({
      name: "audit-persist",
      type: "api_key",
      value: new Uint8Array(Buffer.from("val")),
    });

    // Verify audit entries exist before restart
    const beforeEvents = engine.queryAudit({ eventType: AuditEventType.SECRET_CREATE });
    expect(beforeEvents.length).toBe(1);
    expect(beforeEvents[0]?.detail?.handle).toBe("secret://audit-persist");

    // Simulate restart
    await engine.destroy();

    const engine2 = new VaultEngine({ dbPath, sessionPath });
    const loaded = await engine2.loadSession();
    expect(loaded).toBe(true);

    // After session restore, audit entries should still be decryptable
    const afterEvents = engine2.queryAudit({ eventType: AuditEventType.SECRET_CREATE });
    expect(afterEvents.length).toBe(1);
    expect(afterEvents[0]?.detail?.handle).toBe("secret://audit-persist");

    // Create a new audit entry to verify audit key works for new writes too
    engine2.createSecret({
      name: "post-restart",
      type: "api_key",
      value: new Uint8Array(Buffer.from("val2")),
    });
    const newEvents = engine2.queryAudit({ eventType: AuditEventType.SECRET_CREATE });
    expect(newEvents.length).toBe(2);

    await engine2.destroy();
  });
});

describe("destroy() correctness", () => {
  it("sets state to SEALED after destroy", async () => {
    await engine.initVault("password");
    expect(engine.getState()).toBe(VaultState.UNLOCKED);

    await engine.destroy();
    expect(engine.getState()).toBe(VaultState.SEALED);
  });

  it("rejects listSecrets after destroy", async () => {
    await engine.initVault("password");
    await engine.destroy();

    try {
      engine.listSecrets();
      expect.fail("Should throw");
    } catch (e) {
      expect((e as VaultError).code).toBe(ErrorCode.VAULT_LOCKED);
    }
  });

  it("rejects createSecret after destroy", async () => {
    await engine.initVault("password");
    await engine.destroy();

    try {
      engine.createSecret({
        name: "fail",
        type: "api_key",
        value: new Uint8Array(Buffer.from("v")),
      });
      expect.fail("Should throw");
    } catch (e) {
      expect((e as VaultError).code).toBe(ErrorCode.VAULT_LOCKED);
    }
  });
});

describe("password change", () => {
  it("changes password and re-unlocks with new password", async () => {
    await engine.initVault("old-pass");
    engine.createSecret({
      name: "keep",
      type: "api_key",
      value: new Uint8Array(Buffer.from("secret-val")),
    });

    await engine.changePassword("old-pass", "new-pass");
    await engine.lock();

    const engine2 = new VaultEngine({ dbPath, sessionPath });
    await engine2.unlock("new-pass");

    const value = engine2.getSecretValue("secret://keep");
    expect(Buffer.from(value).toString()).toBe("secret-val");

    await engine2.destroy();
  });
});
