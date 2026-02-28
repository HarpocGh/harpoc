import { createServer } from "node:http";
import type { Server } from "node:http";
import { mkdirSync, rmSync } from "node:fs";
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
