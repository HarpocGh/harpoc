import { describe, it, expect, vi } from "vitest";
import { Hono } from "hono";
import { VaultState, VAULT_VERSION } from "@harpoc/shared";
import { createHealthRoutes } from "./health.js";
import type { HarpocEnv } from "../types.js";

function createTestApp(state: string, secrets: Array<{ expiresAt: number | null; status: string }> = []) {
  const engine = {
    getState: vi.fn().mockReturnValue(state),
    listSecrets: vi.fn().mockReturnValue(
      secrets.map((s, i) => ({
        handle: `secret://key${i}`,
        name: `key${i}`,
        type: "api_key",
        project: null,
        status: s.status,
        version: 1,
        createdAt: Date.now(),
        updatedAt: Date.now(),
        expiresAt: s.expiresAt,
        rotatedAt: null,
      })),
    ),
  };

  const app = new Hono<HarpocEnv>();
  app.use("*", async (c, next) => {
    c.set("engine", engine as never);
    await next();
  });
  app.route("/api/v1/health", createHealthRoutes());

  return { app, engine };
}

describe("health routes", () => {
  it("GET /api/v1/health returns state and version", async () => {
    const { app } = createTestApp(VaultState.UNLOCKED);

    const res = await app.request("/api/v1/health");
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.data.state).toBe("unlocked");
    expect(body.data.version).toBe(VAULT_VERSION);
  });

  it("GET /api/v1/health returns sealed state", async () => {
    const { app } = createTestApp(VaultState.SEALED);

    const res = await app.request("/api/v1/health");
    const body = await res.json();
    expect(body.data.state).toBe("sealed");
  });

  it("GET /api/v1/health/expiring returns empty when sealed", async () => {
    const { app } = createTestApp(VaultState.SEALED);

    const res = await app.request("/api/v1/health/expiring");
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.data).toEqual([]);
  });

  it("GET /api/v1/health/expiring returns secrets expiring within default 7 days", async () => {
    const now = Date.now();
    const threeDays = now + 3 * 24 * 60 * 60 * 1000;
    const tenDays = now + 10 * 24 * 60 * 60 * 1000;

    const { app } = createTestApp(VaultState.UNLOCKED, [
      { expiresAt: threeDays, status: "active" },
      { expiresAt: tenDays, status: "active" },
      { expiresAt: null, status: "active" },
    ]);

    const res = await app.request("/api/v1/health/expiring");
    const body = await res.json();
    expect(body.data).toHaveLength(1);
    expect(body.data[0].name).toBe("key0");
  });

  it("GET /api/v1/health/expiring respects custom days param", async () => {
    const now = Date.now();
    const threeDays = now + 3 * 24 * 60 * 60 * 1000;

    const { app } = createTestApp(VaultState.UNLOCKED, [
      { expiresAt: threeDays, status: "active" },
    ]);

    const res = await app.request("/api/v1/health/expiring?days=1");
    const body = await res.json();
    expect(body.data).toHaveLength(0);

    const res2 = await app.request("/api/v1/health/expiring?days=30");
    const body2 = await res2.json();
    expect(body2.data).toHaveLength(1);
  });

  it("GET /api/v1/health/expiring excludes non-active secrets", async () => {
    const now = Date.now();
    const threeDays = now + 3 * 24 * 60 * 60 * 1000;

    const { app } = createTestApp(VaultState.UNLOCKED, [
      { expiresAt: threeDays, status: "revoked" },
    ]);

    const res = await app.request("/api/v1/health/expiring");
    const body = await res.json();
    expect(body.data).toHaveLength(0);
  });
});
