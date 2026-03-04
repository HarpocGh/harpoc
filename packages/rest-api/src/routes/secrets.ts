import { Hono } from "hono";
import type { Permission, VaultApiToken } from "@harpoc/shared";
import { VaultError, ErrorCode } from "@harpoc/shared";
import type { HarpocEnv } from "../types.js";

function requireScope(token: VaultApiToken, permission: Permission): void {
  if (!token.scope.includes(permission) && !token.scope.includes("admin")) {
    throw VaultError.accessDenied(`Token lacks permission: ${permission}`);
  }
}

function buildHandle(handle: string): string {
  return `secret://${handle}`;
}

export function createSecretRoutes(): Hono<HarpocEnv> {
  const router = new Hono<HarpocEnv>();

  // List secrets
  router.get("/", (c) => {
    const token = c.get("token");
    requireScope(token, "list");

    const engine = c.get("engine");
    const project = c.req.query("project");
    const secrets = engine.listSecrets(project);

    return c.json({ data: secrets });
  });

  // Create secret
  router.post("/", async (c) => {
    const token = c.get("token");
    requireScope(token, "create");

    const engine = c.get("engine");
    const body = await c.req.json<{
      name: string;
      type: string;
      project?: string;
      value?: string;
      injection?: { type: string; header_name?: string; query_param?: string };
      expires_at?: number;
    }>();

    if (!body.name || !body.type) {
      throw VaultError.invalidInput("name and type are required");
    }

    const result = await engine.createSecret({
      name: body.name,
      type: body.type as "api_key" | "oauth_token" | "certificate",
      project: body.project,
      value: body.value ? new Uint8Array(Buffer.from(body.value, "base64")) : undefined,
      injection: body.injection as
        | { type: "header" | "query" | "basic_auth" | "bearer"; header_name?: string; query_param?: string }
        | undefined,
      expiresAt: body.expires_at,
    });

    return c.json({ data: result }, 201);
  });

  // Get secret info
  router.get("/:handle", async (c) => {
    const token = c.get("token");
    requireScope(token, "read");

    const engine = c.get("engine");
    const handle = buildHandle(c.req.param("handle"));
    const info = await engine.getSecretInfo(handle);

    return c.json({ data: info });
  });

  // Get secret value (base64-encoded)
  router.get("/:handle/value", async (c) => {
    const token = c.get("token");
    requireScope(token, "read");

    const engine = c.get("engine");
    const handle = buildHandle(c.req.param("handle"));
    const value = await engine.getSecretValue(handle);

    return c.json({ data: { value: Buffer.from(value).toString("base64") } });
  });

  // Revoke secret
  router.delete("/:handle", async (c) => {
    const token = c.get("token");
    requireScope(token, "revoke");

    const confirm = c.req.query("confirm");
    if (confirm !== "true") {
      throw VaultError.invalidInput("Query parameter confirm=true is required");
    }

    const engine = c.get("engine");
    const handle = buildHandle(c.req.param("handle"));
    await engine.revokeSecret(handle);

    return c.json({ data: { revoked: true } });
  });

  // Rotate secret
  router.post("/:handle/rotate", async (c) => {
    const token = c.get("token");
    requireScope(token, "rotate");

    const engine = c.get("engine");
    const body = await c.req.json<{ value: string }>();

    if (!body.value) {
      throw VaultError.invalidInput("value (base64) is required");
    }

    const handle = buildHandle(c.req.param("handle"));
    const newValue = new Uint8Array(Buffer.from(body.value, "base64"));
    await engine.rotateSecret(handle, newValue);

    return c.json({ data: { rotated: true } });
  });

  // Use secret (HTTP injection)
  router.post("/:handle/use", async (c) => {
    const token = c.get("token");
    requireScope(token, "use");

    const engine = c.get("engine");
    const body = await c.req.json<{
      request: {
        method: string;
        url: string;
        headers?: Record<string, string>;
        body?: string;
        timeout_ms?: number;
      };
      injection: { type: string; header_name?: string; query_param?: string };
      follow_redirects?: string;
    }>();

    if (!body.request || !body.injection) {
      throw new VaultError(ErrorCode.INVALID_INPUT, "request and injection are required");
    }

    const handle = buildHandle(c.req.param("handle"));
    const result = await engine.useSecret(
      handle,
      {
        method: body.request.method as "GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "HEAD",
        url: body.request.url,
        headers: body.request.headers,
        body: body.request.body,
        timeoutMs: body.request.timeout_ms,
      },
      body.injection as { type: "header" | "query" | "basic_auth" | "bearer"; header_name?: string; query_param?: string },
      body.follow_redirects as "same-origin" | "none" | "any" | undefined,
    );

    return c.json({ data: result });
  });

  return router;
}
