import { Hono } from "hono";
import type { AuditEventType, Permission, VaultApiToken } from "@harpoc/shared";
import { VaultError } from "@harpoc/shared";
import type { HarpocEnv } from "../types.js";

function requireScope(token: VaultApiToken, permission: Permission): void {
  if (!token.scope.includes(permission) && !token.scope.includes("admin")) {
    throw VaultError.accessDenied(`Token lacks permission: ${permission}`);
  }
}

export function createAuditRoutes(): Hono<HarpocEnv> {
  const router = new Hono<HarpocEnv>();

  router.get("/", (c) => {
    const token = c.get("token");
    requireScope(token, "admin");

    const engine = c.get("engine");

    const secretId = c.req.query("secret_id");
    const eventType = c.req.query("event_type");
    const since = c.req.query("since");
    const until = c.req.query("until");
    const limit = c.req.query("limit");

    const events = engine.queryAudit({
      secretId: secretId ?? undefined,
      eventType: eventType ? (eventType as AuditEventType) : undefined,
      since: since ? parseInt(since, 10) : undefined,
      until: until ? parseInt(until, 10) : undefined,
      limit: limit ? parseInt(limit, 10) : undefined,
    });

    return c.json({ data: events });
  });

  return router;
}
