import { Hono } from "hono";
import type { Permission, PrincipalType, VaultApiToken } from "@harpoc/shared";
import { VaultError } from "@harpoc/shared";
import type { HarpocEnv } from "../types.js";

function requireScope(token: VaultApiToken, permission: Permission): void {
  if (!token.scope.includes(permission) && !token.scope.includes("admin")) {
    throw VaultError.accessDenied(`Token lacks permission: ${permission}`);
  }
}

function buildHandle(handle: string): string {
  return `secret://${handle}`;
}

export function createPolicyRoutes(): Hono<HarpocEnv> {
  const router = new Hono<HarpocEnv>();

  // List policies for a secret
  router.get("/:handle/policies", async (c) => {
    const token = c.get("token");
    requireScope(token, "read");

    const engine = c.get("engine");
    const handle = buildHandle(c.req.param("handle"));
    const secretId = await engine.resolveSecretId(handle);
    const policies = engine.listPolicies(secretId);

    return c.json({ data: policies });
  });

  // Grant a policy
  router.post("/:handle/policies", async (c) => {
    const token = c.get("token");
    requireScope(token, "admin");

    const engine = c.get("engine");
    const handle = buildHandle(c.req.param("handle"));
    const secretId = await engine.resolveSecretId(handle);

    const body = await c.req.json<{
      principal_type: string;
      principal_id: string;
      permissions: string[];
      expires_at?: number;
    }>();

    if (!body.principal_type || !body.principal_id || !body.permissions?.length) {
      throw VaultError.invalidInput(
        "principal_type, principal_id, and permissions are required",
      );
    }

    const policy = engine.grantPolicy(
      {
        secretId,
        principalType: body.principal_type as PrincipalType,
        principalId: body.principal_id,
        permissions: body.permissions as Permission[],
        expiresAt: body.expires_at,
      },
      token.sub,
    );

    return c.json({ data: policy }, 201);
  });

  // Revoke a policy
  router.delete("/:handle/policies/:policyId", (c) => {
    const token = c.get("token");
    requireScope(token, "admin");

    const engine = c.get("engine");
    const policyId = c.req.param("policyId");
    engine.revokePolicy(policyId);

    return c.json({ data: { revoked: true } });
  });

  return router;
}
