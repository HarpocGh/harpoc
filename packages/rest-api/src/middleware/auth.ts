import type { MiddlewareHandler } from "hono";
import { ErrorCode, VaultError } from "@harpoc/shared";
import type { HarpocEnv } from "../types.js";

export const authMiddleware: MiddlewareHandler<HarpocEnv> = async (c, next) => {
  const header = c.req.header("authorization");
  if (!header) {
    throw new VaultError(ErrorCode.INVALID_TOKEN, "Missing Authorization header");
  }

  const match = /^Bearer\s+(\S+)$/i.exec(header);
  if (!match) {
    throw new VaultError(ErrorCode.INVALID_TOKEN, "Malformed Authorization header");
  }

  const token = match[1] as string;
  const engine = c.get("engine");
  const payload = engine.verifyToken(token);
  c.set("token", payload);

  await next();
};
