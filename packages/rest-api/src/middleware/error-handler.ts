import type { ErrorHandler } from "hono";
import { ErrorCode, VaultError } from "@harpoc/shared";
import type { HarpocEnv } from "../types.js";

export const errorHandler: ErrorHandler<HarpocEnv> = (err, c) => {
  if (err instanceof VaultError) {
    // VAULT_LOCKED → 503 in REST API (service unavailable)
    const status = err.code === ErrorCode.VAULT_LOCKED ? 503 : err.statusCode;
    return c.json({ error: err.code, message: err.message }, status as 400);
  }

  return c.json(
    { error: ErrorCode.INTERNAL_ERROR, message: "Internal server error" },
    500,
  );
};
