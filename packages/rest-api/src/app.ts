import { Hono } from "hono";
import type { VaultEngine } from "@harpoc/core";
import { errorHandler } from "./middleware/error-handler.js";
import { authMiddleware } from "./middleware/auth.js";
import { RateLimiter, createRateLimitMiddleware } from "./middleware/rate-limit.js";
import { auditMiddleware } from "./middleware/audit.js";
import { createHealthRoutes } from "./routes/health.js";
import { createSecretRoutes } from "./routes/secrets.js";
import { createPolicyRoutes } from "./routes/policies.js";
import { createAuditRoutes } from "./routes/audit.js";
import type { HarpocEnv } from "./types.js";

export function createApp(engine: VaultEngine): Hono<HarpocEnv> {
  const app = new Hono<HarpocEnv>();

  // Global error handler
  app.onError(errorHandler);

  // Inject engine into context for all routes
  app.use("*", async (c, next) => {
    c.set("engine", engine);
    await next();
  });

  // Health routes (no auth required)
  app.route("/api/v1/health", createHealthRoutes());

  // Rate limiter for all API routes
  const limiter = new RateLimiter();
  app.use("/api/v1/*", createRateLimitMiddleware(limiter));

  // Audit logging (runs after handler via await next())
  app.use("/api/v1/secrets", auditMiddleware);
  app.use("/api/v1/secrets/*", auditMiddleware);
  app.use("/api/v1/audit", auditMiddleware);

  // Auth middleware for protected routes
  app.use("/api/v1/secrets", authMiddleware);
  app.use("/api/v1/secrets/*", authMiddleware);
  app.use("/api/v1/audit", authMiddleware);

  // Routes
  app.route("/api/v1/secrets", createSecretRoutes());
  app.route("/api/v1/secrets", createPolicyRoutes());
  app.route("/api/v1/audit", createAuditRoutes());

  return app;
}
