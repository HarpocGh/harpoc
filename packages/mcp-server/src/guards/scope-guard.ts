import type { Permission, VaultApiToken } from "@harpoc/shared";
import { VaultError } from "@harpoc/shared";

/**
 * 3-dimensional launch-token scope enforcement:
 * 1. Permission — token's scope must include the required permission (or admin)
 * 2. Project — if token specifies a project, only that project's secrets are accessible
 * 3. Secrets — if token specifies secret names, only those secrets are accessible
 */
export class ScopeGuard {
  constructor(private readonly token: VaultApiToken | null) {}

  /**
   * Check whether the current token grants access for the given operation.
   * Returns the principal ID (token subject) for audit logging.
   * Throws VaultError(ACCESS_DENIED) if access is not permitted.
   */
  checkAccess(permission: Permission, project?: string, secretName?: string): string {
    // Null token = full access (no launch token provided)
    if (!this.token) return "local";

    // 1. Permission check
    if (!this.token.scope.includes(permission) && !this.token.scope.includes("admin")) {
      throw VaultError.accessDenied(`Token lacks permission: ${permission}`);
    }

    // 2. Project scope check
    if (this.token.project && project !== undefined && project !== this.token.project) {
      throw VaultError.accessDenied(`Token is scoped to project: ${this.token.project}`);
    }

    // 3. Secret name scope check
    if (this.token.secrets?.length && secretName !== undefined) {
      if (!this.token.secrets.includes(secretName)) {
        throw VaultError.accessDenied("Token does not grant access to this secret");
      }
    }

    return this.token.sub;
  }

  /** Get the principal ID without performing access checks. */
  get principal(): string {
    return this.token?.sub ?? "local";
  }
}
