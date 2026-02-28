import { createHmac, timingSafeEqual } from "node:crypto";
import type {
  AccessPolicy,
  CreateSecretResponse,
  FollowRedirects,
  HttpMethod,
  InjectionConfig,
  Permission,
  SecretType,
  UseSecretResponse,
  VaultApiToken,
} from "@harpoc/shared";
import {
  AAD_SESSION_JWT,
  AAD_SESSION_KEK,
  AES_KEY_LENGTH,
  AuditEventType,
  ErrorCode,
  LOCKOUT_DURATIONS_MS,
  LOCKOUT_MAX_ATTEMPTS,
  SESSION_CLEANUP_INTERVAL_MS,
  VaultError,
  VaultState,
  VAULT_VERSION,
} from "@harpoc/shared";
import { PolicyEngine } from "./access/policy-engine.js";
import type { GrantPolicyInput } from "./access/policy-engine.js";
import { AuditLogger } from "./audit/audit-logger.js";
import { AuditQuery } from "./audit/audit-query.js";
import type { AuditQueryOptions, DecryptedAuditEvent } from "./audit/audit-query.js";
import { decrypt, encrypt } from "./crypto/aes-gcm.js";
import {
  changePassword,
  createVaultKeys,
  unlockVault,
} from "./crypto/key-hierarchy.js";
import { generateRandomBytes, generateUUIDv7, wipeBuffer } from "./crypto/random.js";
import { deriveSubkey } from "./crypto/hkdf.js";
import { HttpInjector } from "./injection/http-injector.js";
import type { SecretInfo } from "./secrets/secret-manager.js";
import { SecretManager } from "./secrets/secret-manager.js";
import { SessionManager } from "./session/session-manager.js";
import { SqliteStore } from "./storage/sqlite-store.js";

export interface VaultEngineOptions {
  dbPath: string;
  sessionPath: string;
}

interface UnlockedState {
  store: SqliteStore;
  kek: Uint8Array;
  jwtKey: Uint8Array;
  auditKey: Uint8Array;
  vaultId: string;
  secretManager: SecretManager;
  policyEngine: PolicyEngine;
  auditLogger: AuditLogger;
  auditQuery: AuditQuery;
  httpInjector: HttpInjector;
}

/**
 * Central orchestrator for the vault. Manages lifecycle, secrets, policies, audit, and JWT auth.
 */
export class VaultEngine {
  private state: VaultState = VaultState.SEALED;
  private store: SqliteStore | null = null;
  private kek: Uint8Array | null = null;
  private jwtKey: Uint8Array | null = null;
  private auditKey: Uint8Array | null = null;
  private vaultId: string | null = null;
  private sessionId: string | null = null;

  private secretManager: SecretManager | null = null;
  private policyEngine: PolicyEngine | null = null;
  private auditLogger: AuditLogger | null = null;
  private auditQuery: AuditQuery | null = null;
  private httpInjector: HttpInjector | null = null;
  private sessionManager: SessionManager;
  private sessionMonitorInterval: ReturnType<typeof setInterval> | null = null;

  private revokedTokens = new Set<string>();

  constructor(private readonly options: VaultEngineOptions) {
    this.sessionManager = new SessionManager(options.sessionPath);
  }

  // ---------------------------------------------------------------------------
  // Lifecycle
  // ---------------------------------------------------------------------------

  /**
   * Initialize a new vault: generate keys, create database, write session.
   */
  async initVault(password: string): Promise<{ vaultId: string }> {
    const keys = await createVaultKeys(password);

    const store = new SqliteStore(this.options.dbPath);
    store.setMeta("vault_id", keys.vaultId);
    store.setMeta("vault_version", VAULT_VERSION);

    // Store wrapped KEK
    store.setMeta("kdf_salt", Buffer.from(keys.salt).toString("base64"));
    store.setMeta("wrapped_kek", Buffer.from(keys.wrappedKek).toString("base64"));
    store.setMeta("wrapped_kek_iv", Buffer.from(keys.wrappedKekIv).toString("base64"));
    store.setMeta("wrapped_kek_tag", Buffer.from(keys.wrappedKekTag).toString("base64"));

    // Set internal state
    this.store = store;
    this.vaultId = keys.vaultId;
    this.kek = keys.kek;
    this.jwtKey = keys.jwtKey;
    this.auditKey = keys.auditKey;
    this.state = VaultState.UNLOCKED;

    this.initManagers();

    // Write session
    await this.writeNewSession();

    this.auditLogger?.log({
      eventType: AuditEventType.VAULT_UNLOCK,
      sessionId: this.sessionId ?? undefined,
    });

    return { vaultId: keys.vaultId };
  }

  /**
   * Unlock an existing vault with a password.
   */
  async unlock(password: string): Promise<void> {
    const store = this.store ?? new SqliteStore(this.options.dbPath);

    const vaultId = store.getMeta("vault_id");
    if (!vaultId) {
      store.close();
      throw VaultError.vaultNotFound();
    }

    // Check lockout
    this.checkLockout(store);

    const salt = this.loadBase64Meta(store, "kdf_salt");
    const wrappedKek = this.loadBase64Meta(store, "wrapped_kek");
    const wrappedKekIv = this.loadBase64Meta(store, "wrapped_kek_iv");
    const wrappedKekTag = this.loadBase64Meta(store, "wrapped_kek_tag");

    try {
      const keys = await unlockVault(password, salt, wrappedKek, wrappedKekIv, wrappedKekTag, vaultId);

      this.store = store;
      this.vaultId = vaultId;
      this.kek = keys.kek;
      this.jwtKey = keys.jwtKey;
      this.auditKey = keys.auditKey;
      this.state = VaultState.UNLOCKED;

      // Reset lockout on success
      store.setMeta("failed_attempts", "0");

      this.initManagers();
      await this.writeNewSession();

      this.auditLogger?.log({
        eventType: AuditEventType.VAULT_UNLOCK,
        sessionId: this.sessionId ?? undefined,
      });
    } catch (err) {
      if (err instanceof VaultError && err.code === ErrorCode.ENCRYPTION_ERROR) {
        // Wrong password — increment lockout counter
        this.incrementLockout(store);
        throw VaultError.invalidPassword();
      }
      throw err;
    }
  }

  /**
   * Load session from file (for long-lived processes like MCP server).
   */
  async loadSession(): Promise<boolean> {
    const session = await this.sessionManager.readSession();
    if (!session) return false;

    const store = this.store ?? new SqliteStore(this.options.dbPath);
    const vaultId = store.getMeta("vault_id");
    if (!vaultId || vaultId !== session.vault_id) return false;

    // Unwrap KEK and JWT key from session
    const sessionKeyBytes = new Uint8Array(Buffer.from(session.session_key, "base64"));

    try {
      const kek = decrypt(
        sessionKeyBytes,
        new Uint8Array(Buffer.from(session.wrapped_kek, "base64")),
        new Uint8Array(Buffer.from(session.wrapped_kek_iv, "base64")),
        new Uint8Array(Buffer.from(session.wrapped_kek_tag, "base64")),
        AAD_SESSION_KEK,
      );

      const jwtKey = decrypt(
        sessionKeyBytes,
        new Uint8Array(Buffer.from(session.wrapped_jwt_key, "base64")),
        new Uint8Array(Buffer.from(session.wrapped_jwt_key_iv, "base64")),
        new Uint8Array(Buffer.from(session.wrapped_jwt_key_tag, "base64")),
        AAD_SESSION_JWT,
      );

      // Re-derive audit key using master key... but we don't have it.
      // The audit key needs to be stored in the session too, or re-derived.
      // For v1.0, we derive it from the KEK + vaultId as a reasonable approach.
      const auditKey = await deriveSubkey(kek, vaultId, "audit-key-v1");

      this.store = store;
      this.vaultId = vaultId;
      this.kek = kek;
      this.jwtKey = jwtKey;
      this.auditKey = auditKey;
      this.sessionId = session.session_id;
      this.state = VaultState.UNLOCKED;

      this.initManagers();
      this.startSessionMonitor();

      return true;
    } catch {
      return false;
    }
  }

  /**
   * Lock the vault: wipe keys, erase session.
   */
  async lock(): Promise<void> {
    this.auditLogger?.log({
      eventType: AuditEventType.VAULT_LOCK,
      sessionId: this.sessionId ?? undefined,
    });

    this.wipeKeys();
    await this.sessionManager.eraseSession();
    this.state = VaultState.SEALED;
    this.stopSessionMonitor();
  }

  /**
   * Destroy and close everything. Does NOT erase the database.
   */
  async destroy(): Promise<void> {
    this.wipeKeys();
    this.stopSessionMonitor();
    this.store?.close();
    this.store = null;
    this.state = VaultState.SEALED;
  }

  getState(): VaultState {
    return this.state;
  }

  // ---------------------------------------------------------------------------
  // Secrets
  // ---------------------------------------------------------------------------

  createSecret(input: {
    name: string;
    type: SecretType;
    project?: string;
    value?: Uint8Array;
    injection?: InjectionConfig;
    expiresAt?: number;
  }): CreateSecretResponse {
    const s = this.assertUnlocked();
    const result = s.secretManager.createSecret(input);

    s.auditLogger.log({
      eventType: AuditEventType.SECRET_CREATE,
      detail: { handle: result.handle, status: result.status },
      sessionId: this.sessionId ?? undefined,
    });

    return result;
  }

  getSecretInfo(handle: string): SecretInfo {
    const s = this.assertUnlocked();
    const info = s.secretManager.getSecretInfo(handle);

    s.auditLogger.log({
      eventType: AuditEventType.SECRET_READ,
      detail: { handle },
      sessionId: this.sessionId ?? undefined,
    });

    return info;
  }

  getSecretValue(handle: string): Uint8Array {
    const s = this.assertUnlocked();
    return s.secretManager.getSecretValue(handle);
  }

  listSecrets(project?: string): SecretInfo[] {
    const s = this.assertUnlocked();
    return s.secretManager.listSecrets(project);
  }

  setSecretValue(handle: string, value: Uint8Array): void {
    const s = this.assertUnlocked();
    s.secretManager.setSecretValue(handle, value);

    s.auditLogger.log({
      eventType: AuditEventType.SECRET_CREATE,
      detail: { handle, action: "set_value" },
      sessionId: this.sessionId ?? undefined,
    });
  }

  rotateSecret(handle: string, newValue: Uint8Array): void {
    const s = this.assertUnlocked();
    s.secretManager.rotateSecret(handle, newValue);

    s.auditLogger.log({
      eventType: AuditEventType.SECRET_ROTATE,
      detail: { handle },
      sessionId: this.sessionId ?? undefined,
    });
  }

  revokeSecret(handle: string): void {
    const s = this.assertUnlocked();
    s.secretManager.revokeSecret(handle);

    s.auditLogger.log({
      eventType: AuditEventType.SECRET_REVOKE,
      detail: { handle },
      sessionId: this.sessionId ?? undefined,
    });
  }

  /**
   * Execute an HTTP request with an injected secret (use_secret).
   */
  async useSecret(
    handle: string,
    request: {
      method: HttpMethod;
      url: string;
      headers?: Record<string, string>;
      body?: string;
      timeoutMs?: number;
    },
    injection: InjectionConfig,
    followRedirects?: FollowRedirects,
  ): Promise<UseSecretResponse> {
    const s = this.assertUnlocked();

    const secret = s.secretManager.resolveHandle(handle);
    const value = s.secretManager.getSecretValue(handle);

    try {
      return await s.httpInjector.executeWithSecret(
        request,
        value,
        injection,
        followRedirects,
        secret.id,
      );
    } finally {
      wipeBuffer(value);
    }
  }

  // ---------------------------------------------------------------------------
  // Policies
  // ---------------------------------------------------------------------------

  grantPolicy(input: Omit<GrantPolicyInput, "createdBy">, createdBy: string): AccessPolicy {
    const s = this.assertUnlocked();
    const policy = s.policyEngine.grantPolicy({ ...input, createdBy });

    s.auditLogger.log({
      eventType: AuditEventType.POLICY_GRANT,
      secretId: input.secretId,
      detail: {
        policy_id: policy.id,
        principal: `${input.principalType}:${input.principalId}`,
      },
      sessionId: this.sessionId ?? undefined,
    });

    return policy;
  }

  revokePolicy(policyId: string): void {
    const s = this.assertUnlocked();
    s.policyEngine.revokePolicy(policyId);

    s.auditLogger.log({
      eventType: AuditEventType.POLICY_REVOKE,
      detail: { policy_id: policyId },
      sessionId: this.sessionId ?? undefined,
    });
  }

  listPolicies(secretId?: string): AccessPolicy[] {
    const s = this.assertUnlocked();
    return s.policyEngine.listPolicies(secretId);
  }

  // ---------------------------------------------------------------------------
  // Audit
  // ---------------------------------------------------------------------------

  queryAudit(options?: AuditQueryOptions): DecryptedAuditEvent[] {
    const s = this.assertUnlocked();
    return s.auditQuery.query(options);
  }

  // ---------------------------------------------------------------------------
  // JWT Auth
  // ---------------------------------------------------------------------------

  /**
   * Create a scoped JWT API token. HMAC-SHA256 signed.
   */
  createToken(
    subject: string,
    scope: Permission[],
    ttlMs: number = 3600_000,
  ): string {
    const s = this.assertUnlocked();

    const now = Math.floor(Date.now() / 1000);
    const payload: VaultApiToken = {
      sub: subject,
      vault_id: s.vaultId,
      scope,
      iat: now,
      exp: now + Math.floor(ttlMs / 1000),
      jti: generateUUIDv7(),
    };

    return this.signJwt(payload);
  }

  /**
   * Verify and decode a JWT token.
   */
  verifyToken(token: string): VaultApiToken {
    this.assertUnlocked();

    const payload = this.verifyJwt(token);

    if (this.revokedTokens.has(payload.jti)) {
      throw VaultError.tokenRevoked();
    }

    const now = Math.floor(Date.now() / 1000);
    if (payload.exp <= now) {
      throw VaultError.tokenExpired();
    }

    return payload;
  }

  /**
   * Revoke a JWT token by JTI.
   */
  revokeToken(jti: string): void {
    this.assertUnlocked();
    this.revokedTokens.add(jti);
  }

  // ---------------------------------------------------------------------------
  // Password change
  // ---------------------------------------------------------------------------

  async changePassword(oldPassword: string, newPassword: string): Promise<void> {
    const s = this.assertUnlocked();

    const salt = this.loadBase64Meta(s.store, "kdf_salt");
    const wrappedKek = this.loadBase64Meta(s.store, "wrapped_kek");
    const wrappedKekIv = this.loadBase64Meta(s.store, "wrapped_kek_iv");
    const wrappedKekTag = this.loadBase64Meta(s.store, "wrapped_kek_tag");

    const result = await changePassword(
      oldPassword,
      newPassword,
      salt,
      wrappedKek,
      wrappedKekIv,
      wrappedKekTag,
      s.vaultId,
    );

    s.store.setMeta("kdf_salt", Buffer.from(result.newSalt).toString("base64"));
    s.store.setMeta("wrapped_kek", Buffer.from(result.newWrappedKek).toString("base64"));
    s.store.setMeta("wrapped_kek_iv", Buffer.from(result.newWrappedKekIv).toString("base64"));
    s.store.setMeta("wrapped_kek_tag", Buffer.from(result.newWrappedKekTag).toString("base64"));

    // Update in-memory keys
    this.jwtKey = result.jwtKey;
    this.auditKey = result.auditKey;

    // Re-init audit with new key
    this.auditLogger = new AuditLogger(s.store, this.auditKey as Uint8Array);
    this.auditQuery = new AuditQuery(s.store, this.auditKey as Uint8Array);

    this.auditLogger.log({
      eventType: AuditEventType.VAULT_PASSWORD_CHANGE,
      sessionId: this.sessionId ?? undefined,
    });

    // Write new session with updated keys
    await this.writeNewSession();
  }

  // ---------------------------------------------------------------------------
  // Private: state management
  // ---------------------------------------------------------------------------

  private assertUnlocked(): UnlockedState {
    if (this.state !== VaultState.UNLOCKED) {
      throw VaultError.vaultLocked();
    }
    return {
      store: this.store as SqliteStore,
      kek: this.kek as Uint8Array,
      jwtKey: this.jwtKey as Uint8Array,
      auditKey: this.auditKey as Uint8Array,
      vaultId: this.vaultId as string,
      secretManager: this.secretManager as SecretManager,
      policyEngine: this.policyEngine as PolicyEngine,
      auditLogger: this.auditLogger as AuditLogger,
      auditQuery: this.auditQuery as AuditQuery,
      httpInjector: this.httpInjector as HttpInjector,
    };
  }

  private initManagers(): void {
    const store = this.store as SqliteStore;
    const kek = this.kek as Uint8Array;
    const auditKey = this.auditKey as Uint8Array;

    this.secretManager = new SecretManager(store, kek);
    this.policyEngine = new PolicyEngine(store);
    this.auditLogger = new AuditLogger(store, auditKey);
    this.auditQuery = new AuditQuery(store, auditKey);
    this.httpInjector = new HttpInjector(this.auditLogger);
  }

  private wipeKeys(): void {
    if (this.kek) { wipeBuffer(this.kek); this.kek = null; }
    if (this.jwtKey) { wipeBuffer(this.jwtKey); this.jwtKey = null; }
    if (this.auditKey) { wipeBuffer(this.auditKey); this.auditKey = null; }

    this.secretManager = null;
    this.policyEngine = null;
    this.auditLogger = null;
    this.auditQuery = null;
    this.httpInjector = null;
    this.sessionId = null;
    this.vaultId = null;
  }

  // ---------------------------------------------------------------------------
  // Private: session
  // ---------------------------------------------------------------------------

  private async writeNewSession(): Promise<void> {
    const kek = this.kek as Uint8Array;
    const jwtKey = this.jwtKey as Uint8Array;
    const vaultId = this.vaultId as string;

    const sessionKey = generateRandomBytes(AES_KEY_LENGTH);
    const sessionIdVal = generateUUIDv7();
    this.sessionId = sessionIdVal;

    // Wrap KEK with session key
    const wrappedKek = encrypt(sessionKey, kek, AAD_SESSION_KEK);
    const wrappedJwt = encrypt(sessionKey, jwtKey, AAD_SESSION_JWT);

    const session = SessionManager.createSessionData(
      sessionIdVal,
      vaultId,
      Buffer.from(sessionKey).toString("base64"),
      Buffer.from(wrappedKek.ciphertext).toString("base64"),
      Buffer.from(wrappedKek.iv).toString("base64"),
      Buffer.from(wrappedKek.tag).toString("base64"),
      Buffer.from(wrappedJwt.ciphertext).toString("base64"),
      Buffer.from(wrappedJwt.iv).toString("base64"),
      Buffer.from(wrappedJwt.tag).toString("base64"),
    );

    await this.sessionManager.writeSession(session);
  }

  private startSessionMonitor(): void {
    this.stopSessionMonitor();
    this.sessionMonitorInterval = setInterval(async () => {
      const session = await this.sessionManager.readSession();
      if (!session) {
        // Session expired or removed
        this.wipeKeys();
        this.state = VaultState.SEALED;
        this.stopSessionMonitor();
      }
    }, SESSION_CLEANUP_INTERVAL_MS);

    // Don't block Node.js exit
    if (this.sessionMonitorInterval.unref) {
      this.sessionMonitorInterval.unref();
    }
  }

  private stopSessionMonitor(): void {
    if (this.sessionMonitorInterval) {
      clearInterval(this.sessionMonitorInterval);
      this.sessionMonitorInterval = null;
    }
  }

  // ---------------------------------------------------------------------------
  // Private: lockout
  // ---------------------------------------------------------------------------

  private checkLockout(store: SqliteStore): void {
    const lockoutUntil = store.getMeta("lockout_until");
    if (lockoutUntil) {
      const until = parseInt(lockoutUntil, 10);
      if (Date.now() < until) {
        throw VaultError.lockoutActive(until - Date.now());
      }
    }
  }

  private incrementLockout(store: SqliteStore): void {
    const attempts = parseInt(store.getMeta("failed_attempts") ?? "0", 10) + 1;
    store.setMeta("failed_attempts", String(attempts));

    if (attempts >= LOCKOUT_MAX_ATTEMPTS) {
      const lockoutIndex = Math.min(
        Math.floor((attempts - LOCKOUT_MAX_ATTEMPTS) / LOCKOUT_MAX_ATTEMPTS),
        LOCKOUT_DURATIONS_MS.length - 1,
      );
      const duration = LOCKOUT_DURATIONS_MS[lockoutIndex] ?? LOCKOUT_DURATIONS_MS[LOCKOUT_DURATIONS_MS.length - 1] ?? 1800_000;
      store.setMeta("lockout_until", String(Date.now() + duration));
    }
  }

  // ---------------------------------------------------------------------------
  // Private: JWT (HMAC-SHA256, no external deps)
  // ---------------------------------------------------------------------------

  private signJwt(payload: VaultApiToken): string {
    const jwtKey = this.jwtKey as Uint8Array;
    const header = Buffer.from(JSON.stringify({ alg: "HS256", typ: "JWT" })).toString("base64url");
    const body = Buffer.from(JSON.stringify(payload)).toString("base64url");
    const signature = createHmac("sha256", jwtKey)
      .update(`${header}.${body}`)
      .digest("base64url");

    return `${header}.${body}.${signature}`;
  }

  private verifyJwt(token: string): VaultApiToken {
    const jwtKey = this.jwtKey as Uint8Array;
    const parts = token.split(".");
    if (parts.length !== 3) {
      throw new VaultError(ErrorCode.INVALID_TOKEN, "Invalid token format");
    }

    const [header, body, signature] = parts as [string, string, string];

    // Verify signature using timing-safe comparison
    const expectedSig = createHmac("sha256", jwtKey)
      .update(`${header}.${body}`)
      .digest();

    const actualSig = Buffer.from(signature, "base64url");

    if (expectedSig.length !== actualSig.length || !timingSafeEqual(expectedSig, actualSig)) {
      throw new VaultError(ErrorCode.INVALID_TOKEN, "Invalid token signature");
    }

    try {
      return JSON.parse(Buffer.from(body, "base64url").toString("utf8")) as VaultApiToken;
    } catch {
      throw new VaultError(ErrorCode.INVALID_TOKEN, "Invalid token payload");
    }
  }

  // ---------------------------------------------------------------------------
  // Private: helpers
  // ---------------------------------------------------------------------------

  private loadBase64Meta(store: SqliteStore, key: string): Uint8Array {
    const value = store.getMeta(key);
    if (!value) {
      throw VaultError.vaultCorrupted(`Missing ${key}`);
    }
    return new Uint8Array(Buffer.from(value, "base64"));
  }
}
