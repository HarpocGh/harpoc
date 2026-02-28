import type {
  CreateSecretResponse,
  InjectionConfig,
  ParsedHandle,
  Secret,
  SecretType,
} from "@harpoc/shared";
import {
  AES_KEY_LENGTH,
  ErrorCode,
  SecretStatus,
  VaultError,
  formatHandle,
  parseHandle,
} from "@harpoc/shared";
import {
  decryptName,
  decryptSecretValue,
  encryptName,
  encryptSecretValue,
  unwrapDek,
  wrapDek,
} from "../crypto/key-hierarchy.js";
import { generateRandomBytes, generateUUIDv7, wipeBuffer } from "../crypto/random.js";
import type { SqliteStore } from "../storage/sqlite-store.js";

export interface CreateSecretInput {
  name: string;
  type: SecretType;
  project?: string;
  value?: Uint8Array;
  injection?: InjectionConfig;
  expiresAt?: number;
}

/** Info about a secret without its value (safe to return to LLM). */
export interface SecretInfo {
  handle: string;
  name: string;
  type: SecretType;
  project: string | null;
  status: string;
  version: number;
  createdAt: number;
  updatedAt: number;
  expiresAt: number | null;
  rotatedAt: number | null;
}

export class SecretManager {
  constructor(
    private readonly store: SqliteStore,
    private readonly kek: Uint8Array,
  ) {}

  /**
   * Create a new secret. If no value is provided, status is PENDING.
   */
  createSecret(input: CreateSecretInput): CreateSecretResponse {
    const { name, type, project, value, expiresAt } = input;

    // Check for duplicate name+project
    this.assertNoDuplicate(name, project ?? null);

    const id = generateUUIDv7();
    const now = Date.now();

    // Encrypt name with KEK
    const nameEnc = encryptName(this.kek, name, id);

    // Generate DEK and wrap it
    const dek = generateRandomBytes(AES_KEY_LENGTH);
    const wrapped = wrapDek(this.kek, dek, id);

    let status: typeof SecretStatus.ACTIVE | typeof SecretStatus.PENDING;
    let ciphertext: Uint8Array;
    let ctIv: Uint8Array;
    let ctTag: Uint8Array;

    if (value) {
      // Encrypt the value
      const encrypted = encryptSecretValue(dek, value, id, 1);
      ciphertext = encrypted.ciphertext;
      ctIv = encrypted.iv;
      ctTag = encrypted.tag;
      status = SecretStatus.ACTIVE;
    } else {
      // Pending secret — store empty encrypted payload
      const encrypted = encryptSecretValue(dek, new Uint8Array(0), id, 1);
      ciphertext = encrypted.ciphertext;
      ctIv = encrypted.iv;
      ctTag = encrypted.tag;
      status = SecretStatus.PENDING;
    }

    // Wipe DEK from memory
    wipeBuffer(dek);

    const secret: Secret = {
      id,
      name_encrypted: nameEnc.ciphertext,
      name_iv: nameEnc.iv,
      name_tag: nameEnc.tag,
      type,
      project: project ?? null,
      wrapped_dek: wrapped.wrappedDek,
      dek_iv: wrapped.dekIv,
      dek_tag: wrapped.dekTag,
      ciphertext,
      ct_iv: ctIv,
      ct_tag: ctTag,
      metadata_encrypted: null,
      metadata_iv: null,
      metadata_tag: null,
      created_at: now,
      updated_at: now,
      expires_at: expiresAt ?? null,
      rotated_at: null,
      version: 1,
      status,
      sync_version: 0,
    };

    this.store.insertSecret(secret);

    const handle = formatHandle(name, project);
    return {
      handle,
      status: value ? "created" : "pending",
      message: value
        ? `Secret ${handle} created`
        : `Secret ${handle} created with pending status — set value via CLI`,
    };
  }

  /**
   * Set the value for a PENDING secret (transitions to ACTIVE).
   */
  setSecretValue(handle: string, value: Uint8Array): void {
    const secret = this.resolveHandleToSecret(handle);

    if (secret.status !== SecretStatus.PENDING) {
      throw new VaultError(
        ErrorCode.INVALID_INPUT,
        `Secret ${handle} is not pending — use rotate to update an active secret`,
      );
    }

    // Unwrap DEK
    const dek = unwrapDek(this.kek, secret.wrapped_dek, secret.dek_iv, secret.dek_tag, secret.id);

    try {
      const encrypted = encryptSecretValue(dek, value, secret.id, secret.version);

      this.store.updateSecret(secret.id, {
        ciphertext: encrypted.ciphertext,
        ct_iv: encrypted.iv,
        ct_tag: encrypted.tag,
        status: SecretStatus.ACTIVE,
        updated_at: Date.now(),
      });
    } finally {
      wipeBuffer(dek);
    }
  }

  /**
   * Get secret info (metadata only, no value) — safe to return to LLM.
   */
  getSecretInfo(handle: string): SecretInfo {
    const secret = this.resolveHandleToSecret(handle);
    const name = decryptName(this.kek, secret.name_encrypted, secret.name_iv, secret.name_tag, secret.id);

    return {
      handle: formatHandle(name, secret.project ?? undefined),
      name,
      type: secret.type,
      project: secret.project,
      status: secret.status,
      version: secret.version,
      createdAt: secret.created_at,
      updatedAt: secret.updated_at,
      expiresAt: secret.expires_at,
      rotatedAt: secret.rotated_at,
    };
  }

  /**
   * Get the decrypted secret value. NEVER return this to the LLM.
   */
  getSecretValue(handle: string): Uint8Array {
    const secret = this.resolveHandleToSecret(handle);
    this.assertUsable(secret, handle);

    const dek = unwrapDek(this.kek, secret.wrapped_dek, secret.dek_iv, secret.dek_tag, secret.id);

    try {
      return decryptSecretValue(dek, secret.ciphertext, secret.ct_iv, secret.ct_tag, secret.id, secret.version);
    } finally {
      wipeBuffer(dek);
    }
  }

  /**
   * List all secrets (metadata only).
   */
  listSecrets(project?: string): SecretInfo[] {
    const secrets = this.store.listSecrets(project ? { project } : undefined);

    return secrets.map((s) => {
      const name = decryptName(this.kek, s.name_encrypted, s.name_iv, s.name_tag, s.id);
      return {
        handle: formatHandle(name, s.project ?? undefined),
        name,
        type: s.type,
        project: s.project,
        status: s.status,
        version: s.version,
        createdAt: s.created_at,
        updatedAt: s.updated_at,
        expiresAt: s.expires_at,
        rotatedAt: s.rotated_at,
      };
    });
  }

  /**
   * Rotate a secret: new DEK, new ciphertext, version incremented.
   */
  rotateSecret(handle: string, newValue: Uint8Array): void {
    const secret = this.resolveHandleToSecret(handle);
    this.assertUsable(secret, handle);

    const newVersion = secret.version + 1;
    const newDek = generateRandomBytes(AES_KEY_LENGTH);

    try {
      const wrapped = wrapDek(this.kek, newDek, secret.id);
      const encrypted = encryptSecretValue(newDek, newValue, secret.id, newVersion);

      this.store.updateSecret(secret.id, {
        wrapped_dek: wrapped.wrappedDek,
        dek_iv: wrapped.dekIv,
        dek_tag: wrapped.dekTag,
        ciphertext: encrypted.ciphertext,
        ct_iv: encrypted.iv,
        ct_tag: encrypted.tag,
        version: newVersion,
        rotated_at: Date.now(),
        updated_at: Date.now(),
      });
    } finally {
      wipeBuffer(newDek);
    }
  }

  /**
   * Revoke a secret (sets status to REVOKED).
   */
  revokeSecret(handle: string): void {
    const secret = this.resolveHandleToSecret(handle);

    if (secret.status === SecretStatus.REVOKED) {
      throw VaultError.secretRevoked(handle);
    }

    this.store.updateSecret(secret.id, {
      status: SecretStatus.REVOKED,
      updated_at: Date.now(),
    });
  }

  /**
   * Resolve a handle to a secret record.
   */
  resolveHandle(handle: string): Secret {
    return this.resolveHandleToSecret(handle);
  }

  // ---------------------------------------------------------------------------
  // Private
  // ---------------------------------------------------------------------------

  private resolveHandleToSecret(handle: string): Secret {
    const parsed: ParsedHandle = parseHandle(handle);
    const allSecrets = this.store.listSecrets();

    const matches: Secret[] = [];

    for (const secret of allSecrets) {
      const name = decryptName(this.kek, secret.name_encrypted, secret.name_iv, secret.name_tag, secret.id);

      if (name !== parsed.name) continue;
      if (parsed.project !== undefined && secret.project !== parsed.project) continue;
      if (parsed.project === undefined && secret.project !== null) continue;

      matches.push(secret);
    }

    if (matches.length === 0) {
      throw VaultError.secretNotFound(handle);
    }
    if (matches.length > 1) {
      throw new VaultError(ErrorCode.AMBIGUOUS_HANDLE, `Ambiguous handle: ${handle}`);
    }

    return matches[0] as Secret;
  }

  private assertNoDuplicate(name: string, project: string | null): void {
    const allSecrets = this.store.listSecrets();

    for (const secret of allSecrets) {
      if (secret.status === SecretStatus.REVOKED) continue;

      const existingName = decryptName(
        this.kek,
        secret.name_encrypted,
        secret.name_iv,
        secret.name_tag,
        secret.id,
      );

      if (existingName === name && secret.project === project) {
        throw VaultError.duplicateSecret(name);
      }
    }
  }

  private assertUsable(secret: Secret, handle: string): void {
    if (secret.status === SecretStatus.EXPIRED) {
      throw VaultError.secretExpired(handle);
    }
    if (secret.status === SecretStatus.REVOKED) {
      throw VaultError.secretRevoked(handle);
    }
    if (secret.status === SecretStatus.PENDING) {
      throw new VaultError(ErrorCode.SECRET_VALUE_REQUIRED, `Secret ${handle} has no value set`);
    }
  }
}
