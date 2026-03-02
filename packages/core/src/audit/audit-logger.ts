import type { AuditEventType, PrincipalType } from "@harpoc/shared";
import { AAD_AUDIT_DETAIL } from "@harpoc/shared";
import { encrypt } from "../crypto/aes-gcm.js";
import type { SqliteStore } from "../storage/sqlite-store.js";

export interface AuditLogOptions {
  eventType: AuditEventType;
  secretId?: string;
  principalType?: PrincipalType;
  principalId?: string;
  detail?: Record<string, unknown>;
  ipAddress?: string;
  sessionId?: string;
  success?: boolean;
}

/**
 * Writes encrypted audit log entries to the database.
 * If no audit key is provided, detail is stored as null (unencrypted logging disabled).
 */
export class AuditLogger {
  constructor(
    private readonly store: SqliteStore,
    private readonly auditKey: Uint8Array | null,
  ) {}

  log(options: AuditLogOptions): number {
    const {
      eventType,
      secretId,
      principalType,
      principalId,
      detail,
      ipAddress,
      sessionId,
      success = true,
    } = options;

    let detailEncrypted: Uint8Array | null = null;
    let detailIv: Uint8Array | null = null;
    let detailTag: Uint8Array | null = null;

    if (detail && this.auditKey) {
      const plaintext = new Uint8Array(Buffer.from(JSON.stringify(detail), "utf8"));
      const encrypted = encrypt(this.auditKey, plaintext, AAD_AUDIT_DETAIL);
      detailEncrypted = encrypted.ciphertext;
      detailIv = encrypted.iv;
      detailTag = encrypted.tag;
    }

    return this.store.insertAuditEvent({
      timestamp: Date.now(),
      event_type: eventType,
      secret_id: secretId ?? null,
      principal_type: principalType ?? null,
      principal_id: principalId ?? null,
      detail_encrypted: detailEncrypted,
      detail_iv: detailIv,
      detail_tag: detailTag,
      ip_address: ipAddress ?? null,
      session_id: sessionId ?? null,
      success,
    });
  }
}
