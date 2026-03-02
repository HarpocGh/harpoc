import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { AuditEventType } from "@harpoc/shared";
import { generateRandomBytes } from "../crypto/random.js";
import { SqliteStore } from "../storage/sqlite-store.js";
import { AuditLogger } from "./audit-logger.js";

let store: SqliteStore;
let auditKey: Uint8Array;
let logger: AuditLogger;

beforeEach(() => {
  store = new SqliteStore(":memory:");
  auditKey = generateRandomBytes(32);
  logger = new AuditLogger(store, auditKey);
});

afterEach(() => {
  store.close();
});

describe("AuditLogger", () => {
  it("logs an event and returns its ID", () => {
    const id = logger.log({
      eventType: AuditEventType.SECRET_CREATE,
      secretId: "s1",
      success: true,
    });

    expect(id).toBeGreaterThan(0);
  });

  it("encrypts detail when auditKey is provided", () => {
    logger.log({
      eventType: AuditEventType.SECRET_USE,
      detail: { url: "https://api.example.com", method: "GET" },
    });

    const events = store.queryAuditLog();
    expect(events[0]?.detail_encrypted).not.toBeNull();
    expect(events[0]?.detail_iv).not.toBeNull();
    expect(events[0]?.detail_tag).not.toBeNull();
  });

  it("stores null detail when auditKey is null", () => {
    const loggerNoKey = new AuditLogger(store, null);
    loggerNoKey.log({
      eventType: AuditEventType.SECRET_READ,
      detail: { handle: "secret://test" },
    });

    const events = store.queryAuditLog();
    expect(events[0]?.detail_encrypted).toBeNull();
  });

  it("stores null detail when no detail provided", () => {
    logger.log({ eventType: AuditEventType.VAULT_UNLOCK });

    const events = store.queryAuditLog();
    expect(events[0]?.detail_encrypted).toBeNull();
  });

  it("stores all metadata fields", () => {
    logger.log({
      eventType: AuditEventType.ACCESS_DENIED,
      secretId: "s1",
      principalType: "agent",
      principalId: "agent-1",
      ipAddress: "127.0.0.1",
      sessionId: "sess-1",
      success: false,
    });

    const events = store.queryAuditLog();
    const event = events[0];
    expect(event?.event_type).toBe("access.denied");
    expect(event?.secret_id).toBe("s1");
    expect(event?.principal_type).toBe("agent");
    expect(event?.principal_id).toBe("agent-1");
    expect(event?.ip_address).toBe("127.0.0.1");
    expect(event?.session_id).toBe("sess-1");
    expect(event?.success).toBe(false);
  });

  it("defaults success to true", () => {
    logger.log({ eventType: AuditEventType.VAULT_LOCK });

    const events = store.queryAuditLog();
    expect(events[0]?.success).toBe(true);
  });
});
