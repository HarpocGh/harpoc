import { describe, expect, it } from "vitest";

import {
  accessPolicyInputSchema,
  auditEventTypeSchema,
  auditQuerySchema,
  createSecretInputSchema,
  followRedirectsSchema,
  handleSchema,
  injectionConfigSchema,
  permissionSchema,
  principalTypeSchema,
  secretStatusSchema,
  secretTypeSchema,
  sessionFileSchema,
  useSecretRequestSchema,
} from "./schemas.js";

// ---------------------------------------------------------------------------
// Enum schemas
// ---------------------------------------------------------------------------

describe("enum schemas", () => {
  it("secretTypeSchema accepts valid values", () => {
    expect(secretTypeSchema.parse("api_key")).toBe("api_key");
    expect(secretTypeSchema.parse("oauth_token")).toBe("oauth_token");
    expect(secretTypeSchema.parse("certificate")).toBe("certificate");
  });

  it("secretTypeSchema rejects invalid values", () => {
    expect(() => secretTypeSchema.parse("password")).toThrow();
  });

  it("secretStatusSchema accepts valid values", () => {
    expect(secretStatusSchema.parse("active")).toBe("active");
    expect(secretStatusSchema.parse("expired")).toBe("expired");
    expect(secretStatusSchema.parse("revoked")).toBe("revoked");
  });

  it("permissionSchema accepts all valid permissions", () => {
    for (const p of ["list", "read", "use", "create", "rotate", "revoke", "admin"]) {
      expect(permissionSchema.parse(p)).toBe(p);
    }
  });

  it("permissionSchema rejects invalid permission", () => {
    expect(() => permissionSchema.parse("delete")).toThrow();
  });

  it("auditEventTypeSchema accepts valid event types", () => {
    expect(auditEventTypeSchema.parse("vault.unlock")).toBe("vault.unlock");
    expect(auditEventTypeSchema.parse("secret.create")).toBe("secret.create");
    expect(auditEventTypeSchema.parse("access.denied")).toBe("access.denied");
  });

  it("principalTypeSchema accepts valid values", () => {
    for (const p of ["agent", "tool", "project", "user"]) {
      expect(principalTypeSchema.parse(p)).toBe(p);
    }
  });

  it("followRedirectsSchema accepts valid values", () => {
    expect(followRedirectsSchema.parse("same-origin")).toBe("same-origin");
    expect(followRedirectsSchema.parse("none")).toBe("none");
    expect(followRedirectsSchema.parse("any")).toBe("any");
  });
});

// ---------------------------------------------------------------------------
// handleSchema
// ---------------------------------------------------------------------------

describe("handleSchema", () => {
  it("accepts valid handles", () => {
    expect(handleSchema.parse("secret://my-key")).toBe("secret://my-key");
    expect(handleSchema.parse("secret://proj/my-key")).toBe("secret://proj/my-key");
  });

  it("rejects invalid handles", () => {
    expect(() => handleSchema.parse("my-key")).toThrow();
    expect(() => handleSchema.parse("")).toThrow();
    expect(() => handleSchema.parse("secret://")).toThrow();
  });
});

// ---------------------------------------------------------------------------
// injectionConfigSchema
// ---------------------------------------------------------------------------

describe("injectionConfigSchema", () => {
  it("accepts bearer (no extra fields)", () => {
    expect(injectionConfigSchema.parse({ type: "bearer" })).toEqual({ type: "bearer" });
  });

  it("accepts basic_auth", () => {
    expect(injectionConfigSchema.parse({ type: "basic_auth" })).toEqual({ type: "basic_auth" });
  });

  it("accepts header with header_name", () => {
    const result = injectionConfigSchema.parse({ type: "header", header_name: "X-API-Key" });
    expect(result).toEqual({ type: "header", header_name: "X-API-Key" });
  });

  it("rejects header without header_name", () => {
    expect(() => injectionConfigSchema.parse({ type: "header" })).toThrow();
  });

  it("accepts query with query_param", () => {
    const result = injectionConfigSchema.parse({ type: "query", query_param: "api_key" });
    expect(result).toEqual({ type: "query", query_param: "api_key" });
  });

  it("rejects query without query_param", () => {
    expect(() => injectionConfigSchema.parse({ type: "query" })).toThrow();
  });

  it("rejects unknown injection type", () => {
    expect(() => injectionConfigSchema.parse({ type: "cookie" })).toThrow();
  });
});

// ---------------------------------------------------------------------------
// createSecretInputSchema
// ---------------------------------------------------------------------------

describe("createSecretInputSchema", () => {
  it("accepts valid minimal input", () => {
    const input = { name: "github-token", type: "api_key" };
    const result = createSecretInputSchema.parse(input);
    expect(result.name).toBe("github-token");
    expect(result.type).toBe("api_key");
    expect(result.project).toBeUndefined();
    expect(result.injection).toBeUndefined();
  });

  it("accepts input with all optional fields", () => {
    const input = {
      name: "github-token",
      type: "api_key",
      project: "my-api",
      injection: { type: "bearer" as const },
    };
    const result = createSecretInputSchema.parse(input);
    expect(result.project).toBe("my-api");
    expect(result.injection).toEqual({ type: "bearer" });
  });

  it("rejects missing name", () => {
    expect(() => createSecretInputSchema.parse({ type: "api_key" })).toThrow();
  });

  it("rejects invalid type", () => {
    expect(() => createSecretInputSchema.parse({ name: "key", type: "password" })).toThrow();
  });

  it("rejects invalid name format", () => {
    expect(() => createSecretInputSchema.parse({ name: "has space", type: "api_key" })).toThrow();
  });
});

// ---------------------------------------------------------------------------
// useSecretRequestSchema
// ---------------------------------------------------------------------------

describe("useSecretRequestSchema", () => {
  const validRequest = {
    handle: "secret://github-token",
    request: {
      method: "GET" as const,
      url: "https://api.github.com/user",
    },
    injection: { type: "bearer" as const },
  };

  it("accepts valid full request", () => {
    const result = useSecretRequestSchema.parse(validRequest);
    expect(result.handle).toBe("secret://github-token");
    expect(result.request.method).toBe("GET");
  });

  it("accepts request with all optional fields", () => {
    const result = useSecretRequestSchema.parse({
      ...validRequest,
      request: {
        ...validRequest.request,
        headers: { Accept: "application/json" },
        body: '{"key": "val"}',
        timeout_ms: 5000,
      },
      follow_redirects: "none",
    });
    expect(result.request.headers).toEqual({ Accept: "application/json" });
    expect(result.follow_redirects).toBe("none");
  });

  it("rejects invalid method", () => {
    expect(() =>
      useSecretRequestSchema.parse({
        ...validRequest,
        request: { ...validRequest.request, method: "CONNECT" },
      }),
    ).toThrow();
  });

  it("rejects invalid URL", () => {
    expect(() =>
      useSecretRequestSchema.parse({
        ...validRequest,
        request: { ...validRequest.request, url: "not-a-url" },
      }),
    ).toThrow();
  });

  it("rejects missing required fields", () => {
    expect(() => useSecretRequestSchema.parse({ handle: "secret://k" })).toThrow();
    expect(() => useSecretRequestSchema.parse({ ...validRequest, handle: undefined })).toThrow();
  });
});

// ---------------------------------------------------------------------------
// accessPolicyInputSchema
// ---------------------------------------------------------------------------

describe("accessPolicyInputSchema", () => {
  it("accepts valid policy", () => {
    const result = accessPolicyInputSchema.parse({
      principal_type: "agent",
      principal_id: "claude-code",
      permissions: ["read", "use"],
    });
    expect(result.principal_type).toBe("agent");
    expect(result.permissions).toEqual(["read", "use"]);
  });

  it("rejects empty permissions array", () => {
    expect(() =>
      accessPolicyInputSchema.parse({
        principal_type: "agent",
        principal_id: "claude-code",
        permissions: [],
      }),
    ).toThrow();
  });
});

// ---------------------------------------------------------------------------
// auditQuerySchema
// ---------------------------------------------------------------------------

describe("auditQuerySchema", () => {
  it("accepts empty query (all optional)", () => {
    expect(auditQuerySchema.parse({})).toEqual({});
  });

  it("accepts full query", () => {
    const result = auditQuerySchema.parse({
      event_type: "secret.create",
      limit: 100,
    });
    expect(result.event_type).toBe("secret.create");
    expect(result.limit).toBe(100);
  });

  it("rejects limit over 1000", () => {
    expect(() => auditQuerySchema.parse({ limit: 1001 })).toThrow();
  });
});

// ---------------------------------------------------------------------------
// sessionFileSchema
// ---------------------------------------------------------------------------

describe("sessionFileSchema", () => {
  const validSession = {
    version: 1 as const,
    session_id: "01234567-89ab-cdef-0123-456789abcdef",
    vault_id: "vault-001",
    created_at: Date.now(),
    expires_at: Date.now() + 900_000,
    max_expires_at: Date.now() + 86_400_000,
    session_key: "c2Vzc2lvbi1rZXk=",
    wrapped_kek: "d3JhcHBlZC1rZWs=",
    wrapped_kek_iv: "aXY=",
    wrapped_kek_tag: "dGFn",
    wrapped_jwt_key: "and0LWtleQ==",
    wrapped_jwt_key_iv: "and0LWl2",
    wrapped_jwt_key_tag: "and0LXRhZw==",
  };

  it("accepts valid session file", () => {
    const result = sessionFileSchema.parse(validSession);
    expect(result.version).toBe(1);
    expect(result.session_id).toBe(validSession.session_id);
  });

  it("rejects wrong version", () => {
    expect(() => sessionFileSchema.parse({ ...validSession, version: 2 })).toThrow();
  });

  it("rejects missing fields", () => {
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const { session_key: _omitted, ...incomplete } = validSession;
    expect(() => sessionFileSchema.parse(incomplete)).toThrow();
  });

  it("rejects empty string for base64 fields", () => {
    expect(() => sessionFileSchema.parse({ ...validSession, session_key: "" })).toThrow();
  });
});
