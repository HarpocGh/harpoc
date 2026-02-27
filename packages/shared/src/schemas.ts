import { z } from "zod";

import { isValidHandle } from "./handle.js";
import {
  AuditEventType,
  FollowRedirects,
  InjectionType,
  Permission,
  PrincipalType,
  SecretStatus,
  SecretType,
} from "./types.js";

// ---------------------------------------------------------------------------
// Enum schemas (derived from const objects in types.ts)
// ---------------------------------------------------------------------------

const secretTypeValues = Object.values(SecretType) as [SecretType, ...SecretType[]];
export const secretTypeSchema = z.enum(secretTypeValues);

const secretStatusValues = Object.values(SecretStatus) as [SecretStatus, ...SecretStatus[]];
export const secretStatusSchema = z.enum(secretStatusValues);

const permissionValues = Object.values(Permission) as [Permission, ...Permission[]];
export const permissionSchema = z.enum(permissionValues);

const auditEventTypeValues = Object.values(AuditEventType) as [AuditEventType, ...AuditEventType[]];
export const auditEventTypeSchema = z.enum(auditEventTypeValues);

const principalTypeValues = Object.values(PrincipalType) as [PrincipalType, ...PrincipalType[]];
export const principalTypeSchema = z.enum(principalTypeValues);

const injectionTypeValues = Object.values(InjectionType) as [InjectionType, ...InjectionType[]];
export const injectionTypeSchema = z.enum(injectionTypeValues);

const followRedirectsValues = Object.values(FollowRedirects) as [
  FollowRedirects,
  ...FollowRedirects[],
];
export const followRedirectsSchema = z.enum(followRedirectsValues);

// ---------------------------------------------------------------------------
// Handle schema
// ---------------------------------------------------------------------------

export const handleSchema = z.string().refine(isValidHandle, { message: "Invalid secret handle" });

// ---------------------------------------------------------------------------
// Injection config schema
// ---------------------------------------------------------------------------

export const injectionConfigSchema = z.discriminatedUnion("type", [
  z.object({ type: z.literal("bearer") }),
  z.object({ type: z.literal("basic_auth") }),
  z.object({
    type: z.literal("header"),
    header_name: z.string().min(1),
  }),
  z.object({
    type: z.literal("query"),
    query_param: z.string().min(1),
  }),
]);

// ---------------------------------------------------------------------------
// Input validation schemas (API boundaries: REST bodies, MCP inputs, CLI args)
// ---------------------------------------------------------------------------

const namePattern = z.string().regex(/^[a-zA-Z0-9_-]+$/, "Invalid name format");

export const createSecretInputSchema = z.object({
  name: namePattern,
  type: secretTypeSchema,
  project: namePattern.optional(),
  injection: injectionConfigSchema.optional(),
});

const httpMethodSchema = z.enum(["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"]);

export const useSecretRequestSchema = z.object({
  handle: handleSchema,
  request: z.object({
    method: httpMethodSchema,
    url: z.string().url(),
    headers: z.record(z.string()).optional(),
    body: z.string().optional(),
    timeout_ms: z.number().int().positive().optional(),
  }),
  injection: injectionConfigSchema,
  follow_redirects: followRedirectsSchema.optional(),
});

export const accessPolicyInputSchema = z.object({
  principal_type: principalTypeSchema,
  principal_id: z.string().min(1),
  permissions: z.array(permissionSchema).min(1),
  expires_at: z.number().int().positive().optional(),
});

export const auditQuerySchema = z.object({
  secret_id: z.string().uuid().optional(),
  event_type: auditEventTypeSchema.optional(),
  since: z.number().int().nonnegative().optional(),
  until: z.number().int().nonnegative().optional(),
  limit: z.number().int().positive().max(1000).optional(),
});

// ---------------------------------------------------------------------------
// Session file schema (for deserializing session.json)
// ---------------------------------------------------------------------------

const base64Pattern = z.string().min(1);

export const sessionFileSchema = z.object({
  version: z.literal(1),
  session_id: z.string().min(1),
  vault_id: z.string().min(1),
  created_at: z.number().int().positive(),
  expires_at: z.number().int().positive(),
  max_expires_at: z.number().int().positive(),
  session_key: base64Pattern,
  wrapped_kek: base64Pattern,
  wrapped_kek_iv: base64Pattern,
  wrapped_kek_tag: base64Pattern,
  wrapped_jwt_key: base64Pattern,
  wrapped_jwt_key_iv: base64Pattern,
  wrapped_jwt_key_tag: base64Pattern,
});
