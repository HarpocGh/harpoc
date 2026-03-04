import type {
  AccessPolicy,
  CreateSecretResponse,
  FollowRedirects,
  HttpMethod,
  InjectionConfig,
  Permission,
  PrincipalType,
  SecretType,
  UseSecretResponse,
  VaultState,
} from "@harpoc/shared";
import type { AuditQueryOptions, DecryptedAuditEvent, SecretInfo } from "@harpoc/core";

export interface CreateSecretInput {
  name: string;
  type: SecretType;
  project?: string;
  value?: Uint8Array;
  injection?: InjectionConfig;
  expiresAt?: number;
}

export interface UseSecretInput {
  request: {
    method: HttpMethod;
    url: string;
    headers?: Record<string, string>;
    body?: string;
    timeoutMs?: number;
  };
  injection: InjectionConfig;
  followRedirects?: FollowRedirects;
}

export interface GrantPolicyInput {
  principalType: PrincipalType;
  principalId: string;
  permissions: Permission[];
  expiresAt?: number;
}

export interface HealthResponse {
  state: VaultState;
  version: string;
}

export interface VaultClient {
  listSecrets(project?: string): Promise<SecretInfo[]>;
  getSecretInfo(handle: string): Promise<SecretInfo>;
  getSecretValue(handle: string): Promise<Uint8Array>;
  createSecret(input: CreateSecretInput): Promise<CreateSecretResponse>;
  rotateSecret(handle: string, newValue: Uint8Array): Promise<void>;
  revokeSecret(handle: string): Promise<void>;
  useSecret(handle: string, input: UseSecretInput): Promise<UseSecretResponse>;
  grantPolicy(handle: string, input: GrantPolicyInput): Promise<AccessPolicy>;
  revokePolicy(handle: string, policyId: string): Promise<void>;
  listPolicies(handle: string): Promise<AccessPolicy[]>;
  queryAudit(options?: AuditQueryOptions): Promise<DecryptedAuditEvent[]>;
  getHealth(): Promise<HealthResponse>;
}
