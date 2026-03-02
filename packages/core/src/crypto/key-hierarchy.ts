import {
  AAD_DEK_WRAP,
  AAD_NAME_ENCRYPTION,
  AAD_SECRET_PAYLOAD,
  AAD_VAULT_KEK,
  AES_KEY_LENGTH,
  HKDF_INFO_AUDIT,
  HKDF_INFO_JWT_SIGNING,
} from "@harpoc/shared";
import { decrypt, encrypt } from "./aes-gcm.js";
import { deriveKey, generateSalt } from "./argon2.js";
import { deriveSubkey } from "./hkdf.js";
import { generateRandomBytes, generateUUIDv7, wipeBuffer } from "./random.js";

/** Result of creating a new vault. */
export interface VaultKeys {
  salt: Uint8Array;
  wrappedKek: Uint8Array;
  wrappedKekIv: Uint8Array;
  wrappedKekTag: Uint8Array;
  kek: Uint8Array;
  jwtKey: Uint8Array;
  auditKey: Uint8Array;
  vaultId: string;
}

/** Result of unlocking a vault. */
export interface UnlockedKeys {
  kek: Uint8Array;
  jwtKey: Uint8Array;
  auditKey: Uint8Array;
}

/** Wrapped DEK result. */
export interface WrappedDek {
  wrappedDek: Uint8Array;
  dekIv: Uint8Array;
  dekTag: Uint8Array;
}

/** Encrypted value result. */
export interface EncryptedValue {
  ciphertext: Uint8Array;
  iv: Uint8Array;
  tag: Uint8Array;
}

/**
 * Create a new vault: generate KEK, wrap it with master key, derive JWT/audit keys.
 */
export async function createVaultKeys(password: string): Promise<VaultKeys> {
  const salt = generateSalt();
  const masterKey = await deriveKey(password, salt);

  try {
    // Generate random KEK
    const kek = generateRandomBytes(AES_KEY_LENGTH);

    // Wrap KEK with master key
    const { ciphertext: wrappedKek, iv: wrappedKekIv, tag: wrappedKekTag } =
      encrypt(masterKey, kek, AAD_VAULT_KEK);

    // Generate vault ID
    const vaultId = generateUUIDv7();

    // Derive JWT and audit keys via HKDF
    const jwtKey = await deriveSubkey(masterKey, vaultId, HKDF_INFO_JWT_SIGNING);
    const auditKey = await deriveSubkey(masterKey, vaultId, HKDF_INFO_AUDIT);

    return { salt, wrappedKek, wrappedKekIv, wrappedKekTag, kek, jwtKey, auditKey, vaultId };
  } finally {
    wipeBuffer(masterKey);
  }
}

/**
 * Unlock vault: derive master key from password, unwrap KEK, derive JWT/audit keys.
 */
export async function unlockVault(
  password: string,
  salt: Uint8Array,
  wrappedKek: Uint8Array,
  wrappedKekIv: Uint8Array,
  wrappedKekTag: Uint8Array,
  vaultId: string,
): Promise<UnlockedKeys> {
  const masterKey = await deriveKey(password, salt);

  try {
    const kek = decrypt(masterKey, wrappedKek, wrappedKekIv, wrappedKekTag, AAD_VAULT_KEK);
    const jwtKey = await deriveSubkey(masterKey, vaultId, HKDF_INFO_JWT_SIGNING);
    const auditKey = await deriveSubkey(masterKey, vaultId, HKDF_INFO_AUDIT);

    return { kek, jwtKey, auditKey };
  } finally {
    wipeBuffer(masterKey);
  }
}

/**
 * Wrap a per-secret DEK with the vault KEK.
 */
export function wrapDek(kek: Uint8Array, dek: Uint8Array, secretId: string): WrappedDek {
  const { ciphertext: wrappedDek, iv: dekIv, tag: dekTag } =
    encrypt(kek, dek, AAD_DEK_WRAP(secretId));
  return { wrappedDek, dekIv, dekTag };
}

/**
 * Unwrap a per-secret DEK with the vault KEK.
 */
export function unwrapDek(
  kek: Uint8Array,
  wrappedDek: Uint8Array,
  dekIv: Uint8Array,
  dekTag: Uint8Array,
  secretId: string,
): Uint8Array {
  return decrypt(kek, wrappedDek, dekIv, dekTag, AAD_DEK_WRAP(secretId));
}

/**
 * Encrypt a secret value with its DEK.
 */
export function encryptSecretValue(
  dek: Uint8Array,
  plaintext: Uint8Array,
  secretId: string,
  version: number,
): EncryptedValue {
  const { ciphertext, iv, tag } =
    encrypt(dek, plaintext, AAD_SECRET_PAYLOAD(secretId, version));
  return { ciphertext, iv, tag };
}

/**
 * Decrypt a secret value with its DEK.
 */
export function decryptSecretValue(
  dek: Uint8Array,
  ciphertext: Uint8Array,
  iv: Uint8Array,
  tag: Uint8Array,
  secretId: string,
  version: number,
): Uint8Array {
  return decrypt(dek, ciphertext, iv, tag, AAD_SECRET_PAYLOAD(secretId, version));
}

/**
 * Encrypt a secret name with the vault KEK (not per-secret DEK).
 */
export function encryptName(
  kek: Uint8Array,
  name: string,
  secretId: string,
): EncryptedValue {
  const plaintext = new Uint8Array(Buffer.from(name, "utf8"));
  const { ciphertext, iv, tag } = encrypt(kek, plaintext, AAD_NAME_ENCRYPTION(secretId));
  return { ciphertext, iv, tag };
}

/**
 * Decrypt a secret name with the vault KEK.
 */
export function decryptName(
  kek: Uint8Array,
  ciphertext: Uint8Array,
  iv: Uint8Array,
  tag: Uint8Array,
  secretId: string,
): string {
  const plaintext = decrypt(kek, ciphertext, iv, tag, AAD_NAME_ENCRYPTION(secretId));
  return Buffer.from(plaintext).toString("utf8");
}

/**
 * Change vault password: re-wraps KEK with new master key. O(1) — no DEKs/ciphertexts touched.
 */
export async function changePassword(
  oldPassword: string,
  newPassword: string,
  salt: Uint8Array,
  wrappedKek: Uint8Array,
  wrappedKekIv: Uint8Array,
  wrappedKekTag: Uint8Array,
  vaultId: string,
): Promise<{
  newSalt: Uint8Array;
  newWrappedKek: Uint8Array;
  newWrappedKekIv: Uint8Array;
  newWrappedKekTag: Uint8Array;
  jwtKey: Uint8Array;
  auditKey: Uint8Array;
}> {
  // Unwrap KEK with old password
  const oldMasterKey = await deriveKey(oldPassword, salt);
  let kek: Uint8Array;

  try {
    kek = decrypt(oldMasterKey, wrappedKek, wrappedKekIv, wrappedKekTag, AAD_VAULT_KEK);
  } finally {
    wipeBuffer(oldMasterKey);
  }

  // Re-wrap KEK with new password
  const newSalt = generateSalt();
  const newMasterKey = await deriveKey(newPassword, newSalt);

  try {
    const {
      ciphertext: newWrappedKek,
      iv: newWrappedKekIv,
      tag: newWrappedKekTag,
    } = encrypt(newMasterKey, kek, AAD_VAULT_KEK);

    const jwtKey = await deriveSubkey(newMasterKey, vaultId, HKDF_INFO_JWT_SIGNING);
    const auditKey = await deriveSubkey(newMasterKey, vaultId, HKDF_INFO_AUDIT);

    return { newSalt, newWrappedKek, newWrappedKekIv, newWrappedKekTag, jwtKey, auditKey };
  } finally {
    wipeBuffer(newMasterKey);
    wipeBuffer(kek);
  }
}
