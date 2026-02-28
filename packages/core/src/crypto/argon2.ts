import { randomBytes } from "node:crypto";
import { hash } from "argon2";
import {
  ARGON2_HASH_LENGTH,
  ARGON2_MEMORY_COST,
  ARGON2_PARALLELISM,
  ARGON2_TIME_COST,
  ARGON2_VERSION,
  ErrorCode,
  VaultError,
} from "@harpoc/shared";

const SALT_LENGTH = 16;

/**
 * Generate a random 16-byte salt for Argon2id.
 */
export function generateSalt(): Uint8Array {
  return new Uint8Array(randomBytes(SALT_LENGTH));
}

/**
 * Derive a 256-bit key from a password using Argon2id.
 * Uses OWASP-recommended parameters: 64 MB memory, 3 iterations, 4 parallelism.
 */
export async function deriveKey(password: string, salt: Uint8Array): Promise<Uint8Array> {
  try {
    const result = await hash(password, {
      type: 2, // argon2id
      salt: Buffer.from(salt),
      memoryCost: ARGON2_MEMORY_COST,
      timeCost: ARGON2_TIME_COST,
      parallelism: ARGON2_PARALLELISM,
      hashLength: ARGON2_HASH_LENGTH,
      version: ARGON2_VERSION,
      raw: true,
    });
    return new Uint8Array(result);
  } catch (err) {
    throw new VaultError(
      ErrorCode.KEY_DERIVATION_ERROR,
      `Key derivation failed: ${err instanceof Error ? err.message : "unknown error"}`,
    );
  }
}
