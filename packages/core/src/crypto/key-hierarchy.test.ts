import { describe, expect, it } from "vitest";
import { AES_KEY_LENGTH, ErrorCode, VaultError } from "@harpoc/shared";
import {
  changePassword,
  createVaultKeys,
  decryptName,
  decryptSecretValue,
  encryptName,
  encryptSecretValue,
  unlockVault,
  unwrapDek,
  wrapDek,
} from "./key-hierarchy.js";
import { generateRandomBytes } from "./random.js";

describe("createVaultKeys", () => {
  it("returns all required vault keys", async () => {
    const keys = await createVaultKeys("test-password");

    expect(keys.salt).toBeInstanceOf(Uint8Array);
    expect(keys.salt.length).toBe(16);
    expect(keys.wrappedKek).toBeInstanceOf(Uint8Array);
    expect(keys.wrappedKekIv.length).toBe(12);
    expect(keys.wrappedKekTag.length).toBe(16);
    expect(keys.kek).toBeInstanceOf(Uint8Array);
    expect(keys.kek.length).toBe(AES_KEY_LENGTH);
    expect(keys.jwtKey).toBeInstanceOf(Uint8Array);
    expect(keys.jwtKey.length).toBe(AES_KEY_LENGTH);
    expect(keys.auditKey).toBeInstanceOf(Uint8Array);
    expect(keys.auditKey.length).toBe(AES_KEY_LENGTH);
    expect(keys.vaultId).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
    );
  });
});

describe("unlockVault", () => {
  it("recovers KEK, JWT key, and audit key", async () => {
    const password = "my-secure-password";
    const created = await createVaultKeys(password);

    const unlocked = await unlockVault(
      password,
      created.salt,
      created.wrappedKek,
      created.wrappedKekIv,
      created.wrappedKekTag,
      created.vaultId,
    );

    expect(Buffer.from(unlocked.kek).equals(Buffer.from(created.kek))).toBe(true);
    expect(Buffer.from(unlocked.jwtKey).equals(Buffer.from(created.jwtKey))).toBe(true);
    expect(Buffer.from(unlocked.auditKey).equals(Buffer.from(created.auditKey))).toBe(true);
  });

  it("fails with wrong password", async () => {
    const created = await createVaultKeys("correct-password");

    await expect(
      unlockVault(
        "wrong-password",
        created.salt,
        created.wrappedKek,
        created.wrappedKekIv,
        created.wrappedKekTag,
        created.vaultId,
      ),
    ).rejects.toThrow(VaultError);

    try {
      await unlockVault(
        "wrong-password",
        created.salt,
        created.wrappedKek,
        created.wrappedKekIv,
        created.wrappedKekTag,
        created.vaultId,
      );
    } catch (e) {
      expect(e).toBeInstanceOf(VaultError);
      expect((e as VaultError).code).toBe(ErrorCode.ENCRYPTION_ERROR);
    }
  });

  it("different vaultIds produce different derived keys", async () => {
    const password = "test-pw";
    const keys1 = await createVaultKeys(password);
    const keys2 = await createVaultKeys(password);

    // JWT keys should differ because vaultId differs
    expect(Buffer.from(keys1.jwtKey).equals(Buffer.from(keys2.jwtKey))).toBe(false);
    expect(Buffer.from(keys1.auditKey).equals(Buffer.from(keys2.auditKey))).toBe(false);
  });
});

describe("wrapDek / unwrapDek", () => {
  it("roundtrips a DEK", async () => {
    const created = await createVaultKeys("password");
    const dek = generateRandomBytes(AES_KEY_LENGTH);
    const secretId = "test-secret-id";

    const wrapped = wrapDek(created.kek, dek, secretId);
    const unwrapped = unwrapDek(
      created.kek,
      wrapped.wrappedDek,
      wrapped.dekIv,
      wrapped.dekTag,
      secretId,
    );

    expect(Buffer.from(unwrapped).equals(Buffer.from(dek))).toBe(true);
  });

  it("fails with wrong secretId (AAD mismatch)", async () => {
    const created = await createVaultKeys("password");
    const dek = generateRandomBytes(AES_KEY_LENGTH);

    const wrapped = wrapDek(created.kek, dek, "secret-1");

    expect(() =>
      unwrapDek(created.kek, wrapped.wrappedDek, wrapped.dekIv, wrapped.dekTag, "secret-2"),
    ).toThrow("decryption failed");
  });
});

describe("encryptSecretValue / decryptSecretValue", () => {
  it("roundtrips a secret value", () => {
    const dek = generateRandomBytes(AES_KEY_LENGTH);
    const plaintext = new Uint8Array(Buffer.from("api-key-12345"));
    const secretId = "s1";

    const encrypted = encryptSecretValue(dek, plaintext, secretId, 1);
    const decrypted = decryptSecretValue(
      dek,
      encrypted.ciphertext,
      encrypted.iv,
      encrypted.tag,
      secretId,
      1,
    );

    expect(Buffer.from(decrypted).toString()).toBe("api-key-12345");
  });

  it("fails with wrong version (AAD mismatch)", () => {
    const dek = generateRandomBytes(AES_KEY_LENGTH);
    const plaintext = new Uint8Array(Buffer.from("data"));

    const encrypted = encryptSecretValue(dek, plaintext, "s1", 1);

    expect(() =>
      decryptSecretValue(dek, encrypted.ciphertext, encrypted.iv, encrypted.tag, "s1", 2),
    ).toThrow("decryption failed");
  });

  it("fails with wrong secretId", () => {
    const dek = generateRandomBytes(AES_KEY_LENGTH);
    const plaintext = new Uint8Array(Buffer.from("data"));

    const encrypted = encryptSecretValue(dek, plaintext, "s1", 1);

    expect(() =>
      decryptSecretValue(dek, encrypted.ciphertext, encrypted.iv, encrypted.tag, "s2", 1),
    ).toThrow("decryption failed");
  });
});

describe("encryptName / decryptName", () => {
  it("roundtrips a secret name", async () => {
    const created = await createVaultKeys("password");
    const secretId = "test-id";

    const encrypted = encryptName(created.kek, "github-token", secretId);
    const decrypted = decryptName(
      created.kek,
      encrypted.ciphertext,
      encrypted.iv,
      encrypted.tag,
      secretId,
    );

    expect(decrypted).toBe("github-token");
  });

  it("handles unicode names", async () => {
    const created = await createVaultKeys("password");
    const name = "schl\u00fcssel-\ud83d\udd11";

    const encrypted = encryptName(created.kek, name, "id1");
    const decrypted = decryptName(created.kek, encrypted.ciphertext, encrypted.iv, encrypted.tag, "id1");

    expect(decrypted).toBe(name);
  });

  it("fails with wrong secretId (AAD mismatch)", async () => {
    const created = await createVaultKeys("password");

    const encrypted = encryptName(created.kek, "name", "id1");

    expect(() =>
      decryptName(created.kek, encrypted.ciphertext, encrypted.iv, encrypted.tag, "id2"),
    ).toThrow("decryption failed");
  });
});

describe("changePassword", () => {
  it("re-wraps KEK with new password", async () => {
    const oldPassword = "old-pass";
    const newPassword = "new-pass";
    const created = await createVaultKeys(oldPassword);

    const changed = await changePassword(
      oldPassword,
      newPassword,
      created.salt,
      created.wrappedKek,
      created.wrappedKekIv,
      created.wrappedKekTag,
      created.vaultId,
    );

    // Unlock with new password should work
    const unlocked = await unlockVault(
      newPassword,
      changed.newSalt,
      changed.newWrappedKek,
      changed.newWrappedKekIv,
      changed.newWrappedKekTag,
      created.vaultId,
    );

    // KEK should be the same
    expect(Buffer.from(unlocked.kek).equals(Buffer.from(created.kek))).toBe(true);
  });

  it("old password no longer works after change", async () => {
    const oldPassword = "old-pass";
    const newPassword = "new-pass";
    const created = await createVaultKeys(oldPassword);

    const changed = await changePassword(
      oldPassword,
      newPassword,
      created.salt,
      created.wrappedKek,
      created.wrappedKekIv,
      created.wrappedKekTag,
      created.vaultId,
    );

    await expect(
      unlockVault(
        oldPassword,
        changed.newSalt,
        changed.newWrappedKek,
        changed.newWrappedKekIv,
        changed.newWrappedKekTag,
        created.vaultId,
      ),
    ).rejects.toThrow(VaultError);
  });

  it("fails with wrong old password", async () => {
    const created = await createVaultKeys("correct");

    await expect(
      changePassword(
        "wrong",
        "new",
        created.salt,
        created.wrappedKek,
        created.wrappedKekIv,
        created.wrappedKekTag,
        created.vaultId,
      ),
    ).rejects.toThrow(VaultError);
  });

  it("existing secrets remain decryptable after password change", async () => {
    const oldPassword = "old-pass";
    const newPassword = "new-pass";
    const created = await createVaultKeys(oldPassword);

    // Encrypt something with the KEK
    const dek = generateRandomBytes(AES_KEY_LENGTH);
    const secretId = "my-secret";
    const wrapped = wrapDek(created.kek, dek, secretId);
    const encrypted = encryptSecretValue(dek, new Uint8Array(Buffer.from("secret-value")), secretId, 1);

    // Change password
    const changed = await changePassword(
      oldPassword,
      newPassword,
      created.salt,
      created.wrappedKek,
      created.wrappedKekIv,
      created.wrappedKekTag,
      created.vaultId,
    );

    // Unlock with new password
    const unlocked = await unlockVault(
      newPassword,
      changed.newSalt,
      changed.newWrappedKek,
      changed.newWrappedKekIv,
      changed.newWrappedKekTag,
      created.vaultId,
    );

    // Unwrap DEK with recovered KEK
    const recoveredDek = unwrapDek(
      unlocked.kek,
      wrapped.wrappedDek,
      wrapped.dekIv,
      wrapped.dekTag,
      secretId,
    );

    // Decrypt secret
    const decrypted = decryptSecretValue(
      recoveredDek,
      encrypted.ciphertext,
      encrypted.iv,
      encrypted.tag,
      secretId,
      1,
    );

    expect(Buffer.from(decrypted).toString()).toBe("secret-value");
  });
});

describe("full key hierarchy lifecycle", () => {
  it("creates vault, unlocks, wraps DEK, encrypts name+value, decrypts all", async () => {
    // Create vault
    const vault = await createVaultKeys("vault-password");

    // Unlock vault
    const unlocked = await unlockVault(
      "vault-password",
      vault.salt,
      vault.wrappedKek,
      vault.wrappedKekIv,
      vault.wrappedKekTag,
      vault.vaultId,
    );

    // Create a secret with its own DEK
    const dek = generateRandomBytes(AES_KEY_LENGTH);
    const secretId = "secret-123";

    // Wrap DEK
    const wrapped = wrapDek(unlocked.kek, dek, secretId);

    // Encrypt name with KEK
    const nameEnc = encryptName(unlocked.kek, "api-key", secretId);

    // Encrypt value with DEK
    const valueEnc = encryptSecretValue(
      dek,
      new Uint8Array(Buffer.from("sk-1234567890")),
      secretId,
      1,
    );

    // --- Later, recover everything ---

    // Unwrap DEK
    const recoveredDek = unwrapDek(
      unlocked.kek,
      wrapped.wrappedDek,
      wrapped.dekIv,
      wrapped.dekTag,
      secretId,
    );

    // Decrypt name
    const name = decryptName(
      unlocked.kek,
      nameEnc.ciphertext,
      nameEnc.iv,
      nameEnc.tag,
      secretId,
    );
    expect(name).toBe("api-key");

    // Decrypt value
    const value = decryptSecretValue(
      recoveredDek,
      valueEnc.ciphertext,
      valueEnc.iv,
      valueEnc.tag,
      secretId,
      1,
    );
    expect(Buffer.from(value).toString()).toBe("sk-1234567890");
  });
});
