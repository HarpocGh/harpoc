import { randomBytes } from "node:crypto";
import { describe, expect, it } from "vitest";
import { AES_KEY_LENGTH } from "@harpoc/shared";
import { decrypt, encrypt } from "./aes-gcm.js";

const validKey = new Uint8Array(randomBytes(AES_KEY_LENGTH));
const aad = "test-aad";

describe("encrypt", () => {
  it("returns ciphertext, iv, and tag", () => {
    const plaintext = new Uint8Array(Buffer.from("hello world"));
    const result = encrypt(validKey, plaintext, aad);

    expect(result.ciphertext).toBeInstanceOf(Uint8Array);
    expect(result.iv).toBeInstanceOf(Uint8Array);
    expect(result.tag).toBeInstanceOf(Uint8Array);
    expect(result.iv.length).toBe(12);
    expect(result.tag.length).toBe(16);
  });

  it("produces different ciphertext for the same plaintext (fresh IV)", () => {
    const plaintext = new Uint8Array(Buffer.from("same input"));
    const r1 = encrypt(validKey, plaintext, aad);
    const r2 = encrypt(validKey, plaintext, aad);

    expect(Buffer.from(r1.iv).equals(Buffer.from(r2.iv))).toBe(false);
    expect(Buffer.from(r1.ciphertext).equals(Buffer.from(r2.ciphertext))).toBe(false);
  });

  it("rejects a key that is not 32 bytes", () => {
    const shortKey = new Uint8Array(16);
    const plaintext = new Uint8Array(Buffer.from("data"));

    expect(() => encrypt(shortKey, plaintext, aad)).toThrow("AES key must be 32 bytes");
  });

  it("handles empty plaintext", () => {
    const result = encrypt(validKey, new Uint8Array(0), aad);
    expect(result.ciphertext.length).toBe(0);
    expect(result.tag.length).toBe(16);
  });
});

describe("decrypt", () => {
  it("roundtrips correctly", () => {
    const plaintext = new Uint8Array(Buffer.from("secret data 123"));
    const { ciphertext, iv, tag } = encrypt(validKey, plaintext, aad);
    const result = decrypt(validKey, ciphertext, iv, tag, aad);

    expect(Buffer.from(result).toString()).toBe("secret data 123");
  });

  it("roundtrips empty plaintext", () => {
    const plaintext = new Uint8Array(0);
    const { ciphertext, iv, tag } = encrypt(validKey, plaintext, aad);
    const result = decrypt(validKey, ciphertext, iv, tag, aad);
    expect(result.length).toBe(0);
  });

  it("fails with wrong key", () => {
    const plaintext = new Uint8Array(Buffer.from("data"));
    const { ciphertext, iv, tag } = encrypt(validKey, plaintext, aad);

    const wrongKey = new Uint8Array(randomBytes(AES_KEY_LENGTH));
    expect(() => decrypt(wrongKey, ciphertext, iv, tag, aad)).toThrow("decryption failed");
  });

  it("fails with wrong AAD", () => {
    const plaintext = new Uint8Array(Buffer.from("data"));
    const { ciphertext, iv, tag } = encrypt(validKey, plaintext, aad);

    expect(() => decrypt(validKey, ciphertext, iv, tag, "wrong-aad")).toThrow("decryption failed");
  });

  it("fails with tampered ciphertext", () => {
    const plaintext = new Uint8Array(Buffer.from("data"));
    const { ciphertext, iv, tag } = encrypt(validKey, plaintext, aad);

    const tampered = new Uint8Array(ciphertext);
    tampered[0] = (tampered[0] ?? 0) ^ 0xff;

    expect(() => decrypt(validKey, tampered, iv, tag, aad)).toThrow("decryption failed");
  });

  it("fails with tampered tag", () => {
    const plaintext = new Uint8Array(Buffer.from("data"));
    const { ciphertext, iv, tag } = encrypt(validKey, plaintext, aad);

    const tamperedTag = new Uint8Array(tag);
    tamperedTag[0] = (tamperedTag[0] ?? 0) ^ 0xff;

    expect(() => decrypt(validKey, ciphertext, iv, tamperedTag, aad)).toThrow("decryption failed");
  });

  it("rejects invalid key length", () => {
    expect(() =>
      decrypt(new Uint8Array(16), new Uint8Array(10), new Uint8Array(12), new Uint8Array(16), aad),
    ).toThrow("AES key must be 32 bytes");
  });

  it("rejects invalid IV length", () => {
    expect(() =>
      decrypt(validKey, new Uint8Array(10), new Uint8Array(8), new Uint8Array(16), aad),
    ).toThrow("IV must be 12 bytes");
  });

  it("rejects invalid tag length", () => {
    expect(() =>
      decrypt(validKey, new Uint8Array(10), new Uint8Array(12), new Uint8Array(8), aad),
    ).toThrow("Auth tag must be 16 bytes");
  });
});

describe("AAD binding", () => {
  it("different AAD strings produce different ciphertext", () => {
    const plaintext = new Uint8Array(Buffer.from("data"));
    const r1 = encrypt(validKey, plaintext, "aad-1");
    const r2 = encrypt(validKey, plaintext, "aad-2");

    // Decrypt with matching AAD works
    const d1 = decrypt(validKey, r1.ciphertext, r1.iv, r1.tag, "aad-1");
    const d2 = decrypt(validKey, r2.ciphertext, r2.iv, r2.tag, "aad-2");
    expect(Buffer.from(d1).toString()).toBe("data");
    expect(Buffer.from(d2).toString()).toBe("data");

    // Decrypt with swapped AAD fails
    expect(() => decrypt(validKey, r1.ciphertext, r1.iv, r1.tag, "aad-2")).toThrow(
      "decryption failed",
    );
  });
});
