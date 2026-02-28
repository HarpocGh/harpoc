import { describe, expect, it } from "vitest";
import { ErrorCode, VaultError } from "@harpoc/shared";
import { isLoopback, isPrivateIp, validateUrl } from "./url-validator.js";

describe("isPrivateIp", () => {
  it.each([
    "10.0.0.1",
    "10.255.255.255",
    "172.16.0.1",
    "172.31.255.255",
    "192.168.0.1",
    "192.168.1.100",
    "169.254.1.1",
    "127.0.0.1",
    "127.255.255.255",
  ])("returns true for private IPv4 %s", (ip) => {
    expect(isPrivateIp(ip)).toBe(true);
  });

  it.each(["8.8.8.8", "1.1.1.1", "203.0.113.1", "172.32.0.1", "11.0.0.1"])(
    "returns false for public IPv4 %s",
    (ip) => {
      expect(isPrivateIp(ip)).toBe(false);
    },
  );

  it("returns true for IPv6 loopback", () => {
    expect(isPrivateIp("::1")).toBe(true);
    expect(isPrivateIp("[::1]")).toBe(true);
  });

  it("returns true for IPv6 ULA", () => {
    expect(isPrivateIp("fc00::1")).toBe(true);
    expect(isPrivateIp("fd12:3456::1")).toBe(true);
  });

  it("returns true for IPv6 link-local", () => {
    expect(isPrivateIp("fe80::1")).toBe(true);
  });

  it("returns false for public IPv6", () => {
    expect(isPrivateIp("2001:db8::1")).toBe(false);
  });
});

describe("isLoopback", () => {
  it.each(["localhost", "127.0.0.1", "::1", "[::1]", "LOCALHOST"])(
    "returns true for %s",
    (host) => {
      expect(isLoopback(host)).toBe(true);
    },
  );

  it.each(["example.com", "10.0.0.1", "192.168.1.1"])("returns false for %s", (host) => {
    expect(isLoopback(host)).toBe(false);
  });
});

describe("validateUrl", () => {
  it("accepts valid HTTPS URLs", () => {
    const url = validateUrl("https://api.example.com/v1/test");
    expect(url.protocol).toBe("https:");
  });

  it("accepts HTTP for localhost", () => {
    const url = validateUrl("http://localhost:3000/api");
    expect(url.protocol).toBe("http:");
  });

  it("accepts HTTP for 127.0.0.1", () => {
    const url = validateUrl("http://127.0.0.1:8080/test");
    expect(url.hostname).toBe("127.0.0.1");
  });

  it("rejects HTTP for non-loopback", () => {
    try {
      validateUrl("http://api.example.com/test");
      expect.fail("Should throw");
    } catch (e) {
      expect((e as VaultError).code).toBe(ErrorCode.URL_HTTPS_REQUIRED);
    }
  });

  it("rejects non-HTTP(S) schemes", () => {
    try {
      validateUrl("ftp://example.com/file");
      expect.fail("Should throw");
    } catch (e) {
      expect((e as VaultError).code).toBe(ErrorCode.URL_HTTPS_REQUIRED);
    }
  });

  it("rejects invalid URLs", () => {
    try {
      validateUrl("not-a-url");
      expect.fail("Should throw");
    } catch (e) {
      expect((e as VaultError).code).toBe(ErrorCode.URL_INVALID);
    }
  });

  it("blocks SSRF for private IPs", () => {
    try {
      validateUrl("https://10.0.0.1/api");
      expect.fail("Should throw");
    } catch (e) {
      expect((e as VaultError).code).toBe(ErrorCode.SSRF_BLOCKED);
    }
  });

  it("blocks SSRF for 192.168.x.x", () => {
    try {
      validateUrl("https://192.168.1.1/api");
      expect.fail("Should throw");
    } catch (e) {
      expect((e as VaultError).code).toBe(ErrorCode.SSRF_BLOCKED);
    }
  });

  it("blocks SSRF for 172.16-31.x.x", () => {
    try {
      validateUrl("https://172.16.0.1/api");
      expect.fail("Should throw");
    } catch (e) {
      expect((e as VaultError).code).toBe(ErrorCode.SSRF_BLOCKED);
    }
  });

  it("allows loopback despite being 'private'", () => {
    expect(() => validateUrl("http://127.0.0.1/test")).not.toThrow();
    expect(() => validateUrl("http://localhost/test")).not.toThrow();
  });
});
