import { describe, expect, it } from "vitest";

import { ErrorCode, VaultError } from "./errors.js";
import { formatHandle, isValidHandle, isValidName, parseHandle } from "./handle.js";

describe("isValidHandle", () => {
  it.each([
    "secret://github-token",
    "secret://my-api/github-token",
    "secret://a",
    "secret://proj/a",
    "secret://my_key-1",
    "secret://Proj-2/My_Key",
  ])("accepts valid handle: %s", (h) => {
    expect(isValidHandle(h)).toBe(true);
  });

  it.each([
    "",
    "github-token",
    "secret://",
    "secret:///name",
    "secret://a/b/c",
    "secret://has space",
    "secret://has.dot",
    "secret://proj/na me",
    "http://github-token",
    "secret://proj//name",
    "secret://na!me",
    "secret://name/",
  ])("rejects invalid handle: %s", (h) => {
    expect(isValidHandle(h)).toBe(false);
  });
});

describe("isValidName", () => {
  it("accepts alphanumeric with hyphens and underscores", () => {
    expect(isValidName("github-token")).toBe(true);
    expect(isValidName("my_key_1")).toBe(true);
    expect(isValidName("A")).toBe(true);
  });

  it("rejects invalid names", () => {
    expect(isValidName("")).toBe(false);
    expect(isValidName("has space")).toBe(false);
    expect(isValidName("has.dot")).toBe(false);
  });
});

describe("parseHandle", () => {
  it("parses simple handle (no project)", () => {
    const result = parseHandle("secret://github-token");
    expect(result).toEqual({ name: "github-token" });
    expect(result.project).toBeUndefined();
  });

  it("parses handle with project", () => {
    const result = parseHandle("secret://my-api/github-token");
    expect(result).toEqual({ name: "github-token", project: "my-api" });
  });

  it("throws VaultError with INVALID_HANDLE for invalid input", () => {
    expect.assertions(3);
    expect(() => parseHandle("not-a-handle")).toThrow(VaultError);
    try {
      parseHandle("bad://handle");
    } catch (e) {
      expect(e).toBeInstanceOf(VaultError);
      expect((e as VaultError).code).toBe(ErrorCode.INVALID_HANDLE);
    }
  });

  it("throws for empty string", () => {
    expect(() => parseHandle("")).toThrow(VaultError);
  });

  it("throws for too many segments", () => {
    expect(() => parseHandle("secret://a/b/c")).toThrow(VaultError);
  });
});

describe("formatHandle", () => {
  it("formats name-only handle", () => {
    expect(formatHandle("github-token")).toBe("secret://github-token");
  });

  it("formats handle with project", () => {
    expect(formatHandle("github-token", "my-api")).toBe("secret://my-api/github-token");
  });

  it("throws for invalid name", () => {
    expect.assertions(2);
    expect(() => formatHandle("bad name")).toThrow(VaultError);
    try {
      formatHandle("bad.name");
    } catch (e) {
      expect((e as VaultError).code).toBe(ErrorCode.INVALID_SECRET_NAME);
    }
  });

  it("throws for invalid project name", () => {
    expect.assertions(2);
    expect(() => formatHandle("name", "bad project")).toThrow(VaultError);
    try {
      formatHandle("name", "bad.project");
    } catch (e) {
      expect((e as VaultError).code).toBe(ErrorCode.INVALID_PROJECT_NAME);
    }
  });
});

describe("handle edge cases", () => {
  it("formatHandle with empty string project throws INVALID_PROJECT_NAME", () => {
    expect.assertions(2);
    expect(() => formatHandle("name", "")).toThrow(VaultError);
    try {
      formatHandle("name", "");
    } catch (e) {
      expect((e as VaultError).code).toBe(ErrorCode.INVALID_PROJECT_NAME);
    }
  });

  it("rejects Unicode characters in handle", () => {
    expect(isValidHandle("secret://café")).toBe(false);
  });

  it("parseHandle preserves casing", () => {
    const result = parseHandle("secret://MyApi/GitHub-Token");
    expect(result).toEqual({ project: "MyApi", name: "GitHub-Token" });
  });

  it("isValidName rejects name longer than 255 characters", () => {
    expect(isValidName("a".repeat(256))).toBe(false);
  });

  it("isValidName accepts name of exactly 255 characters", () => {
    expect(isValidName("a".repeat(255))).toBe(true);
  });

  it("formatHandle rejects name longer than 255 characters", () => {
    expect(() => formatHandle("a".repeat(256))).toThrow(VaultError);
  });

  it("accepts very long handle (isValidHandle has no name length limit)", () => {
    const longName = "a".repeat(500);
    expect(isValidHandle(`secret://${longName}`)).toBe(true);
  });
});

describe("roundtrip", () => {
  it("parseHandle(formatHandle(name)) === { name }", () => {
    expect(parseHandle(formatHandle("my-key"))).toEqual({ name: "my-key" });
  });

  it("parseHandle(formatHandle(name, project)) === { name, project }", () => {
    expect(parseHandle(formatHandle("my-key", "proj"))).toEqual({
      name: "my-key",
      project: "proj",
    });
  });
});
