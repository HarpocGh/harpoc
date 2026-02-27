import { ErrorCode, VaultError } from "./errors.js";
import type { ParsedHandle } from "./types.js";

const HANDLE_REGEX = /^secret:\/\/([a-zA-Z0-9_-]+\/)?[a-zA-Z0-9_-]+$/;
const NAME_REGEX = /^[a-zA-Z0-9_-]+$/;

export function isValidHandle(handle: string): boolean {
  return HANDLE_REGEX.test(handle);
}

export function isValidName(name: string): boolean {
  return NAME_REGEX.test(name);
}

export function parseHandle(handle: string): ParsedHandle {
  if (!isValidHandle(handle)) {
    throw new VaultError(ErrorCode.INVALID_HANDLE, `Invalid handle: ${handle}`);
  }

  const path = handle.slice("secret://".length);
  const slashIndex = path.indexOf("/");

  if (slashIndex === -1) {
    return { name: path };
  }

  return {
    project: path.slice(0, slashIndex),
    name: path.slice(slashIndex + 1),
  };
}

export function formatHandle(name: string, project?: string): string {
  if (!isValidName(name)) {
    throw new VaultError(ErrorCode.INVALID_SECRET_NAME, `Invalid secret name: ${name}`);
  }

  if (project !== undefined) {
    if (!isValidName(project)) {
      throw new VaultError(ErrorCode.INVALID_PROJECT_NAME, `Invalid project name: ${project}`);
    }
    return `secret://${project}/${name}`;
  }

  return `secret://${name}`;
}
