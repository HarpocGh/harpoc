import { ErrorCode, VaultError } from "@harpoc/shared";

const LOOPBACK_HOSTS = new Set(["localhost", "127.0.0.1", "::1", "[::1]"]);

/** RFC 1918 and link-local IPv4 ranges. */
const PRIVATE_IPV4_RANGES: [number, number, number][] = [
  // 10.0.0.0/8
  [10, 0, 8],
  // 172.16.0.0/12
  [172, 16, 12],
  // 192.168.0.0/16
  [192, 168, 16],
  // 169.254.0.0/16 (link-local)
  [169, 254, 16],
];

/**
 * Check if an IPv4 address is in a private range.
 */
export function isPrivateIp(ip: string): boolean {
  // IPv4
  const parts = ip.split(".");
  if (parts.length === 4) {
    const octets = parts.map(Number);
    if (octets.some((o) => isNaN(o) || o < 0 || o > 255)) return false;

    for (const [prefix0, prefix1, cidr] of PRIVATE_IPV4_RANGES) {
      if (cidr === 8 && octets[0] === prefix0) return true;
      if (cidr === 12 && octets[0] === prefix0 && (octets[1] ?? 0) >= prefix1 && (octets[1] ?? 0) <= prefix1 + 15) return true;
      if (cidr === 16 && octets[0] === prefix0 && octets[1] === prefix1) return true;
    }

    // Loopback 127.0.0.0/8
    if (octets[0] === 127) return true;

    return false;
  }

  // IPv6 ULA fc00::/7 and loopback ::1
  const normalized = ip.replace(/^\[|\]$/g, "").toLowerCase();
  if (normalized === "::1") return true;
  if (normalized.startsWith("fc") || normalized.startsWith("fd")) return true;
  if (normalized.startsWith("fe80")) return true; // link-local

  return false;
}

/**
 * Check if a hostname is a loopback address.
 */
export function isLoopback(hostname: string): boolean {
  return LOOPBACK_HOSTS.has(hostname.toLowerCase());
}

/**
 * Validate a URL for use in secret injection.
 *
 * Rules:
 * - Must be a valid URL
 * - Must use HTTPS (exception: HTTP for loopback)
 * - Must not target private/internal IP ranges (SSRF prevention)
 */
export function validateUrl(urlStr: string): URL {
  let url: URL;
  try {
    url = new URL(urlStr);
  } catch {
    throw new VaultError(ErrorCode.URL_INVALID, `Invalid URL: ${urlStr}`);
  }

  const hostname = url.hostname;

  // Scheme check
  if (url.protocol === "http:") {
    if (!isLoopback(hostname)) {
      throw new VaultError(
        ErrorCode.URL_HTTPS_REQUIRED,
        "HTTP is only allowed for loopback addresses (localhost, 127.0.0.1, ::1)",
      );
    }
  } else if (url.protocol !== "https:") {
    throw new VaultError(
      ErrorCode.URL_HTTPS_REQUIRED,
      `Only HTTPS URLs are allowed, got ${url.protocol}`,
    );
  }

  // SSRF check — skip for loopback
  if (!isLoopback(hostname) && isPrivateIp(hostname)) {
    throw new VaultError(
      ErrorCode.SSRF_BLOCKED,
      `SSRF blocked: ${hostname} resolves to a private/internal IP address`,
    );
  }

  return url;
}
