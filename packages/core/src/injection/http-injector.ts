import type {
  FollowRedirects,
  HttpMethod,
  InjectionConfig,
  UseSecretResponse,
} from "@harpoc/shared";
import {
  DEFAULT_HTTP_TIMEOUT_MS,
  ErrorCode,
  VaultError,
} from "@harpoc/shared";
import type { AuditLogger } from "../audit/audit-logger.js";
import { validateUrl } from "./url-validator.js";

export interface HttpInjectorRequest {
  method: HttpMethod;
  url: string;
  headers?: Record<string, string>;
  body?: string;
  timeoutMs?: number;
}

/**
 * Executes HTTP requests with injected credentials.
 * The secret value is injected at the execution layer and never returned to the LLM.
 */
export class HttpInjector {
  constructor(private readonly auditLogger: AuditLogger | null) {}

  async executeWithSecret(
    request: HttpInjectorRequest,
    secretValue: Uint8Array,
    injection: InjectionConfig,
    followRedirects: FollowRedirects = "same-origin",
    secretId?: string,
  ): Promise<UseSecretResponse> {
    // Validate URL
    const url = validateUrl(request.url);

    // Build headers
    const headers: Record<string, string> = { ...request.headers };
    const valueStr = Buffer.from(secretValue).toString("utf8");

    // Inject credential
    let finalUrl = url.toString();
    switch (injection.type) {
      case "bearer":
        headers["Authorization"] = `Bearer ${valueStr}`;
        break;
      case "basic_auth":
        headers["Authorization"] = `Basic ${Buffer.from(valueStr).toString("base64")}`;
        break;
      case "header":
        if (!injection.header_name) {
          throw new VaultError(ErrorCode.INVALID_INJECTION_CONFIG, "header_name required for header injection");
        }
        headers[injection.header_name] = valueStr;
        break;
      case "query":
        if (!injection.query_param) {
          throw new VaultError(ErrorCode.INVALID_INJECTION_CONFIG, "query_param required for query injection");
        }
        url.searchParams.set(injection.query_param, valueStr);
        finalUrl = url.toString();
        break;
    }

    const timeoutMs = request.timeoutMs ?? DEFAULT_HTTP_TIMEOUT_MS;

    try {
      const response = await this.fetchWithRedirects(
        finalUrl,
        request.method,
        headers,
        request.body,
        timeoutMs,
        followRedirects,
      );

      this.auditLogger?.log({
        eventType: "secret.use",
        secretId,
        detail: {
          method: request.method,
          url: request.url,
          status: response.status,
          injection_type: injection.type,
        },
      });

      return response;
    } catch (err) {
      if (err instanceof VaultError) {
        this.auditLogger?.log({
          eventType: "secret.use",
          secretId,
          detail: {
            method: request.method,
            url: request.url,
            error: err.code,
            injection_type: injection.type,
          },
          success: false,
        });
        throw err;
      }

      const errorCode = this.classifyFetchError(err);

      this.auditLogger?.log({
        eventType: "secret.use",
        secretId,
        detail: {
          method: request.method,
          url: request.url,
          error: errorCode,
          injection_type: injection.type,
        },
        success: false,
      });

      return {
        status: null,
        error: errorCode,
      };
    }
  }

  private async fetchWithRedirects(
    url: string,
    method: HttpMethod,
    headers: Record<string, string>,
    body: string | undefined,
    timeoutMs: number,
    followRedirects: FollowRedirects,
  ): Promise<UseSecretResponse> {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), timeoutMs);

    try {
      const response = await fetch(url, {
        method,
        headers,
        body: body ?? null,
        signal: controller.signal,
        redirect: followRedirects === "none" ? "manual" : "manual",
      });

      // Handle redirects
      if (response.status >= 300 && response.status < 400) {
        const location = response.headers.get("location");

        if (followRedirects === "none" || !location) {
          return this.buildResponse(response);
        }

        // Resolve redirect URL
        const redirectUrl = new URL(location, url);

        if (followRedirects === "same-origin") {
          const originalUrl = new URL(url);
          if (
            redirectUrl.protocol !== originalUrl.protocol ||
            redirectUrl.hostname !== originalUrl.hostname ||
            redirectUrl.port !== originalUrl.port
          ) {
            // Cross-origin: strip credentials, add warning
            const cleanHeaders = { ...headers };
            delete cleanHeaders["Authorization"];

            // Remove injected query params too (best effort)
            const result = await this.fetchSimple(
              redirectUrl.toString(),
              method,
              cleanHeaders,
              body,
              timeoutMs,
              controller.signal,
            );
            return {
              ...result,
              redirect_warning: `Cross-origin redirect to ${redirectUrl.origin} — credentials stripped`,
            };
          }
        }

        // Validate redirect target
        try {
          validateUrl(redirectUrl.toString());
        } catch {
          throw new VaultError(
            ErrorCode.REDIRECT_POLICY_VIOLATION,
            `Redirect target blocked: ${redirectUrl.toString()}`,
          );
        }

        // Follow redirect
        return this.fetchSimple(
          redirectUrl.toString(),
          method,
          headers,
          body,
          timeoutMs,
          controller.signal,
        );
      }

      return this.buildResponse(response);
    } finally {
      clearTimeout(timeout);
    }
  }

  private async fetchSimple(
    url: string,
    method: HttpMethod,
    headers: Record<string, string>,
    body: string | undefined,
    timeoutMs: number,
    signal: AbortSignal,
  ): Promise<UseSecretResponse> {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), timeoutMs);

    // If parent signal is aborted, abort this too
    if (signal.aborted) {
      controller.abort();
    }
    signal.addEventListener("abort", () => controller.abort());

    try {
      const response = await fetch(url, {
        method,
        headers,
        body: body ?? null,
        signal: controller.signal,
        redirect: "follow",
      });

      return this.buildResponse(response);
    } finally {
      clearTimeout(timeout);
    }
  }

  private async buildResponse(response: Response): Promise<UseSecretResponse> {
    const responseHeaders: Record<string, string> = {};
    response.headers.forEach((value, key) => {
      responseHeaders[key] = value;
    });

    let body: string | undefined;
    try {
      body = await response.text();
    } catch {
      body = undefined;
    }

    return {
      status: response.status,
      headers: responseHeaders,
      body,
    };
  }

  private classifyFetchError(err: unknown): string {
    if (!(err instanceof Error)) return ErrorCode.INTERNAL_ERROR;

    // Node's fetch wraps the real error in `cause`
    const cause = (err as { cause?: Error }).cause;
    const message = err.message.toLowerCase();
    const causeMessage = cause?.message?.toLowerCase() ?? "";
    const causeCode = ((cause as { code?: string })?.code ?? "").toLowerCase();
    const combined = `${message} ${causeMessage} ${causeCode}`;

    if (err.name === "AbortError" || combined.includes("abort") || combined.includes("timeout")) {
      return ErrorCode.TIMEOUT;
    }
    if (combined.includes("enotfound") || combined.includes("getaddrinfo") || combined.includes("dns")) {
      return ErrorCode.DNS_RESOLUTION_FAILED;
    }
    if (combined.includes("econnrefused") || combined.includes("connection refused")) {
      return ErrorCode.CONNECTION_REFUSED;
    }
    if (
      combined.includes("tls") ||
      combined.includes("ssl") ||
      combined.includes("certificate") ||
      combined.includes("cert_")
    ) {
      return ErrorCode.TLS_ERROR;
    }

    return ErrorCode.INTERNAL_ERROR;
  }
}
