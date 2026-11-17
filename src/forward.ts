import type { Env } from "./env";
import { jsonResponse } from "./http";
import { readEnabledMap } from "./config";
import { resolve, type Resolved } from "./providers";
import { ensureFreshToken, TokenExpiredError } from "./oauth/refresh";

export function providerKey(resolved: Resolved, env: Env): string | undefined {
  return (env as unknown as Record<string, string | undefined>)[resolved.keySecret ?? ""];
}

export class MissingKeyError extends Error {
  constructor(public secret: string) {
    super(
      `Provider key not configured. Set secret ${secret}: npx wrangler secret put ${secret}`,
    );
  }
}

export class MissingTokenError extends Error {
  constructor(public prefix: string) {
    super(
      `OAuth provider '${prefix}' is not connected — connect it in the admin console (/admin).`,
    );
  }
}

export class DisabledProviderError extends Error {
  constructor(public prefix: string) {
    super(
      `Provider '${prefix}' is disabled — re-enable it in the admin console (/admin).`,
    );
  }
}

/**
 * Shared forwarder for chat, messages and fallback paths.
 * `path` is appended to the provider baseURL (e.g. "/chat/completions", "/messages").
 * `clientHeaders` (optional): anthropic-* client headers are forwarded except the
 * ones this gateway sets itself (x-api-key, anthropic-version) — keeps Claude Code
 * beta features (prompt caching etc.) working.
 * Returns the upstream Response untouched (status, headers, stream body).
 * Throws MissingKeyError when the provider secret is not configured —
 * direct calls turn it into a 400, fallback chains skip the provider instead.
 */
export async function forwardToProvider(
  resolved: Resolved,
  path: string,
  upstreamBody: unknown,
  env: Env,
  clientHeaders?: Headers,
): Promise<Response> {
  // Enabled-check ONLY when a DB binding exists (Global Constraint ruling:
  // fail-open without D1 → Phase A behavior preserved).
  if (env.DB) {
    const enabled = await readEnabledMap(env);
    if (enabled[resolved.prefix] === false) {
      throw new DisabledProviderError(resolved.prefix);
    }
  }
  const headers: Record<string, string> = { "content-type": "application/json" };
  if (resolved.oauth === true) {
    // OAuth-backed provider: the credential lives in the encrypted D1 store,
    // refreshed on use. Unusable token → MissingTokenError keeps the same
    // 400/skip-in-chain semantics as a missing API key.
    let token: string;
    try {
      token = await ensureFreshToken(env, resolved.prefix);
    } catch (err) {
      if (err instanceof TokenExpiredError) throw new MissingTokenError(err.prefix);
      throw err;
    }
    headers["authorization"] = `Bearer ${token}`;
  } else if (resolved.auth === "anthropic") {
    const key = providerKey(resolved, env);
    if (!key) throw new MissingKeyError(resolved.keySecret!);
    headers["x-api-key"] = key;
    headers["anthropic-version"] = "2023-06-01";
  } else {
    const key = providerKey(resolved, env);
    if (!key) throw new MissingKeyError(resolved.keySecret!);
    headers["authorization"] = `Bearer ${key}`;
  }
  if (clientHeaders) {
    const gatewaySet = new Set([
      "x-api-key",
      "anthropic-version",
      "authorization",
      "content-type",
    ]);
    for (const [name, value] of clientHeaders.entries()) {
      const lower = name.toLowerCase();
      if (lower.startsWith("anthropic-") && !gatewaySet.has(lower)) {
        headers[lower] = value;
      }
    }
  }
  return fetch(`${resolved.baseURL}${path}`, {
    method: "POST",
    headers,
    body: JSON.stringify(upstreamBody),
  });
}

/**
 * Direct-call wrapper: MissingKeyError becomes a 400 naming the secret,
 * any other error (network, DNS, TLS) becomes a 502 JSON naming the provider.
 * Used by direct provider routes (chat, messages); fallback chains handle
 * these errors themselves to skip the provider.
 * `meta` (optional out-param): on a thrown-error path this is populated with a
 * compact error tag ({@code missing-key:<SECRET>}, {@code disabled},
 * {@code network-error:<prefix>}) so callers can log WHY the call failed —
 * plan Task 10 requires the error column on direct paths too.
 */
export async function forwardOr400(
  resolved: Resolved,
  path: string,
  upstreamBody: unknown,
  env: Env,
  clientHeaders?: Headers,
  meta?: { error?: string },
): Promise<Response> {
  try {
    return await forwardToProvider(resolved, path, upstreamBody, env, clientHeaders);
  } catch (err) {
    if (err instanceof MissingKeyError) {
      if (meta) meta.error = `missing-key:${err.secret}`;
      return jsonResponse({ error: { message: err.message } }, 400);
    }
    if (err instanceof MissingTokenError) {
      if (meta) meta.error = `missing-token:${err.prefix}`;
      return jsonResponse({ error: { message: err.message } }, 400);
    }
    if (err instanceof DisabledProviderError) {
      if (meta) meta.error = "disabled";
      return jsonResponse({ error: { message: err.message } }, 400);
    }
    if (meta) meta.error = `network-error:${resolved.prefix}`;
    return jsonResponse(
      {
        error: {
          message: `Provider unreachable (${resolved.prefix}): ${err instanceof Error ? err.message : "unknown error"}`,
        },
      },
      502,
    );
  }
}
