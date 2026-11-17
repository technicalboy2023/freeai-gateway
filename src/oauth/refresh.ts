import type { Env } from "../env";
import { getAdapter } from "./engine";
import { getToken, saveToken } from "./store";
import type { RawTokens } from "./types";

/**
 * Refresh-on-use: the free plan has no cron, so tokens are refreshed just
 * before they are spent (forward path). Refreshed rows keep their original
 * authKind and record last_refresh_at; a rejected refresh records last_error
 * and forces a reconnect on the next attempt.
 */

export const REFRESH_SKEW_SEC = 300;

export class TokenExpiredError extends Error {
  constructor(public prefix: string, public detail: string) {
    super(`OAuth token unusable for ${prefix}: ${detail}`);
  }
}

interface RefreshConfig {
  tokenUrl?: unknown;
  clientId?: unknown;
}

async function standardRefresh(config: RefreshConfig, refreshToken: string): Promise<RawTokens> {
  const tokenUrl = typeof config.tokenUrl === "string" ? config.tokenUrl : "";
  if (!tokenUrl) throw new Error("no tokenUrl configured for standard refresh");
  const res = await fetch(tokenUrl, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "refresh_token",
      client_id: typeof config.clientId === "string" ? config.clientId : "",
      refresh_token: refreshToken,
    }).toString(),
  });
  let data: unknown = null;
  try {
    data = await res.json();
  } catch {
    // non-JSON body → handled below by the !ok/shape checks
  }
  // OAuth errors travel in the body ({"error":"invalid_grant"}) — surface the
  // upstream reason, not just the status.
  if (data && typeof data === "object" && !Array.isArray(data)) {
    const reason = (data as RawTokens).error;
    if (typeof reason === "string" && reason) throw new Error(reason);
  }
  if (!res.ok || !data || typeof data !== "object" || Array.isArray(data)) {
    throw new Error(`refresh failed (${res.status})`);
  }
  return data as RawTokens;
}

/** Record a non-fatal failure on the connection row (never throws on absent rows). */
export async function markTokenError(env: Env, provider: string, error: string): Promise<void> {
  if (!env.DB) return;
  try {
    await env.DB.prepare("UPDATE oauth_tokens SET last_error = ?1 WHERE provider = ?2")
      .bind(error.slice(0, 500), provider)
      .run();
  } catch {
    // D1 unavailable — the caller's primary error still propagates.
  }
}

/**
 * Return a usable access token for `prefix`, refreshing first when the stored
 * one is within REFRESH_SKEW_SEC of expiry.
 */
export async function ensureFreshToken(env: Env, prefix: string): Promise<string> {
  const adapter = getAdapter(prefix);
  if (!adapter) throw new TokenExpiredError(prefix, "unknown provider");

  const row = await getToken(env, prefix);
  if (!row) throw new TokenExpiredError(prefix, "not connected");

  const skewMs = REFRESH_SKEW_SEC * 1000;
  const fresh = row.expiresAt == null || row.expiresAt - Date.now() >= skewMs;
  if (fresh) return row.accessToken;
  if (!row.refreshToken) {
    const detail = "token expired, no refresh grant";
    await markTokenError(env, prefix, detail);
    throw new TokenExpiredError(prefix, detail);
  }

  let raw: RawTokens;
  try {
    raw = adapter.refresh
      ? await adapter.refresh(adapter.config, row.refreshToken, row.meta)
      : await standardRefresh(adapter.config as RefreshConfig, row.refreshToken);
  } catch (err) {
    const detail = err instanceof Error ? err.message : "refresh failed";
    await markTokenError(env, prefix, detail);
    // Adapter-agnostic terminal signals used when a provider explicitly
    // rejects a durable credential. Keep provider-specific detail in the
    // thrown error; transient failures still collapse to refresh-rejected
    // while preserving last_error above.
    const errorStatus =
      err && typeof err === "object" && "status" in err
        ? Number((err as { status?: unknown }).status)
        : 0;
    const terminalUnauthorized =
      err instanceof Error &&
      ((err.name === "MuseCodeMintError" && (errorStatus === 401 || errorStatus === 403)) ||
        err.name === "CursorRefreshUnauthorized");
    throw new TokenExpiredError(prefix, terminalUnauthorized ? detail : "refresh rejected");
  }

  // Refresh never re-runs postExchange — extras stay untouched. Pass saved
  // metadata and encrypted provider secrets so mappers can preserve identity.
  const mapped = adapter.mapTokens(raw, undefined, row.meta, row.secrets);
  if (!mapped.accessToken) {
    await markTokenError(env, prefix, "refresh returned no access token");
    throw new TokenExpiredError(prefix, "refresh rejected");
  }

  await saveToken(env, {
    provider: prefix,
    accessToken: mapped.accessToken,
    // Refresh responses rarely carry profile fields or a rotated grant —
    // merge with the existing row so the label/meta/refresh grant survive.
    refreshToken: mapped.refreshToken ?? row.refreshToken ?? null,
    expiresIn: mapped.expiresIn ?? null,
    email: mapped.email ?? null,
    name: mapped.name ?? row.accountLabel ?? null,
    meta: mapped.meta ?? row.meta ?? undefined,
    secrets: mapped.secrets ?? row.secrets,
    authKind: row.authKind,
    connectedAt: row.connectedAt,
    lastRefreshAt: Date.now(),
  });
  return mapped.accessToken;
}
