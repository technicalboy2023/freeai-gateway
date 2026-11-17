import type { Env } from "../env";
import { decodeCredentialBlob } from "./blob";
import { generatePkce } from "./pkce";
import { OAUTH_ADAPTERS } from "./providers/registry";
import {
  DbMissingError,
  deletePending,
  deleteToken,
  getPending,
  getTokenStatus,
  savePending,
  saveToken,
} from "./store";
import type { FlowMode, MappedTokens, OAuthAdapter, PollResult, RawTokens } from "./types";

/**
 * Flow engine: drives the three connect modes (paste / paste-code / device)
 * against the registered adapters and persists the result via ./store.
 * This module imports NO provider files — providers register themselves
 * (providers/registry.ts is wired in by the provider tasks).
 */

export class OAuthError extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
}

const adapters = new Map<string, OAuthAdapter>();

export function registerAdapter(a: OAuthAdapter): void {
  adapters.set(a.prefix, a);
}

// Real provider adapters self-register at module init.
for (const a of OAUTH_ADAPTERS) registerAdapter(a);

export function getAdapter(prefix: string): OAuthAdapter | null {
  return adapters.get(prefix) ?? null;
}

export function listAdapters(): OAuthAdapter[] {
  return [...adapters.values()].sort((a, b) => (a.prefix < b.prefix ? -1 : a.prefix > b.prefix ? 1 : 0));
}

export type StartResult =
  | { mode: "paste"; instructions: string }
  | { mode: "paste-code"; authUrl: string; state: string }
  | {
      mode: "device";
      user_code: string;
      verification_uri: string;
      verification_uri_complete: string;
      expires_in: number;
      interval: number;
    };

const PKCE_PENDING_TTL_SEC = 600;

function requireAdapter(prefix: string): OAuthAdapter {
  const a = adapters.get(prefix);
  if (!a) throw new OAuthError(404, `Unknown OAuth provider: ${prefix}`);
  return a;
}

function resolveRedirectUri(a: OAuthAdapter, requestUrl?: URL): string {
  if (a.redirectUri) return a.redirectUri;
  // Adapters without a static redirect land on the gateway's own public
  // state-matched auto-callback (Task 2) — start and exchange MUST agree.
  if (requestUrl) return new URL(`/admin/oauth/${a.prefix}/callback`, requestUrl.origin).toString();
  return "";
}

/** Terminal poll error text: error/error_description first, then msg/code. */
function pollErrorText(data: RawTokens): string {
  const error = data.error;
  // A provider may use this stable marker while carrying the actual HTTP
  // detail separately; preserve both in the user-facing terminal poll result.
  if (error === "poll_failed" && typeof data.error_description === "string" && data.error_description) {
    return `poll_failed: ${data.error_description}`;
  }
  if (typeof error === "string" && error) return error;
  const desc = data.error_description;
  if (typeof desc === "string" && desc) return desc;
  const code = typeof data.code === "number" ? String(data.code) : "";
  const msg = typeof data.msg === "string" ? data.msg : "";
  if (code && msg) return `poll failed (code ${code}): ${msg}`;
  if (code) return `poll failed (code ${code})`;
  if (msg) return `poll failed: ${msg}`;
  return "poll failed";
}

async function finalizeAndSave(
  env: Env,
  a: OAuthAdapter,
  tokens: RawTokens,
  authKind: string,
  opts: {
    /** Provider-specific start params threaded through the flow (postExchange input). */
    startParams?: Record<string, unknown>;
    /** Fallback extra for mapTokens when the adapter has no postExchange. */
    extra?: Record<string, unknown>;
    /** Saved row meta for refreshes — mapTokens merges, never clobbers. */
    priorMeta?: Record<string, unknown>;
    /** Only exchange-success paths opt in — the paste path never mints extras. */
    postExchange?: boolean;
  } = {},
): Promise<MappedTokens> {
  const normalized = authKind === "paste" && a.importToken ? await a.importToken(tokens) : tokens;
  let extra = opts.extra;
  if (opts.postExchange && a.postExchange) {
    extra = await a.postExchange(normalized, opts.startParams);
  }
  const mapped = a.mapTokens(normalized, extra, opts.priorMeta);
  if (!mapped.accessToken) {
    throw new OAuthError(400, `${a.prefix}: token mapping produced no access token`);
  }
  await saveToken(env, {
    provider: a.prefix,
    accessToken: mapped.accessToken,
    refreshToken: mapped.refreshToken ?? null,
    expiresIn: mapped.expiresIn ?? null,
    email: mapped.email ?? null,
    name: mapped.name ?? null,
    meta: mapped.meta,
    secrets: mapped.secrets,
    authKind,
  });
  return mapped;
}

export async function start(env: Env, prefix: string, requestUrl: URL): Promise<StartResult> {
  const a = requireAdapter(prefix);

  if (a.flowMode === "paste") {
    return { mode: "paste", instructions: a.instructions ?? "Paste the provider token." };
  }

  if (a.flowMode === "paste-code") {
    if (!a.buildAuthUrl || !a.exchangeToken) {
      throw new OAuthError(400, `${prefix} does not support paste-code login`);
    }
    const pkce = await generatePkce(a.pkceVerifierBytes ?? 32);
    const redirectUri = resolveRedirectUri(a, requestUrl);
    const authUrl = a.buildAuthUrl(a.config, redirectUri, pkce.state, pkce.codeChallenge);
    await savePending(env, {
      provider: prefix,
      mode: "pkce",
      state: pkce.state,
      codeVerifier: pkce.codeVerifier,
      ttlSec: PKCE_PENDING_TTL_SEC,
    });
    return { mode: "paste-code", authUrl, state: pkce.state };
  }

  // device
  if (!a.requestDeviceCode) {
    throw new OAuthError(400, `${prefix} does not support device login`);
  }
  // The pending row always carries a PKCE pair: adapters that use S256 in the
  // browser get the challenge here and the verifier twin back on poll.
  const pkce = await generatePkce(32);
  const startParams = a.parseStartParams?.(requestUrl);
  let d;
  try {
    d = await a.requestDeviceCode(a.config, pkce.codeChallenge, startParams);
  } catch (err) {
    throw new OAuthError(502, `${prefix} device start failed: ${err instanceof Error ? err.message : "unknown error"}`);
  }
  const extras: Record<string, unknown> = {
    ...(startParams ?? {}),
    ...(d.device_id ? { deviceId: d.device_id } : {}),
  };
  const extra = Object.keys(extras).length > 0 ? extras : undefined;
  // Upstream owns the device-code lifetime — clamp to [60s, 30min], default 15min.
  const ttl = Math.min(Math.max(d.expires_in || 900, 60), 1800);
  await savePending(env, {
    provider: prefix,
    mode: "device",
    codeVerifier: pkce.codeVerifier,
    deviceCode: d.device_code,
    extra,
    ttlSec: ttl,
  });
  return {
    mode: "device",
    user_code: d.user_code,
    verification_uri: d.verification_uri,
    verification_uri_complete: d.verification_uri_complete ?? d.verification_uri,
    expires_in: d.expires_in,
    interval: d.interval,
  };
}

export interface CompleteInput {
  code?: string;
  token?: string;
  blob?: string;
}

export async function complete(
  env: Env,
  prefix: string,
  input: CompleteInput,
  requestUrl?: URL,
): Promise<{ connected: true; accountLabel: string | null }> {
  const a = requireAdapter(prefix);

  // Paste-token import is an alternate path for select paste-code/device
  // adapters. It does not consume or require an in-flight OAuth pending row,
  // and deliberately skips postExchange enrichment.
  if (
    (a.flowMode === "paste-code" || a.flowMode === "device") &&
    typeof input.token === "string" &&
    a.importToken
  ) {
    try {
      const mapped = await finalizeAndSave(env, a, { access_token: input.token.trim() }, "paste");
      return { connected: true, accountLabel: mapped.name ?? mapped.email ?? null };
    } catch (err) {
      if (err instanceof DbMissingError) throw err;
      if (err instanceof OAuthError) throw err;
      throw new OAuthError(400, err instanceof Error ? err.message : "token rejected");
    }
  }

  if (a.flowMode === "paste") {
    try {
      let tokens: RawTokens;
      if (typeof input.token === "string") {
        // Empty string still reaches importToken — adapter-level validation
        // ("Token is empty") is the better error than a generic 400. Trim
        // first: header copies arrive with leading/trailing whitespace.
        tokens = { access_token: input.token.trim() };
      } else if (typeof input.blob === "string" && input.blob.length > 0) {
        const decoded = decodeCredentialBlob(input.blob);
        if (decoded.provider !== prefix) {
          throw new OAuthError(400, `blob is for ${decoded.provider}, not ${prefix}`);
        }
        tokens = decoded.tokens;
      } else {
        throw new OAuthError(400, "paste a token or blob");
      }
      const mapped = await finalizeAndSave(env, a, tokens, "paste");
      return { connected: true, accountLabel: mapped.name ?? mapped.email ?? null };
    } catch (err) {
      // Store-class errors must keep their own HTTP class (no DB → 503);
      // only adapter-level failures flatten into a 400.
      if (err instanceof DbMissingError) throw err;
      if (err instanceof OAuthError) throw err;
      throw new OAuthError(400, err instanceof Error ? err.message : "token rejected");
    }
  }

  if (a.flowMode === "paste-code") {
    if (!a.exchangeToken) {
      throw new OAuthError(400, `${prefix} does not support paste-code login`);
    }
    if (typeof input.code !== "string" || !input.code.trim()) {
      throw new OAuthError(400, "paste the authorization code");
    }
    const pending = await getPending(env, prefix);
    if (!pending || pending.mode !== "pkce") {
      throw new OAuthError(410, "login flow expired — start again");
    }
    let raw: RawTokens;
    try {
      raw = await a.exchangeToken(
        a.config,
        input.code.trim(),
        resolveRedirectUri(a, requestUrl),
        pending.codeVerifier ?? "",
        pending.state ?? "",
      );
    } catch (err) {
      throw new OAuthError(400, err instanceof Error ? err.message : "token exchange failed");
    }
    const mapped = await finalizeAndSave(env, a, raw, "oauth", {
      postExchange: true,
      startParams: pending.extra ?? undefined,
      extra: pending.extra ?? undefined,
    });
    await deletePending(env, prefix);
    return { connected: true, accountLabel: mapped.name ?? mapped.email ?? null };
  }

  throw new OAuthError(400, `${prefix} completes through the device flow`);
}

const NON_TERMINAL_POLL_ERRORS = new Set(["authorization_pending", "slow_down"]);

export async function poll(
  env: Env,
  prefix: string,
): Promise<{ status: "pending" | "connected" | "error"; error?: string }> {
  const a = requireAdapter(prefix);
  if (a.flowMode !== "device" || !a.pollToken) {
    throw new OAuthError(400, `${prefix} does not support device login`);
  }
  const pending = await getPending(env, prefix);
  if (!pending || pending.mode !== "device") {
    return { status: "error", error: "expired" };
  }

  let result: PollResult;
  try {
    result = await a.pollToken(
      a.config,
      pending.deviceCode ?? "",
      pending.codeVerifier ?? undefined,
      pending.extra ?? undefined,
    );
  } catch (err) {
    // Adapter/network throw is retryable — keep the flow alive.
    return {
      status: "error",
      error: err instanceof Error ? err.message : "poll failed",
    };
  }

  if (result.ok && typeof result.data.access_token === "string" && result.data.access_token) {
    await finalizeAndSave(env, a, result.data, "oauth", {
      postExchange: true,
      startParams: pending.extra ?? undefined,
      extra: pending.extra ?? undefined,
    });
    await deletePending(env, prefix);
    return { status: "connected" };
  }

  if (result.ok) {
    // Upstream said ok but sent no token — a protocol quirk, not a denial.
    // Keep the flow alive so the console can retry.
    return { status: "error", error: "upstream returned no access token" };
  }

  if (!result.ok && NON_TERMINAL_POLL_ERRORS.has(String(result.data.error))) {
    return { status: "pending", error: String(result.data.error) };
  }

  // Terminal upstream answer — the flow is over, clean the pending row.
  await deletePending(env, prefix);
  return {
    status: "error",
    error: pollErrorText(result.data),
  };
}

export async function statusOf(env: Env, prefix: string): Promise<{
  connected: boolean;
  expiresAt: number | null;
  accountLabel: string | null;
  lastError: string | null;
  flowMode: FlowMode;
}> {
  const a = requireAdapter(prefix);
  const s = await getTokenStatus(env, prefix);
  return {
    connected: s?.connected ?? false,
    expiresAt: s?.expiresAt ?? null,
    accountLabel: s?.accountLabel ?? null,
    lastError: s?.lastError ?? null,
    flowMode: a.flowMode,
  };
}

export async function disconnect(env: Env, prefix: string): Promise<void> {
  requireAdapter(prefix);
  await deleteToken(env, prefix);
  await deletePending(env, prefix);
}
