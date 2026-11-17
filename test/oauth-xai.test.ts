import { beforeEach, describe, expect, it, vi } from "vitest";
import { complete, getAdapter, registerAdapter, start } from "../src/oauth/engine";
import { deriveChallenge } from "../src/oauth/pkce";
import { ensureFreshToken } from "../src/oauth/refresh";
import { getToken, saveToken } from "../src/oauth/store";
import { decodeJwtPayload } from "../src/oauth/providers/jwt";
import type { Env } from "../src/env";
import type { OAuthAdapter } from "../src/oauth/types";

const KEY = btoa(String.fromCharCode(...new Uint8Array(32).fill(0x41)))
  .replace(/\+/g, "-")
  .replace(/\//g, "_")
  .replace(/=+$/, "");
const CLIENT_ID = "b1a00492-073a-47ea-816f-4c329264a828";
const REDIRECT_URI = "http://127.0.0.1:56121/callback";
const SCOPE = "openid profile email offline_access grok-cli:access api:access";
const ORIGIN = "https://gw.test";

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

function jwt(payload: Record<string, unknown>): string {
  const bytes = new TextEncoder().encode(JSON.stringify(payload));
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  const encoded = btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  return `eyJhbGciOiJub25lIn0.${encoded}.sig`;
}

function stubDb() {
  const tokens = new Map<string, Record<string, unknown>>();
  const pending = new Map<string, Record<string, unknown>>();
  const db = {
    prepare: (sql: string) => ({
      bind: (...params: unknown[]) => ({
        first: async <T,>() => {
          if (!sql.startsWith("SELECT")) return null;
          const map = sql.includes("oauth_pending") ? pending : tokens;
          const row = map.get(String(params[0]));
          return row ? (row as T) : null;
        },
        all: async <T,>() => ({ results: [] as unknown[] } as unknown as T),
        run: async () => {
          if (sql.startsWith("INSERT INTO oauth_tokens")) {
            const [provider, access, refresh, expiresAt, label, meta, authKind, connectedAt, lastRefreshAt] =
              params as [string, ...unknown[]];
            tokens.set(provider, {
              provider,
              access_token: access,
              refresh_token: refresh ?? null,
              expires_at: expiresAt ?? null,
              account_label: label ?? null,
              meta: meta ?? null,
              auth_kind: authKind,
              connected_at: connectedAt,
              last_refresh_at: lastRefreshAt ?? null,
              last_error: null,
            });
          }
          if (sql.startsWith("UPDATE oauth_tokens")) {
            const row = tokens.get(String(params[1]));
            if (row) row.last_error = params[0];
          }
          if (sql.startsWith("DELETE FROM oauth_tokens")) tokens.delete(String(params[0]));
          if (sql.startsWith("INSERT INTO oauth_pending")) {
            const [provider, mode, state, codeVerifier, deviceCode, extra, createdAt, expiresAt] =
              params as [string, ...unknown[]];
            pending.set(provider, {
              provider,
              mode,
              state: state ?? null,
              code_verifier: codeVerifier ?? null,
              device_code: deviceCode ?? null,
              extra: extra ?? null,
              created_at: createdAt,
              expires_at: expiresAt,
            });
          }
          if (sql.startsWith("DELETE FROM oauth_pending")) pending.delete(String(params[0]));
          return { success: true };
        },
      }),
    }),
  } as unknown as D1Database;
  return { db, tokens, pending };
}

function envWith(db: D1Database): Env {
  return { DB: db, OAUTH_ENCRYPTION_KEY: KEY } as unknown as Env;
}

function xai(): OAuthAdapter {
  const adapter = getAdapter("xai-oauth");
  if (!adapter) throw new Error("xai-oauth adapter was not registered");
  return adapter;
}

beforeEach(() => {
  vi.unstubAllGlobals();
});

describe("shared JWT payload decoder", () => {
  it("decodes base64url UTF-8 claims and safely rejects malformed tokens", () => {
    const payload = { email: "xäï@example.com", name: "XAI CLI" };
    expect(decodeJwtPayload(jwt(payload))).toEqual(payload);
    expect(decodeJwtPayload("not-a-jwt")).toBeNull();
    expect(decodeJwtPayload("a.b.c")).toBeNull();
  });
});

describe("XAI verifier length and authorization URL", () => {
  it("uses pkceVerifierBytes for a 128-character verifier and matching challenge", async () => {
    let authChallenge = "";
    let exchangeVerifier = "";
    const testAdapter = {
      prefix: "xv-test",
      flowMode: "paste-code",
      config: {},
      pkceVerifierBytes: 96,
      buildAuthUrl: (_config: Record<string, unknown>, _redirect: string, _state: string, challenge: string) => {
        authChallenge = challenge;
        return "https://test.invalid/auth";
      },
      exchangeToken: async (
        _config: Record<string, unknown>,
        _code: string,
        _redirect: string,
        verifier: string,
      ) => {
        exchangeVerifier = verifier;
        return { access_token: "xv-at" };
      },
      mapTokens: (tokens: Record<string, unknown>) => ({ accessToken: String(tokens.access_token) }),
    } as OAuthAdapter & { pkceVerifierBytes: number };
    registerAdapter(testAdapter);
    const { db } = stubDb();
    const env = envWith(db);
    await start(env, "xv-test", new URL(`${ORIGIN}/start`));
    await complete(env, "xv-test", { code: "test-code" });
    expect(exchangeVerifier).toMatch(/^[A-Za-z0-9_-]{128}$/);
    expect(await deriveChallenge(exchangeVerifier)).toBe(authChallenge);
  });

  it("sends all pinned authorization fields and the static loopback redirect", async () => {
    const { db } = stubDb();
    const result = await start(envWith(db), "xai-oauth", new URL(`${ORIGIN}/start`));
    expect(result.mode).toBe("paste-code");
    if (result.mode !== "paste-code") throw new Error("expected paste-code flow");
    expect(xai().redirectUri).toBe(REDIRECT_URI);
    expect(xai().config).toMatchObject({
      clientId: CLIENT_ID,
      authorizeUrl: "https://auth.x.ai/oauth2/authorize",
      tokenUrl: "https://auth.x.ai/oauth2/token",
      scope: SCOPE,
    });
    const authUrl = new URL(result.authUrl);
    expect(authUrl.origin + authUrl.pathname).toBe("https://auth.x.ai/oauth2/authorize");
    expect(authUrl.searchParams.get("response_type")).toBe("code");
    expect(authUrl.searchParams.get("client_id")).toBe(CLIENT_ID);
    expect(authUrl.searchParams.get("redirect_uri")).toBe(REDIRECT_URI);
    expect(authUrl.searchParams.get("scope")).toBe(SCOPE);
    expect(authUrl.searchParams.get("code_challenge")).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(authUrl.searchParams.get("code_challenge_method")).toBe("S256");
    expect(authUrl.searchParams.get("state")).toBe(result.state);
    expect(authUrl.searchParams.get("nonce")).toMatch(/^[a-f0-9]{32}$/);
    expect(authUrl.searchParams.get("plan")).toBe("generic");
    expect(authUrl.searchParams.get("referrer")).toBe("cli-proxy-api");
    expect([...authUrl.searchParams.keys()].sort()).toEqual(
      [
        "response_type",
        "client_id",
        "redirect_uri",
        "scope",
        "code_challenge",
        "code_challenge_method",
        "state",
        "nonce",
        "plan",
        "referrer",
      ].sort(),
    );
  });
});

describe("XAI token exchange and identity mapping", () => {
  it("exchanges five standard fields and maps id_token email/name/scope/tokenType", async () => {
    const idToken = jwt({ email: "xai@example.com", name: "XAI User" });
    const fetchMock = vi.fn(async () =>
      jsonResponse({
        access_token: "xai-at",
        refresh_token: "xai-rt",
        expires_in: 3600,
        id_token: idToken,
        scope: "openid api:access",
        token_type: "DPoP",
      }),
    );
    vi.stubGlobal("fetch", fetchMock);
    const { db } = stubDb();
    const env = envWith(db);
    await start(env, "xai-oauth", new URL(`${ORIGIN}/start`));
    const result = await complete(env, "xai-oauth", { code: "xai-code" });
    expect(result).toEqual({ connected: true, accountLabel: "XAI User" });
    const [url, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe("https://auth.x.ai/oauth2/token");
    const body = new URLSearchParams(String(init.body));
    expect([...body.keys()].sort()).toEqual(
      ["grant_type", "client_id", "code", "redirect_uri", "code_verifier"].sort(),
    );
    expect(body.get("grant_type")).toBe("authorization_code");
    expect(body.get("client_id")).toBe(CLIENT_ID);
    expect(body.get("code")).toBe("xai-code");
    expect(body.get("redirect_uri")).toBe(REDIRECT_URI);
    expect(body.get("code_verifier")).toMatch(/^[A-Za-z0-9_-]{128}$/);
    const row = (await getToken(env, "xai-oauth"))!;
    expect(row.accessToken).toBe("xai-at");
    expect(row.refreshToken).toBe("xai-rt");
    expect(row.accountLabel).toBe("XAI User");
    expect(row.meta).toEqual({ scope: "openid api:access", tokenType: "DPoP" });
  });

  it("uses preferred_username when id_token has no email and defaults tokenType", () => {
    const mapped = xai().mapTokens({
      access_token: "xai-at",
      id_token: jwt({ preferred_username: "handle@example.com", name: "Handle" }),
    });
    expect(mapped.email).toBe("handle@example.com");
    expect(mapped.name).toBe("Handle");
    expect(mapped.meta).toEqual({ scope: SCOPE, tokenType: "Bearer" });
  });
});

describe("XAI refresh", () => {
  it("uses standard refresh without a custom hook", async () => {
    expect(xai().refresh).toBeUndefined();
    const fetchMock = vi.fn(async () =>
      jsonResponse({ access_token: "xai-refreshed", refresh_token: "xai-rt-2", expires_in: 3600 }),
    );
    vi.stubGlobal("fetch", fetchMock);
    const { db } = stubDb();
    const env = envWith(db);
    await saveToken(env, {
      provider: "xai-oauth",
      accessToken: "old-at",
      refreshToken: "old-rt",
      expiresIn: 10,
      authKind: "oauth",
    });
    expect(await ensureFreshToken(env, "xai-oauth")).toBe("xai-refreshed");
    const [url, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe("https://auth.x.ai/oauth2/token");
    const body = new URLSearchParams(String(init.body));
    expect(body.get("grant_type")).toBe("refresh_token");
    expect(body.get("client_id")).toBe(CLIENT_ID);
    expect(body.get("refresh_token")).toBe("old-rt");
    expect(body.has("scope")).toBe(false);
  });
});
