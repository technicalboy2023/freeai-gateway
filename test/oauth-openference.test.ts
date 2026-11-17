import { beforeEach, describe, expect, it, vi } from "vitest";
import { complete, getAdapter, start } from "../src/oauth/engine";
import { ensureFreshToken } from "../src/oauth/refresh";
import { getToken, saveToken } from "../src/oauth/store";
import type { Env } from "../src/env";
import type { OAuthAdapter } from "../src/oauth/types";

const KEY = btoa(String.fromCharCode(...new Uint8Array(32).fill(0x41)))
  .replace(/\+/g, "-")
  .replace(/\//g, "_")
  .replace(/=+$/, "");
const CLIENT_ID = "omniroute";
const AUTHORIZE_URL = "https://openference.com/app/oauth/authorize";
const TOKEN_URL = "https://openference.com/oauth/token";
const USERINFO_URL = "https://openference.com/oauth/userinfo";
const REDIRECT_URI = "http://127.0.0.1:56123/callback";
const SCOPE = "openid profile email model:invoke offline_access";
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

function openference(): OAuthAdapter {
  const adapter = getAdapter("openference");
  if (!adapter) throw new Error("openference adapter was not registered");
  return adapter;
}

beforeEach(() => {
  vi.unstubAllGlobals();
});

describe("Openference authorization-code flow", () => {
  it("builds the ordered authorization query with the fixed loopback redirect", async () => {
    expect(openference().flowMode).toBe("paste-code");
    expect(openference().redirectUri).toBe(REDIRECT_URI);
    const { db } = stubDb();
    const result = await start(envWith(db), "openference", new URL(`${ORIGIN}/admin/api/oauth/openference/start`));
    expect(result.mode).toBe("paste-code");
    if (result.mode !== "paste-code") throw new Error("expected paste-code flow");

    const authUrl = new URL(result.authUrl);
    expect(authUrl.origin + authUrl.pathname).toBe(AUTHORIZE_URL);
    expect([...authUrl.searchParams.keys()]).toEqual([
      "response_type",
      "client_id",
      "redirect_uri",
      "scope",
      "code_challenge",
      "code_challenge_method",
      "state",
    ]);
    expect(authUrl.searchParams.get("response_type")).toBe("code");
    expect(authUrl.searchParams.get("client_id")).toBe(CLIENT_ID);
    expect(authUrl.searchParams.get("redirect_uri")).toBe(REDIRECT_URI);
    expect(authUrl.searchParams.get("scope")).toBe(SCOPE);
    expect(authUrl.searchParams.get("code_challenge")).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(authUrl.searchParams.get("code_challenge_method")).toBe("S256");
    expect(authUrl.searchParams.get("state")).toBe(result.state);
  });

  it("exchanges the five standard fields, loads userinfo, and prefers id_token identity", async () => {
    const idToken = jwt({ email: "id-token@example.com", name: "ID Token Name" });
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(
        jsonResponse({
          access_token: "openference-at",
          refresh_token: "openference-rt",
          expires_in: 3600,
          id_token: idToken,
          scope: "",
          token_type: "",
        }),
      )
      .mockResolvedValueOnce(
        jsonResponse({
          email: "userinfo@example.com",
          name: "Userinfo Name",
          preferred_username: "userinfo-handle",
        }),
      );
    vi.stubGlobal("fetch", fetchMock);
    const { db } = stubDb();
    const env = envWith(db);
    await start(env, "openference", new URL(`${ORIGIN}/start`));
    const result = await complete(env, "openference", { code: "authorization-code" });
    expect(result).toEqual({ connected: true, accountLabel: "ID Token Name" });

    const [exchangeUrl, exchangeInit] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
    expect(exchangeUrl).toBe(TOKEN_URL);
    expect(exchangeInit.method).toBe("POST");
    expect(exchangeInit.headers).toMatchObject({
      Accept: "application/json",
      "Content-Type": "application/x-www-form-urlencoded",
    });
    const exchange = new URLSearchParams(String(exchangeInit.body));
    expect([...exchange.keys()].sort()).toEqual(
      ["grant_type", "client_id", "code", "redirect_uri", "code_verifier"].sort(),
    );
    expect(exchange.get("grant_type")).toBe("authorization_code");
    expect(exchange.get("client_id")).toBe(CLIENT_ID);
    expect(exchange.get("code")).toBe("authorization-code");
    expect(exchange.get("redirect_uri")).toBe(REDIRECT_URI);
    expect(exchange.get("code_verifier")).toMatch(/^[A-Za-z0-9_-]{43}$/);

    const [userinfoUrl, userinfoInit] = fetchMock.mock.calls[1] as unknown as [string, RequestInit];
    expect(userinfoUrl).toBe(USERINFO_URL);
    expect(userinfoInit.method).toBe("GET");
    expect(userinfoInit.headers).toEqual({
      Authorization: "Bearer openference-at",
      Accept: "application/json",
    });

    const row = (await getToken(env, "openference"))!;
    expect(row.accessToken).toBe("openference-at");
    expect(row.refreshToken).toBe("openference-rt");
    expect(row.accountLabel).toBe("ID Token Name");
    expect(row.meta).toEqual({ scope: SCOPE, tokenType: "Bearer" });
  });

  it("uses userinfo as a best-effort fallback when id_token identity is absent", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(
        jsonResponse({
          access_token: "openference-at",
          id_token: jwt({}),
        }),
      )
      .mockResolvedValueOnce(jsonResponse({ name: "Userinfo Name", preferred_username: "handle@example.com" }));
    vi.stubGlobal("fetch", fetchMock);
    const { db } = stubDb();
    const env = envWith(db);
    await start(env, "openference", new URL(`${ORIGIN}/start`));
    const result = await complete(env, "openference", { code: "fallback-code" });
    expect(result).toEqual({ connected: true, accountLabel: "Userinfo Name" });
    expect((await getToken(env, "openference"))?.accountLabel).toBe("Userinfo Name");
  });

  it("does not block OAuth completion when userinfo returns a non-2xx response", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(jsonResponse({ access_token: "openference-at" }))
      .mockResolvedValueOnce(new Response("userinfo unavailable", { status: 503 }));
    vi.stubGlobal("fetch", fetchMock);
    const { db } = stubDb();
    const env = envWith(db);
    await start(env, "openference", new URL(`${ORIGIN}/start`));
    const result = await complete(env, "openference", { code: "best-effort-code" });
    expect(result).toEqual({ connected: true, accountLabel: null });
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect((await getToken(env, "openference"))?.accessToken).toBe("openference-at");
  });
});

describe("Openference identity fallback mapping", () => {
  it.each([
    [{ email: "id@example.com", preferred_username: "id-handle", name: "ID Name" }, { name: "UI Name", email: "ui@example.com" }, "id@example.com", "ID Name"],
    [{}, { name: "UI Name", preferred_username: "ui-handle@example.com" }, "ui-handle@example.com", "UI Name"],
    [{}, { email: "ui@example.com" }, "ui@example.com", "ui@example.com"],
    [{}, { preferred_username: "ui-handle@example.com" }, "ui-handle@example.com", "ui-handle@example.com"],
  ])(
    "maps id_token and userinfo identity candidates in priority order",
    (claims, userinfo, expectedEmail, expectedName) => {
      const mapped = openference().mapTokens(
        { access_token: "at", id_token: jwt(claims), scope: "openid email", token_type: "DPoP" },
        userinfo,
      );
      expect(mapped.email).toBe(expectedEmail);
      expect(mapped.name).toBe(expectedName);
      expect(mapped.meta).toEqual({ scope: "openid email", tokenType: "DPoP" });
    },
  );
});

describe("Openference standard refresh", () => {
  it("uses the standard refresh grant without scope and retains an omitted rotating refresh token", async () => {
    expect(openference().refresh).toBeUndefined();
    const fetchMock = vi.fn(async () =>
      jsonResponse({ access_token: "openference-refreshed", expires_in: 7200 }),
    );
    vi.stubGlobal("fetch", fetchMock);
    const { db } = stubDb();
    const env = envWith(db);
    await saveToken(env, {
      provider: "openference",
      accessToken: "old-access-token",
      refreshToken: "oar-one-time-refresh",
      expiresIn: 10,
      authKind: "oauth",
    });
    expect(await ensureFreshToken(env, "openference")).toBe("openference-refreshed");
    const [url, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe(TOKEN_URL);
    expect(init.method).toBe("POST");
    const body = new URLSearchParams(String(init.body));
    expect([...body.keys()].sort()).toEqual(["grant_type", "client_id", "refresh_token"].sort());
    expect(body.get("grant_type")).toBe("refresh_token");
    expect(body.get("client_id")).toBe(CLIENT_ID);
    expect(body.get("refresh_token")).toBe("oar-one-time-refresh");
    expect(body.has("scope")).toBe(false);
    expect((await getToken(env, "openference"))?.refreshToken).toBe("oar-one-time-refresh");
  });
});
