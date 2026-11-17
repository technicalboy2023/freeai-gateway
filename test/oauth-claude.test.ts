import { beforeEach, describe, expect, it, vi } from "vitest";
import { complete, getAdapter, OAuthError, registerAdapter, start } from "../src/oauth/engine";
import { ensureFreshToken } from "../src/oauth/refresh";
import { getToken, saveToken } from "../src/oauth/store";
import type { Env } from "../src/env";
import type { OAuthAdapter } from "../src/oauth/types";

const KEY = btoa(String.fromCharCode(...new Uint8Array(32).fill(0x41)))
  .replace(/\+/g, "-")
  .replace(/\//g, "_")
  .replace(/=+$/, "");

const REDIRECT_URI = "https://platform.claude.com/oauth/code/callback";
const CLIENT_ID = "9d1c250a-e61b-44d9-88ed-5944d1962f5e";
const BETA = "oauth-2025-04-20";

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
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

function claude(): OAuthAdapter {
  const adapter = getAdapter("claude");
  if (!adapter) throw new Error("claude adapter was not registered");
  return adapter;
}

beforeEach(() => {
  vi.unstubAllGlobals();
});

describe("Claude authorization-code flow", () => {
  it("builds the provider URL with the fixed redirect, exact scopes, PKCE, code=true and prompt=login", async () => {
    const { db } = stubDb();
    const result = await start(envWith(db), "claude", new URL("https://gw.test/admin/api/oauth/claude/start"));
    expect(result.mode).toBe("paste-code");
    if (result.mode !== "paste-code") throw new Error("expected paste-code flow");

    const authUrl = new URL(result.authUrl);
    expect(authUrl.origin + authUrl.pathname).toBe("https://claude.ai/oauth/authorize");
    expect([...authUrl.searchParams.keys()].sort()).toEqual(
      [
        "client_id",
        "code",
        "code_challenge",
        "code_challenge_method",
        "prompt",
        "redirect_uri",
        "response_type",
        "scope",
        "state",
      ].sort(),
    );
    expect(authUrl.searchParams.get("response_type")).toBe("code");
    expect(authUrl.searchParams.get("client_id")).toBe(CLIENT_ID);
    expect(authUrl.searchParams.get("redirect_uri")).toBe(REDIRECT_URI);
    expect(authUrl.searchParams.get("scope")).toBe(
      "org:create_api_key user:profile user:inference user:sessions:claude_code user:mcp_servers",
    );
    expect(authUrl.searchParams.get("code_challenge")).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(authUrl.searchParams.get("code_challenge_method")).toBe("S256");
    expect(authUrl.searchParams.get("code")).toBe("true");
    expect(authUrl.searchParams.get("prompt")).toBe("login");
    expect(authUrl.searchParams.get("state")).toBe(result.state);
    expect(claude().instructions).toContain("sk-ant-oat");
  });

  it("exchanges only the code before # and bootstraps account details into token meta", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(
        jsonResponse({
          access_token: "claude-at",
          refresh_token: "claude-rt",
          expires_in: 3600,
          token_type: "Bearer",
        }),
      )
      .mockResolvedValueOnce(
        jsonResponse({
          account_uuid: "acct-123",
          email: "claude@example.com",
          organizationName: "Example Org",
          organizationRole: "admin",
        }),
      );
    vi.stubGlobal("fetch", fetchMock);
    const { db } = stubDb();
    const env = envWith(db);
    await start(env, "claude", new URL("https://gw.test/start"));
    const result = await complete(env, "claude", { code: "auth-code#callback-state" });
    expect(result).toEqual({ connected: true, accountLabel: "claude@example.com" });

    const [tokenUrl, tokenInit] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
    expect(tokenUrl).toBe("https://api.anthropic.com/v1/oauth/token");
    expect(tokenInit.method).toBe("POST");
    expect(tokenInit.headers).toMatchObject({
      Accept: "application/json",
      "Content-Type": "application/x-www-form-urlencoded",
    });
    const exchange = new URLSearchParams(String(tokenInit.body));
    expect([...exchange.keys()].sort()).toEqual(
      ["grant_type", "client_id", "code", "redirect_uri", "code_verifier"].sort(),
    );
    expect(exchange.get("grant_type")).toBe("authorization_code");
    expect(exchange.get("client_id")).toBe(CLIENT_ID);
    expect(exchange.get("code")).toBe("auth-code");
    expect(exchange.get("redirect_uri")).toBe(REDIRECT_URI);
    expect(exchange.get("code_verifier")).toMatch(/^[A-Za-z0-9_-]{43}$/);

    const [bootstrapUrl, bootstrapInit] = fetchMock.mock.calls[1] as unknown as [string, RequestInit];
    expect(bootstrapUrl).toBe("https://api.anthropic.com/api/claude_cli/bootstrap");
    expect(bootstrapInit.method).toBe("GET");
    expect(bootstrapInit.headers).toMatchObject({
      Authorization: "Bearer claude-at",
      Accept: "application/json",
      "User-Agent": "claude-cli/2.1.7 (external, cli)",
      "anthropic-beta": BETA,
    });
    expect(bootstrapInit.signal).toBeInstanceOf(AbortSignal);

    const row = (await getToken(env, "claude"))!;
    expect(row.accessToken).toBe("claude-at");
    expect(row.refreshToken).toBe("claude-rt");
    expect(row.authKind).toBe("oauth");
    expect(row.accountLabel).toBe("claude@example.com");
    expect(row.meta).toMatchObject({
      cliUserID: expect.stringMatching(/^[a-f0-9]{64}$/),
      account_uuid: "acct-123",
      email: "claude@example.com",
      organizationName: "Example Org",
      organizationRole: "admin",
    });
  });

  it.each([
    ["non-2xx", async () => new Response("unavailable", { status: 503 })],
    ["network failure", async () => Promise.reject(new TypeError("bootstrap timed out"))],
  ])("bootstrap %s is best-effort and does not block token exchange", async (_label, bootstrapResponse) => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(jsonResponse({ access_token: "claude-at", refresh_token: "claude-rt" }))
      .mockImplementationOnce(bootstrapResponse);
    vi.stubGlobal("fetch", fetchMock);
    const { db } = stubDb();
    const env = envWith(db);
    await start(env, "claude", new URL("https://gw.test/start"));
    const result = await complete(env, "claude", { code: "auth-code" });
    expect(result).toEqual({ connected: true, accountLabel: null });
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect((await getToken(env, "claude"))?.meta).toMatchObject({
      cliUserID: expect.stringMatching(/^[a-f0-9]{64}$/),
    });
    expect((await getToken(env, "claude"))?.meta).not.toHaveProperty("account_uuid");
  });

  it("keeps wrong-code completion on the existing expired-flow path", async () => {
    const { db } = stubDb();
    await expect(complete(envWith(db), "claude", { code: "wrong-code" })).rejects.toMatchObject({
      status: 410,
      message: "login flow expired — start again",
    });
  });
});

describe("Claude setup-token paste import", () => {
  it("rejects a token without the setup-token prefix before making a provider request", async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    const { db } = stubDb();
    await expect(complete(envWith(db), "claude", { token: "sk-ant-invalid" })).rejects.toMatchObject({
      status: 400,
      message: "paste a setup token starting with sk-ant-oat",
    });
    expect(fetchMock).not.toHaveBeenCalled();
    expect(await getToken(envWith(db), "claude")).toBeNull();
  });

  it.each([
    [401, "Invalid OAuth token"],
    [403, "Invalid OAuth token"],
    [500, "Provider unavailable (500)"],
    [400, "Claude setup-token validation failed (HTTP 400)"],
    [429, "Claude setup-token validation failed (HTTP 429)"],
  ])("live validation HTTP %i is rejected before storage", async (status, message) => {
    const fetchMock = vi.fn(async () => new Response("provider response", { status }));
    vi.stubGlobal("fetch", fetchMock);
    const { db } = stubDb();
    await expect(complete(envWith(db), "claude", { token: "sk-ant-oat-secret" })).rejects.toMatchObject({
      status: 400,
      message,
    });
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(await getToken(envWith(db), "claude")).toBeNull();
  });

  it("validates then saves as paste without bootstrap or refresh grant", async () => {
    const fetchMock = vi.fn(async () => jsonResponse({ id: "msg-1", content: [] }));
    vi.stubGlobal("fetch", fetchMock);
    const { db } = stubDb();
    const env = envWith(db);
    const result = await complete(env, "claude", { token: "sk-ant-oat-secret" });
    expect(result).toEqual({ connected: true, accountLabel: null });
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe("https://api.anthropic.com/v1/messages");
    expect(init.method).toBe("POST");
    expect(init.headers).toMatchObject({
      Authorization: "Bearer sk-ant-oat-secret",
      "anthropic-version": "2023-06-01",
      "anthropic-beta": BETA,
      "Content-Type": "application/json",
    });
    expect(JSON.parse(String(init.body))).toEqual({
      model: "claude-haiku-4-5-20251001",
      max_tokens: 1,
      messages: [{ role: "user", content: "test" }],
    });

    const row = (await getToken(env, "claude"))!;
    expect(row.accessToken).toBe("sk-ant-oat-secret");
    expect(row.refreshToken).toBeNull();
    expect(row.authKind).toBe("paste");
    expect(row.meta).toMatchObject({
      tokenKind: "setup",
      cliUserID: expect.stringMatching(/^[a-f0-9]{64}$/),
    });
    await expect(claude().refresh!(claude().config, "unused", row.meta ?? {})).rejects.toThrow(
      "no refresh grant for setup tokens",
    );
  });

  it("preserves the shared paste-token route for device adapters exposing importToken", async () => {
    const fake: OAuthAdapter = {
      prefix: "fake-device-import",
      flowMode: "device",
      config: {},
      importToken: async (raw) => ({ access_token: String(raw.access_token).trim() }),
      mapTokens: (tokens) => ({
        accessToken: String(tokens.access_token),
        meta: { imported: true },
      }),
    };
    registerAdapter(fake);
    const { db } = stubDb();
    const env = envWith(db);
    await complete(env, fake.prefix, { token: " device-token " });
    const row = (await getToken(env, fake.prefix))!;
    expect(row.accessToken).toBe("device-token");
    expect(row.authKind).toBe("paste");
    expect(row.meta).toEqual({ imported: true });
  });
});

describe("Claude OAuth refresh and stable CLI identity", () => {
  it("refresh sends the beta header, rotates the refresh token, and preserves cliUserID", async () => {
    const fetchMock = vi.fn(async () =>
      jsonResponse({
        access_token: "claude-new-at",
        refresh_token: "claude-new-rt",
        expires_in: 3600,
      }),
    );
    vi.stubGlobal("fetch", fetchMock);
    const { db } = stubDb();
    const env = envWith(db);
    await saveToken(env, {
      provider: "claude",
      accessToken: "claude-old-at",
      refreshToken: "claude-old-rt",
      expiresIn: 10,
      authKind: "oauth",
      meta: {
        cliUserID: "preserve-this-cli-id",
        account_uuid: "acct-old",
        email: "old@example.com",
      },
    });
    expect(await ensureFreshToken(env, "claude")).toBe("claude-new-at");
    const [url, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe("https://api.anthropic.com/v1/oauth/token");
    expect(init.method).toBe("POST");
    expect(init.headers).toMatchObject({
      Accept: "application/json",
      "Content-Type": "application/x-www-form-urlencoded",
      "anthropic-beta": BETA,
    });
    const body = new URLSearchParams(String(init.body));
    expect([...body.keys()].sort()).toEqual(["grant_type", "refresh_token", "client_id"].sort());
    expect(body.get("grant_type")).toBe("refresh_token");
    expect(body.get("refresh_token")).toBe("claude-old-rt");
    expect(body.get("client_id")).toBe(CLIENT_ID);
    const row = (await getToken(env, "claude"))!;
    expect(row.refreshToken).toBe("claude-new-rt");
    expect(row.meta).toMatchObject({
      cliUserID: "preserve-this-cli-id",
      account_uuid: "acct-old",
      email: "old@example.com",
    });
  });
});
