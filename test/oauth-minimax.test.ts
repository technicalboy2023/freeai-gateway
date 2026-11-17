import { beforeEach, describe, expect, it, vi } from "vitest";
import { deriveChallenge } from "../src/oauth/pkce";
import { getToken, saveToken } from "../src/oauth/store";
import { ensureFreshToken } from "../src/oauth/refresh";
import { getAdapter, OAuthError, poll, start } from "../src/oauth/engine";
import type { Env } from "../src/env";
import type { OAuthAdapter } from "../src/oauth/types";

const KEY = btoa(String.fromCharCode(...new Uint8Array(32).fill(0x41)))
  .replace(/\+/g, "-")
  .replace(/\//g, "_")
  .replace(/=+$/, "");

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

function adapter(): OAuthAdapter {
  const a = getAdapter("minimax-code");
  if (!a) throw new Error("minimax-code adapter was not registered");
  return a;
}

const DEVICE = {
  device_code: "mm-dc-1",
  user_code: "MM-123",
  verification_uri: "https://platform.minimax.io/login",
  expires_in: 600,
  interval: 7,
};

beforeEach(() => {
  vi.unstubAllGlobals();
});

describe("minimax-code registration and device start", () => {
  it("uses the pinned account config and PKCE-aware device body", async () => {
    expect(adapter().flowMode).toBe("device");
    expect(adapter().config).toMatchObject({
      clientId: "mcode-public",
      scope: "agent.default",
      audience: "agent-backend",
      accountBase: "https://account.minimax.io",
      deviceCodeUrl: "https://account.minimax.io/oauth2/device/code",
      tokenUrl: "https://account.minimax.io/oauth2/token",
      userAgent: "minimax-code-cli",
    });
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(jsonResponse({ ...DEVICE, expires_in: undefined, interval: undefined }))
      .mockResolvedValueOnce(jsonResponse({ error: "authorization_pending" }));
    vi.stubGlobal("fetch", fetchMock);
    const env = envWith(stubDb().db);
    const result = await start(env, "minimax-code", new URL("https://gw.test/x"));
    expect(result).toMatchObject({
      mode: "device",
      user_code: "MM-123",
      verification_uri: DEVICE.verification_uri,
      expires_in: 300,
      interval: 5,
    });
    const [startUrl, startInit] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
    expect(startUrl).toBe("https://account.minimax.io/oauth2/device/code");
    expect(startInit.method).toBe("POST");
    expect(startInit.redirect).toBe("error");
    expect((startInit.headers as Record<string, string>)["User-Agent"]).toBe("minimax-code-cli");
    const startForm = new URLSearchParams(String(startInit.body));
    expect(startForm.get("client_id")).toBe("mcode-public");
    expect(startForm.get("scope")).toBe("agent.default");
    expect(startForm.get("audience")).toBe("agent-backend");
    const challenge = startForm.get("code_challenge")!;
    expect(challenge).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(startForm.get("code_challenge_method")).toBe("S256");

    expect(await poll(env, "minimax-code")).toEqual({
      status: "pending",
      error: "authorization_pending",
    });
    const [pollUrl, pollInit] = fetchMock.mock.calls[1] as unknown as [string, RequestInit];
    expect(pollUrl).toBe("https://account.minimax.io/oauth2/token");
    const pollForm = new URLSearchParams(String(pollInit.body));
    expect(pollForm.get("grant_type")).toBe("urn:ietf:params:oauth:grant-type:device_code");
    expect(pollForm.get("device_code")).toBe("mm-dc-1");
    expect(pollForm.get("client_id")).toBe("mcode-public");
    expect(await deriveChallenge(pollForm.get("code_verifier")!)).toBe(challenge);
  });

  it("unreachable account endpoint → 502 with pinned message", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => {
      throw new TypeError("failed to fetch");
    }));
    const error = await start(
      envWith(stubDb().db),
      "minimax-code",
      new URL("https://gw.test/x"),
    ).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(OAuthError);
    expect((error as OAuthError).status).toBe(502);
    expect((error as Error).message).toContain(
      "MiniMax Code device authorization failed: the account endpoint is unreachable",
    );
  });

  it("device response missing code/user_code reports the upstream reason", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => jsonResponse({ error: "invalid_client", error_description: "bad client" })));
    const error = await start(
      envWith(stubDb().db),
      "minimax-code",
      new URL("https://gw.test/x"),
    ).catch((e: unknown) => e);
    expect((error as OAuthError).status).toBe(502);
    expect((error as Error).message).toContain("bad client");
  });
});

describe("minimax-code poll", () => {
  it.each([
    [400, { error: "authorization_pending" }, { status: "pending", error: "authorization_pending" }],
    [400, { error: "expired_token", error_description: "expired" }, { status: "error", error: "expired_token" }],
    [403, { error: "access_denied", error_description: "denied" }, { status: "error", error: "access_denied" }],
  ] as const)("HTTP %i body %j controls the poll result", async (status, body, expected) => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(jsonResponse(DEVICE))
      .mockResolvedValueOnce(jsonResponse(body, status));
    vi.stubGlobal("fetch", fetchMock);
    const env = envWith(stubDb().db);
    await start(env, "minimax-code", new URL("https://gw.test/x"));
    expect(await poll(env, "minimax-code")).toEqual(expected);
  });

  it("non-ok response with no error → poll_failed with status detail", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(jsonResponse(DEVICE))
      .mockResolvedValueOnce(jsonResponse({ message: "oops" }, 503));
    vi.stubGlobal("fetch", fetchMock);
    const env = envWith(stubDb().db);
    await start(env, "minimax-code", new URL("https://gw.test/x"));
    expect(await poll(env, "minimax-code")).toEqual({
      status: "error",
      error: "poll_failed: Poll failed: 503",
    });
  });
});

describe("minimax-code mapping and refresh", () => {
  it("stores actual OAuth tokens, pinned label/meta, and uses accountBase from priorMeta on refresh", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(jsonResponse(DEVICE))
      .mockResolvedValueOnce(jsonResponse({
        access_token: "mm-at",
        refresh_token: "mm-rt",
        expires_in: 1800,
      }));
    vi.stubGlobal("fetch", fetchMock);
    const { db } = stubDb();
    const env = envWith(db);
    await start(env, "minimax-code", new URL("https://gw.test/x"));
    expect(await poll(env, "minimax-code")).toEqual({ status: "connected" });
    const row = (await getToken(env, "minimax-code"))!;
    expect(row.accessToken).toBe("mm-at");
    expect(row.refreshToken).toBe("mm-rt");
    expect(row.accountLabel).toBe("MiniMax Code account");
    expect(row.meta).toEqual({
      authKind: "oauth",
      accountBase: "https://account.minimax.io",
    });

    const refreshMock = vi.fn(async () =>
      jsonResponse({ access_token: "mm-new-at", refresh_token: "mm-new-rt", expires_in: 3600 }),
    );
    vi.stubGlobal("fetch", refreshMock);
    await saveToken(env, {
      provider: "minimax-code",
      accessToken: "old-at",
      refreshToken: "old-rt",
      expiresIn: 5,
      authKind: "oauth",
      meta: { authKind: "oauth", accountBase: "https://account.minimax.cn" },
    });
    expect(await ensureFreshToken(env, "minimax-code")).toBe("mm-new-at");
    const [url, init] = refreshMock.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe("https://account.minimax.cn/oauth2/token");
    const form = new URLSearchParams(String(init.body));
    expect(form.get("grant_type")).toBe("refresh_token");
    expect(form.get("refresh_token")).toBe("old-rt");
    expect(form.get("client_id")).toBe("mcode-public");
    expect(form.get("scope")).toBe("agent.default");
    expect(form.get("audience")).toBe("agent-backend");
    expect(form.has("code_verifier")).toBe(false);
    expect(form.has("code_challenge")).toBe(false);
  });
});
