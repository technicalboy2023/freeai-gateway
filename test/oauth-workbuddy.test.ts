import { beforeEach, describe, expect, it, vi } from "vitest";
import { getToken, saveToken } from "../src/oauth/store";
import { ensureFreshToken, TokenExpiredError } from "../src/oauth/refresh";
import { getAdapter, poll, start } from "../src/oauth/engine";
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
  const a = getAdapter("workbuddy");
  if (!a) throw new Error("workbuddy adapter was not registered");
  return a;
}

const STATE_URL = "https://www.workbuddy.ai/v2/plugin/auth/state";
const TOKEN_URL = "https://www.workbuddy.ai/v2/plugin/auth/token";
const REFRESH_URL = "https://www.workbuddy.ai/v2/plugin/auth/token/refresh";

beforeEach(() => {
  vi.unstubAllGlobals();
});

describe("workbuddy registration and state start", () => {
  it("uses the pinned endpoints and sends platform in both query + JSON body", async () => {
    expect(adapter().flowMode).toBe("device");
    expect(adapter().config).toMatchObject({ stateUrl: STATE_URL, tokenUrl: TOKEN_URL, refreshUrl: REFRESH_URL });
    const fetchMock = vi.fn(async () =>
      jsonResponse({ code: 0, data: { state: "wb-state-1", authUrl: "https://workbuddy.ai/authorize" } }),
    );
    vi.stubGlobal("fetch", fetchMock);
    const result = await start(
      envWith(stubDb().db),
      "workbuddy",
      new URL("https://gw.test/x"),
    );
    expect(result).toEqual({
      mode: "device",
      user_code: "wb-state-1",
      verification_uri: "https://workbuddy.ai/authorize",
      verification_uri_complete: "https://workbuddy.ai/authorize",
      expires_in: 600,
      interval: 5,
    });
    const [url, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe(`${STATE_URL}?platform=CLI`);
    expect(init.method).toBe("POST");
    expect(init.headers).toMatchObject({
      Accept: "application/json",
      "Content-Type": "application/json",
      "X-Product": "SaaS",
    });
    expect(init.body).toBe(JSON.stringify({ platform: "CLI" }));
  });

  it("code !== 0 becomes a 502 state error with upstream msg", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => jsonResponse({ code: 7, msg: "service unavailable" })));
    const error = await start(
      envWith(stubDb().db),
      "workbuddy",
      new URL("https://gw.test/x"),
    ).catch((e: unknown) => e);
    expect((error as { status: number }).status).toBe(502);
    expect((error as Error).message).toContain("WorkBuddy state error: service unavailable");
  });

  it("missing state is rejected", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => jsonResponse({ code: 0, data: { authUrl: "https://x" } })));
    const error = await start(
      envWith(stubDb().db),
      "workbuddy",
      new URL("https://gw.test/x"),
    ).catch((e: unknown) => e);
    expect((error as { status: number }).status).toBe(502);
    expect((error as Error).message).toContain("WorkBuddy state error:");
  });
});

describe("workbuddy poll", () => {
  it("gets the state token, maps the success envelope, and stores real tokens", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(jsonResponse({
        code: 0,
        data: { state: "state / 1", url: "https://workbuddy.ai/device" },
      }))
      .mockResolvedValueOnce(jsonResponse({
        code: 0,
        data: { accessToken: "wb-at", refreshToken: "wb-rt", expiresIn: 3600 },
      }));
    vi.stubGlobal("fetch", fetchMock);
    const { db } = stubDb();
    const env = envWith(db);
    await start(env, "workbuddy", new URL("https://gw.test/x"));
    expect(await poll(env, "workbuddy")).toEqual({ status: "connected" });
    const [url, init] = fetchMock.mock.calls[1] as unknown as [string, RequestInit];
    expect(url).toBe(`${TOKEN_URL}?state=state%20%2F%201`);
    expect(init.method).toBe("GET");
    expect(init.headers).toMatchObject({ Accept: "application/json", "X-Product": "SaaS" });
    const row = (await getToken(env, "workbuddy"))!;
    expect(row.accessToken).toBe("wb-at");
    expect(row.refreshToken).toBe("wb-rt");
    expect(row.expiresAt).toBeGreaterThan(Date.now());
    expect(row.meta).toEqual({});
  });

  it("code 11217 maps to authorization_pending and keeps the engine flow alive", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(jsonResponse({ code: 0, data: { state: "wait", authUrl: "https://wb.test" } }))
      .mockResolvedValueOnce(jsonResponse({ code: 11217, msg: "not approved yet" }));
    vi.stubGlobal("fetch", fetchMock);
    const { db } = stubDb();
    const env = envWith(db);
    await start(env, "workbuddy", new URL("https://gw.test/x"));
    expect(await poll(env, "workbuddy")).toEqual({ status: "pending", error: "authorization_pending" });
  });

  it("terminal code/msg reaches the engine error text", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(jsonResponse({ code: 0, data: { state: "bad", authUrl: "https://wb.test" } }))
      .mockResolvedValueOnce(jsonResponse({ code: 500, msg: "server rejected state" }));
    vi.stubGlobal("fetch", fetchMock);
    const { db } = stubDb();
    const env = envWith(db);
    await start(env, "workbuddy", new URL("https://gw.test/x"));
    expect(await poll(env, "workbuddy")).toEqual({
      status: "error",
      error: "poll failed (code 500): server rejected state",
    });
  });
});

describe("workbuddy token mapping and refresh", () => {
  it("mapTokens defaults expiry to one year and refresh returns snake_case", async () => {
    const mapped = adapter().mapTokens({ access_token: "wb-at" });
    expect(mapped).toEqual({
      accessToken: "wb-at",
      refreshToken: null,
      expiresIn: 31_104_000,
      meta: {},
      name: undefined,
    });

    const fetchMock = vi.fn(async () =>
      jsonResponse({ code: 0, data: { accessToken: "wb-new-at", refreshToken: "wb-new-rt", expiresIn: 3600 } }),
    );
    vi.stubGlobal("fetch", fetchMock);
    const { db } = stubDb();
    const env = envWith(db);
    await saveToken(env, {
      provider: "workbuddy",
      accessToken: "old-at",
      refreshToken: "old-rt",
      expiresIn: 10,
      authKind: "oauth",
      meta: {},
    });
    expect(await ensureFreshToken(env, "workbuddy")).toBe("wb-new-at");
    const [url, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe(REFRESH_URL);
    expect(init.method).toBe("POST");
    expect(init.headers).toMatchObject({
      "Content-Type": "application/json",
      Accept: "application/json",
      "X-Refresh-Token": "old-rt",
      "X-Product": "SaaS",
      "X-Domain": "www.workbuddy.ai",
      "User-Agent": "WorkBuddy/5.5.6",
    });
    expect(init.body).toBe("{}");
    const row = (await getToken(env, "workbuddy"))!;
    expect(row.accessToken).toBe("wb-new-at");
    expect(row.refreshToken).toBe("wb-new-rt");
    expect(row.expiresAt).toBeGreaterThan(Date.now());
  });

  it("refresh code failure or missing accessToken throws the pinned error", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(jsonResponse({ code: 1, msg: "denied", data: { accessToken: "should-not-use" } }))
      .mockResolvedValueOnce(jsonResponse({ code: 0, data: {} }))
      .mockResolvedValueOnce(jsonResponse({ code: 1, msg: "denied", data: { accessToken: "should-not-use" } }));
    vi.stubGlobal("fetch", fetchMock);
    await expect(adapter().refresh!(adapter().config, "old-rt")).rejects.toThrow(
      "WorkBuddy token refresh returned no token",
    );
    await expect(adapter().refresh!(adapter().config, "old-rt")).rejects.toThrow(
      "WorkBuddy token refresh returned no token",
    );

    const { db } = stubDb();
    const env = envWith(db);
    await saveToken(env, {
      provider: "workbuddy",
      accessToken: "old-at",
      refreshToken: "old-rt",
      expiresIn: 10,
      authKind: "oauth",
    });
    await expect(ensureFreshToken(env, "workbuddy")).rejects.toBeInstanceOf(TokenExpiredError);
    expect((await getToken(env, "workbuddy"))?.lastError).toBe(
      "WorkBuddy token refresh returned no token",
    );
  });
});
