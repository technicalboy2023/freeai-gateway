import { beforeEach, describe, expect, it, vi } from "vitest";
import { complete, getAdapter, OAuthError, poll, start } from "../src/oauth/engine";
import { ensureFreshToken, TokenExpiredError } from "../src/oauth/refresh";
import { deriveChallenge } from "../src/oauth/pkce";
import { getPending, getToken, saveToken } from "../src/oauth/store";
import type { Env } from "../src/env";
import type { OAuthAdapter } from "../src/oauth/types";

const KEY = btoa(String.fromCharCode(...new Uint8Array(32).fill(0x41)))
  .replace(/\+/g, "-")
  .replace(/\//g, "_")
  .replace(/=+$/, "");
const LOGIN_URL = "https://cursor.com/loginDeepControl";
const POLL_URL = "https://api2.cursor.sh/auth/poll";
const REFRESH_URL = "https://api2.cursor.sh/auth/exchange_user_api_key";
const CLIENT_VERSION = "2026.07.08-0c04a8a";
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

function cursor(): OAuthAdapter {
  const adapter = getAdapter("cursor");
  if (!adapter) throw new Error("cursor adapter was not registered");
  return adapter;
}

beforeEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
});

describe("Cursor deep-control device flow", () => {
  it("builds the login URL with an engine-generated challenge and UUID device code", async () => {
    expect(cursor().flowMode).toBe("device");
    expect(cursor().config).toEqual({
      loginUrl: LOGIN_URL,
      pollUrl: POLL_URL,
      refreshUrl: REFRESH_URL,
      clientVersion: CLIENT_VERSION,
      clientType: "ide",
    });
    const { db } = stubDb();
    const env = envWith(db);
    const result = await start(env, "cursor", new URL(`${ORIGIN}/admin/api/oauth/cursor/start`));
    expect(result.mode).toBe("device");
    if (result.mode !== "device") throw new Error("expected device flow");

    const loginUrl = new URL(result.verification_uri);
    expect(loginUrl.origin + loginUrl.pathname).toBe(LOGIN_URL);
    expect([...loginUrl.searchParams.keys()].sort()).toEqual(
      ["challenge", "uuid", "mode", "redirectTarget"].sort(),
    );
    expect(loginUrl.searchParams.get("uuid")).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i,
    );
    expect(result.user_code).toBe(loginUrl.searchParams.get("uuid"));
    expect(loginUrl.searchParams.get("mode")).toBe("login");
    expect(loginUrl.searchParams.get("redirectTarget")).toBe("cli");
    expect(loginUrl.searchParams.get("challenge")).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(result.verification_uri_complete).toBe(result.verification_uri);
    expect(result.expires_in).toBe(900);
    expect(result.interval).toBe(2);

    const pending = await getPending(env, "cursor");
    expect(pending?.deviceCode).toBe(result.user_code);
    expect(await deriveChallenge(pending?.codeVerifier ?? "")).toBe(
      loginUrl.searchParams.get("challenge"),
    );
  });
});

describe("Cursor device polling", () => {
  it("GETs the poll URL with uuid and verifier and sends no custom headers", async () => {
    const fetchMock = vi.fn(async () =>
      jsonResponse({ accessToken: "cursor-at", refreshToken: "cursor-rt" }),
    );
    vi.stubGlobal("fetch", fetchMock);
    const result = await cursor().pollToken!(cursor().config, "device-uuid", "pkce-verifier");
    expect(result).toEqual({
      ok: true,
      data: { access_token: "cursor-at", refresh_token: "cursor-rt" },
    });
    const [url, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
    const parsed = new URL(url);
    expect(parsed.origin + parsed.pathname).toBe(POLL_URL);
    expect([...parsed.searchParams.keys()].sort()).toEqual(["uuid", "verifier"]);
    expect(parsed.searchParams.get("uuid")).toBe("device-uuid");
    expect(parsed.searchParams.get("verifier")).toBe("pkce-verifier");
    expect(init).toBeUndefined();
  });

  it("maps 404 to authorization_pending", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => new Response("", { status: 404 })));
    expect(await cursor().pollToken!(cursor().config, "uuid", "verifier")).toEqual({
      ok: false,
      data: { error: "authorization_pending" },
    });
  });

  it("rejects a successful poll body missing either credential", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => jsonResponse({ accessToken: "cursor-at" })),
    );
    expect(await cursor().pollToken!(cursor().config, "uuid", "verifier")).toEqual({
      ok: false,
      data: { error: "Cursor auth response missing tokens" },
    });
  });

  it("surfaces non-404 poll status with the HTTP status", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => new Response("upstream error", { status: 500 })));
    expect(await cursor().pollToken!(cursor().config, "uuid", "verifier")).toEqual({
      ok: false,
      data: { error: "Cursor auth poll failed: 500" },
    });
  });

  it("does not connect when a device poll omits the refresh token", async () => {
    const fetchMock = vi.fn(async () => jsonResponse({ accessToken: "cursor-at" }));
    vi.stubGlobal("fetch", fetchMock);
    const { db, pending } = stubDb();
    const env = envWith(db);
    await start(env, "cursor", new URL(`${ORIGIN}/start`));
    expect(await poll(env, "cursor")).toEqual({
      status: "error",
      error: "Cursor auth response missing tokens",
    });
    expect(pending.has("cursor")).toBe(false);
    expect(await getToken(env, "cursor")).toBeNull();
  });
});

describe("Cursor access-token mapping", () => {
  it("maps deep-control JWT identity and subtracts the five-minute refresh skew", () => {
    const exp = Math.floor(Date.now() / 1000) + 3600;
    const accessToken = jwt({ exp, email: "CURSOR@Example.COM", sub: "cursor-account-1" });
    const mapped = cursor().mapTokens({
      access_token: accessToken,
      refresh_token: "cursor-rt",
    });
    expect(mapped.accessToken).toBe(accessToken);
    expect(mapped.refreshToken).toBe("cursor-rt");
    expect(mapped.expiresIn).toBeGreaterThanOrEqual(3299);
    expect(mapped.expiresIn).toBeLessThanOrEqual(3300);
    expect(mapped.email).toBe("cursor@example.com");
    expect(mapped.name).toBe("cursor@example.com");
    expect(mapped.meta).toEqual({
      accountId: "cursor-account-1",
      authMethod: "deep_control",
      machineId: null,
    });
  });

  it("uses a one-hour fallback when deep-control access JWT has no decodable expiry", () => {
    const mapped = cursor().mapTokens({
      access_token: "not-a-jwt-but-long-enough-to-be-an-access-token",
      refresh_token: "cursor-rt",
    });
    expect(mapped.expiresIn).toBe(3600);
    expect(mapped.email).toBeNull();
    expect(mapped.name).toBeNull();
  });

  it("requires both deep-control credentials", () => {
    expect(() =>
      cursor().mapTokens({ access_token: "cursor-at-without-refresh-token" }),
    ).toThrow("Cursor auth response missing tokens");
  });
});

describe("Cursor paste-token import", () => {
  it("imports a raw JWT as cursor-agent and uses its exp claim", async () => {
    const exp = Math.floor(Date.now() / 1000) + 7200;
    const accessToken = jwt({ exp, email: "CURSOR@Example.COM", sub: "cursor-user-1" });
    expect(accessToken.length).toBeGreaterThanOrEqual(50);
    const { db } = stubDb();
    const env = envWith(db);
    const result = await complete(env, "cursor", { token: accessToken });
    expect(result).toEqual({ connected: true, accountLabel: "cursor@example.com" });
    const row = (await getToken(env, "cursor"))!;
    expect(row.accessToken).toBe(accessToken);
    expect(row.refreshToken).toBeNull();
    expect(row.authKind).toBe("paste");
    expect(row.accountLabel).toBe("cursor@example.com");
    expect(row.expiresAt).toBeLessThanOrEqual(exp * 1000);
    expect(row.expiresAt).toBeGreaterThanOrEqual(exp * 1000 - 1000);
    expect(row.meta).toEqual({
      accountId: "cursor-user-1",
      authMethod: "cursor-agent",
      machineId: null,
    });
  });

  it("rejects short pasted tokens with the pinned 400 message", async () => {
    const error = await complete(envWith(stubDb().db), "cursor", { token: "short-token" }).catch(
      (err: unknown) => err,
    );
    expect(error).toBeInstanceOf(OAuthError);
    expect((error as OAuthError).status).toBe(400);
    expect((error as Error).message).toBe("Invalid token format. Token appears too short.");
  });

  it("imports a JSON paste object, retains refresh/machine fields, and marks it imported", async () => {
    const accessToken = jwt({
      exp: Math.floor(Date.now() / 1000) + 3600,
      email: "imported@example.com",
      sub: "imported-account",
    });
    const { db } = stubDb();
    const env = envWith(db);
    await complete(
      env,
      "cursor",
      {
        token: JSON.stringify({
          accessToken,
          refreshToken: "imported-refresh",
          machineId: "machine-identifier",
        }),
      },
    );
    const row = (await getToken(env, "cursor"))!;
    expect(row.accessToken).toBe(accessToken);
    expect(row.refreshToken).toBe("imported-refresh");
    expect(row.accountLabel).toBe("imported@example.com");
    expect(row.meta).toEqual({
      accountId: "imported-account",
      authMethod: "imported",
      machineId: "machine-identifier",
    });
  });

  it("rejects machine IDs that look like long hex or UUID identifiers", async () => {
    const accessToken = jwt({ email: "id@example.com" });
    const error = await complete(
      envWith(stubDb().db),
      "cursor",
      { token: JSON.stringify({ accessToken, machineId: "a".repeat(32) }) },
    ).catch((err: unknown) => err);
    expect(error).toBeInstanceOf(OAuthError);
    expect((error as OAuthError).status).toBe(400);
    expect((error as Error).message).toBe("Invalid machine ID format.");
  });

  it("falls back to a one-day expiry when an imported JWT has no exp claim", () => {
    const accessToken = jwt({ sub: "cursor-user" });
    const imported = cursor().importToken!;
    return expect(imported({ access_token: accessToken })).resolves.toMatchObject({
      accessToken,
      expiresIn: 86_400,
      authMethod: "cursor-agent",
    });
  });
});

describe("Cursor refresh", () => {
  it("POSTs JSON to the custom refresh endpoint and preserves a missing rotated token", async () => {
    const accessToken = jwt({
      exp: Math.floor(Date.now() / 1000) + 3600,
      email: "refresh@example.com",
      sub: "refresh-account",
    });
    const fetchMock = vi.fn(async () => jsonResponse({ accessToken }));
    vi.stubGlobal("fetch", fetchMock);
    const { db } = stubDb();
    const env = envWith(db);
    await saveToken(env, {
      provider: "cursor",
      accessToken: "old-access-token",
      refreshToken: "old-refresh-token",
      expiresIn: 10,
      authKind: "oauth",
    });
    expect(await ensureFreshToken(env, "cursor")).toBe(accessToken);

    const [url, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe(REFRESH_URL);
    expect(init.method).toBe("POST");
    expect(init.headers).toMatchObject({
      Authorization: "Bearer old-refresh-token",
      Accept: "application/json",
      "Content-Type": "application/json",
    });
    expect(JSON.parse(String(init.body))).toEqual({});
    expect(init.signal).toBeInstanceOf(AbortSignal);
    const row = (await getToken(env, "cursor"))!;
    expect(row.refreshToken).toBe("old-refresh-token");
    expect(row.meta).toMatchObject({
      accountId: "refresh-account",
      authMethod: "deep_control",
    });
  });

  it.each([401, 403])(
    "%i refresh is terminal and is classified by the Cursor unauthorized error name",
    async (status) => {
      const fetchMock = vi.fn(async () => new Response("unauthorized", { status }));
      vi.stubGlobal("fetch", fetchMock);
      const adapter = cursor();
      const directError = await adapter.refresh!(adapter.config, "dead-refresh").catch(
        (err: unknown) => err,
      );
      expect((directError as Error).name).toBe("CursorRefreshUnauthorized");
      expect((directError as Error).message).toContain(String(status));
      expect(fetchMock).toHaveBeenCalledTimes(1);

      const { db } = stubDb();
      const env = envWith(db);
      await saveToken(env, {
        provider: "cursor",
        accessToken: "old-access",
        refreshToken: "dead-refresh",
        expiresIn: 10,
        authKind: "oauth",
      });
      const error = await ensureFreshToken(env, "cursor").catch((err: unknown) => err);
      expect(error).toBeInstanceOf(TokenExpiredError);
      expect((error as TokenExpiredError).detail).toContain(String(status));
      expect((await getToken(env, "cursor"))?.lastError).toContain(String(status));
    },
  );

  it("retries 503 responses twice with exponential jittered waits before succeeding", async () => {
    vi.useFakeTimers();
    const timeoutSpy = vi.spyOn(globalThis, "setTimeout");
    try {
      const accessToken = jwt({ exp: Math.floor(Date.now() / 1000) + 3600 });
      const fetchMock = vi
        .fn()
        .mockResolvedValueOnce(new Response("busy", { status: 503 }))
        .mockResolvedValueOnce(new Response("busy", { status: 503 }))
        .mockResolvedValueOnce(jsonResponse({ accessToken, refreshToken: "rotated-refresh" }));
      vi.stubGlobal("fetch", fetchMock);
      const pending = cursor().refresh!(cursor().config, "old-refresh");
      await vi.advanceTimersByTimeAsync(2000);
      const raw = await pending;
      expect(raw).toEqual({
        access_token: accessToken,
        refresh_token: "rotated-refresh",
      });
      expect(fetchMock).toHaveBeenCalledTimes(3);
      const delays = timeoutSpy.mock.calls.map(([callback, delay]) =>
        typeof delay === "number" ? delay : 0,
      );
      expect(delays).toHaveLength(2);
      expect(delays[0]).toBeGreaterThanOrEqual(240);
      expect(delays[0]).toBeLessThanOrEqual(360);
      expect(delays[1]).toBeGreaterThanOrEqual(480);
      expect(delays[1]).toBeLessThanOrEqual(720);
    } finally {
      timeoutSpy.mockRestore();
      vi.useRealTimers();
    }
  });

  it("records the provider-specific terminal message after three retryable failures", async () => {
    vi.useFakeTimers();
    try {
      let notifyFetchStarted!: () => void;
      const fetchStarted = new Promise<void>((resolve) => {
        notifyFetchStarted = resolve;
      });
      const fetchMock = vi.fn(async () => {
        notifyFetchStarted();
        return new Response("busy", { status: 503 });
      });
      vi.stubGlobal("fetch", fetchMock);
      const { db } = stubDb();
      const env = envWith(db);
      await saveToken(env, {
        provider: "cursor",
        accessToken: "old-access",
        refreshToken: "old-refresh",
        expiresIn: 10,
        authKind: "oauth",
      });
      const pending = ensureFreshToken(env, "cursor").then(
        (value) => ({ value }),
        (error: unknown) => ({ error }),
      );
      // Wait for the encrypted store read to reach the first upstream request
      // before advancing fake time; otherwise it could advance before the
      // retry delay is scheduled.
      await fetchStarted;
      await vi.advanceTimersByTimeAsync(0);
      await vi.advanceTimersByTimeAsync(2000);
      const result = await pending;
      if (!("error" in result)) throw new Error("expected cursor refresh to reject");
      const error = result.error;
      expect(error).toBeInstanceOf(TokenExpiredError);
      expect((error as TokenExpiredError).detail).toBe("refresh rejected");
      expect(fetchMock).toHaveBeenCalledTimes(3);
      expect((await getToken(env, "cursor"))?.lastError).toBe(
        "Cursor token refresh failed after 3 attempts (last status 503)",
      );
    } finally {
      vi.useRealTimers();
    }
  });
});
