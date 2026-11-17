import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ensureFreshToken, markTokenError, REFRESH_SKEW_SEC, TokenExpiredError } from "../src/oauth/refresh";
import { registerAdapter } from "../src/oauth/engine";
import { getToken, getTokenStatus, saveToken } from "../src/oauth/store";
import type { Env } from "../src/env";
import type { OAuthAdapter } from "../src/oauth/types";

const KEY = btoa(String.fromCharCode(...new Uint8Array(32).fill(0x41)))
  .replace(/\+/g, "-")
  .replace(/\//g, "_")
  .replace(/=+$/, "");

function stubDb() {
  const tokens = new Map<string, Record<string, unknown>>();
  const db = {
    prepare: (sql: string) => ({
      bind: (...params: unknown[]) => ({
        first: async <T,>() => {
          if (!sql.startsWith("SELECT")) return null;
          const row = tokens.get(String(params[0]));
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
          return { success: true };
        },
      }),
    }),
  } as unknown as D1Database;
  return { db, tokens };
}

function envWith(db: D1Database): Env {
  return { DB: db, OAUTH_ENCRYPTION_KEY: KEY } as unknown as Env;
}

function refreshAdapter(overrides: Partial<OAuthAdapter> = {}): OAuthAdapter {
  return {
    prefix: "fakerefresh",
    flowMode: "paste",
    config: { tokenUrl: "https://up.test/token", clientId: "cid-1" },
    mapTokens: (tokens) => ({
      accessToken: String(tokens.access_token),
      refreshToken: (tokens.refresh_token as string) ?? null,
      expiresIn: (tokens.expires_in as number) ?? 3600,
    }),
    ...overrides,
  };
}

function jsonResponse(payload: unknown, status = 200): Response {
  return new Response(JSON.stringify(payload), {
    status,
    headers: { "content-type": "application/json" },
  });
}

let fetchMock: ReturnType<typeof vi.fn>;

beforeEach(() => {
  registerAdapter(refreshAdapter());
  fetchMock = vi.fn();
  vi.stubGlobal("fetch", fetchMock);
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("ensureFreshToken", () => {
  it("fresh-enough token returns as-is, no fetch", async () => {
    const { db } = stubDb();
    const env = envWith(db);
    await saveToken(env, {
      provider: "fakerefresh",
      accessToken: "still-good",
      expiresIn: 3600,
      refreshToken: "rt",
      authKind: "oauth",
    });
    expect(await ensureFreshToken(env, "fakerefresh")).toBe("still-good");
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("no expiry (null) returns as-is, no fetch", async () => {
    const { db } = stubDb();
    const env = envWith(db);
    await saveToken(env, { provider: "fakerefresh", accessToken: "forever", authKind: "oauth" });
    expect(await ensureFreshToken(env, "fakerefresh")).toBe("forever");
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("near-expiry fires exactly one standard refresh POST and persists rotated tokens", async () => {
    const { db, tokens } = stubDb();
    const env = envWith(db);
    await saveToken(env, {
      provider: "fakerefresh",
      accessToken: "old-at",
      expiresIn: 10, // < 300s skew
      refreshToken: "old-rt",
      authKind: "paste",
    });
    fetchMock.mockResolvedValueOnce(
      jsonResponse({ access_token: "new-at", refresh_token: "new-rt", expires_in: 7200 }),
    );
    expect(await ensureFreshToken(env, "fakerefresh")).toBe("new-at");
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("https://up.test/token");
    expect(init.method).toBe("POST");
    const body = String(init.body);
    expect(body).toContain("grant_type=refresh_token");
    expect(body).toContain("client_id=cid-1");
    expect(body).toContain("refresh_token=old-rt");
    const row = (await getToken(env, "fakerefresh"))!;
    expect(row.accessToken).toBe("new-at");
    expect(row.refreshToken).toBe("new-rt");
    expect(row.lastRefreshAt).toBeGreaterThan(0);
    // pre-flight ruling: refresh preserves the original authKind
    expect(row.authKind).toBe("paste");
    expect(tokens.get("fakerefresh")!.last_error).toBeNull();
  });

  it("refresh re-save preserves connected_at/account_label/meta and keeps the old refresh_token when the response omits it", async () => {
    const { db } = stubDb();
    const env = envWith(db);
    // Calls 1-2 (initial save: expires_at bind + connected_at bind) land at
    // T=1000; every later call (freshness check, refresh re-save) far future.
    const nowSpy = vi
      .spyOn(Date, "now")
      .mockReturnValueOnce(1000)
      .mockReturnValueOnce(1000)
      .mockReturnValue(999_999);
    try {
      await saveToken(env, {
        provider: "fakerefresh",
        accessToken: "old-at",
        expiresIn: 10,
        refreshToken: "keep-rt",
        name: "acct-1",
        meta: { webId: "w-1" },
        authKind: "paste",
      });
      // Refresh response carries no refresh_token and no profile fields —
      // the re-save must merge with the existing row, not blank it.
      fetchMock.mockResolvedValueOnce(jsonResponse({ access_token: "new-at", expires_in: 7200 }));
      expect(await ensureFreshToken(env, "fakerefresh")).toBe("new-at");
      const row = (await getToken(env, "fakerefresh"))!;
      expect(row.refreshToken).toBe("keep-rt");
      expect(row.accountLabel).toBe("acct-1");
      expect(row.meta).toEqual({ webId: "w-1" });
      expect(row.connectedAt).toBe(1000);
    } finally {
      nowSpy.mockRestore();
    }
  });

  it("invalid_grant → TokenExpiredError + last_error recorded", async () => {
    const { db, tokens } = stubDb();
    const env = envWith(db);
    await saveToken(env, {
      provider: "fakerefresh",
      accessToken: "old-at",
      expiresIn: 10,
      refreshToken: "dead-rt",
      authKind: "oauth",
    });
    fetchMock.mockResolvedValueOnce(jsonResponse({ error: "invalid_grant" }, 400));
    await expect(ensureFreshToken(env, "fakerefresh")).rejects.toThrow(TokenExpiredError);
    expect(String(tokens.get("fakerefresh")!.last_error)).toContain("invalid_grant");
  });

  it("refresh HTTP failure → TokenExpiredError + last_error", async () => {
    const { db, tokens } = stubDb();
    const env = envWith(db);
    await saveToken(env, {
      provider: "fakerefresh",
      accessToken: "old-at",
      expiresIn: 10,
      refreshToken: "rt",
      authKind: "oauth",
    });
    fetchMock.mockResolvedValueOnce(new Response("boom", { status: 500 }));
    await expect(ensureFreshToken(env, "fakerefresh")).rejects.toThrow(TokenExpiredError);
    expect(String(tokens.get("fakerefresh")!.last_error)).toMatch(/refresh failed/);
  });

  it("adapter refresh hook replaces the standard POST", async () => {
    const { db } = stubDb();
    const env = envWith(db);
    await saveToken(env, {
      provider: "fakerefresh",
      accessToken: "old-at",
      expiresIn: 10,
      refreshToken: "rt",
      authKind: "oauth",
    });
    registerAdapter(
      refreshAdapter({
        refresh: async () => ({ access_token: "hook-at" }),
      }),
    );
    expect(await ensureFreshToken(env, "fakerefresh")).toBe("hook-at");
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("missing row → TokenExpiredError not connected", async () => {
    const { db } = stubDb();
    await expect(ensureFreshToken(envWith(db), "fakerefresh")).rejects.toThrow(/not connected/);
  });

  it("expired + no refresh grant records reconnect-required status before throwing", async () => {
    const { db } = stubDb();
    const env = envWith(db);
    await saveToken(env, {
      provider: "fakerefresh",
      accessToken: "dead-at",
      expiresIn: -10,
      authKind: "oauth",
    });
    await expect(ensureFreshToken(env, "fakerefresh")).rejects.toMatchObject({
      prefix: "fakerefresh",
      detail: "token expired, no refresh grant",
    });
    expect(await getTokenStatus(env, "fakerefresh")).toMatchObject({
      connected: true,
      lastError: "token expired, no refresh grant",
    });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("REFRESH_SKEW_SEC is 300", () => {
    expect(REFRESH_SKEW_SEC).toBe(300);
  });
});

describe("markTokenError", () => {
  it("records last_error on the row", async () => {
    const { db, tokens } = stubDb();
    const env = envWith(db);
    await saveToken(env, { provider: "fakerefresh", accessToken: "a", authKind: "oauth" });
    await markTokenError(env, "fakerefresh", "something broke");
    expect(String(tokens.get("fakerefresh")!.last_error)).toBe("something broke");
  });

  it("unknown provider is a no-op", async () => {
    const { db } = stubDb();
    await expect(markTokenError(envWith(db), "ghost", "x")).resolves.toBeUndefined();
  });
});
