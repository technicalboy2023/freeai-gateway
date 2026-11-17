import { beforeEach, describe, expect, it, vi } from "vitest";
import { getAdapter, poll, start } from "../src/oauth/engine";
import { ensureFreshToken, TokenExpiredError } from "../src/oauth/refresh";
import { getToken, saveToken } from "../src/oauth/store";
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
            const [provider, access, refresh, expiresAt, label, meta, ...rest] = params;
            const [authKind, connectedAt, lastRefreshAt, providerSecrets] = rest;
            tokens.set(String(provider), {
              provider,
              access_token: access,
              refresh_token: refresh ?? null,
              expires_at: expiresAt ?? null,
              account_label: label ?? null,
              meta: meta ?? null,
              provider_secrets: providerSecrets ?? null,
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
  const a = getAdapter("muse-code");
  if (!a) throw new Error("muse-code adapter was not registered");
  return a;
}

const DEVICE_URL = "https://auth.meta.com/oidc/device/authorization/";
const TOKEN_URL = "https://auth.meta.com/oidc/device/token/";
const MINT_URL = "https://api.meta.ai/muse-code/key";
const DEVICE = {
  device_code: "muse-dc-1",
  user_code: "MUSE-123",
  verification_uri: "https://auth.meta.com/device",
  verification_uri_complete: "https://auth.meta.com/device?user_code=MUSE-123",
  expires_in: 900,
  interval: 5,
};

beforeEach(() => {
  vi.unstubAllGlobals();
});

describe("muse-code registration and device start", () => {
  it("uses the trailing-slash endpoints and pinned client ID", () => {
    expect(adapter().flowMode).toBe("device");
    expect(adapter().config).toMatchObject({
      clientId: "1031625952748946",
      deviceCodeUrl: DEVICE_URL,
      tokenUrl: TOKEN_URL,
      mintUrl: MINT_URL,
    });
  });

  it("POSTs form client_id only with Muse headers and defaults interval to five", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => jsonResponse({ ...DEVICE, interval: undefined })),
    );
    const result = await start(
      envWith(stubDb().db),
      "muse-code",
      new URL("https://gw.test/x"),
    );
    expect(result).toMatchObject({
      mode: "device",
      user_code: "MUSE-123",
      verification_uri: DEVICE.verification_uri,
      verification_uri_complete: DEVICE.verification_uri_complete,
      expires_in: 900,
      interval: 5,
    });
    const [url, init] = (fetch as unknown as ReturnType<typeof vi.fn>).mock.calls[0] as [
      string,
      RequestInit,
    ];
    expect(url).toBe(DEVICE_URL);
    expect(init.method).toBe("POST");
    expect(init.redirect).toBe("error");
    expect(String(init.body)).toBe("client_id=1031625952748946");
    expect(init.headers).toMatchObject({
      Accept: "application/json",
      "User-Agent": "muse-code/1.0.2",
      "Content-Type": "application/x-www-form-urlencoded",
    });
    expect(init.signal).toBeInstanceOf(AbortSignal);
  });

  it("rejects verification URLs outside auth.meta.com", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => jsonResponse({ ...DEVICE, verification_uri: "https://evil.com/device" })),
    );
    const error = await start(
      envWith(stubDb().db),
      "muse-code",
      new URL("https://gw.test/x"),
    ).catch((e: unknown) => e);
    expect((error as { status: number }).status).toBe(502);
    expect((error as Error).message).toContain("Muse Code returned an invalid authorization URL.");
  });

  it("rejects a device expiry outside (0, 86400]", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => jsonResponse({ ...DEVICE, expires_in: 999999 })),
    );
    const error = await start(
      envWith(stubDb().db),
      "muse-code",
      new URL("https://gw.test/x"),
    ).catch((e: unknown) => e);
    expect((error as { status: number }).status).toBe(502);
    expect((error as Error).message).toContain("Muse Code returned an invalid device code expiry.");
  });

  it.each(["device_code", "user_code"] as const)(
    "missing %s is rejected with field-specific validation",
    async (field) => {
      const data = { ...DEVICE, [field]: "  " };
      vi.stubGlobal("fetch", vi.fn(async () => jsonResponse(data)));
      const error = await start(
        envWith(stubDb().db),
        "muse-code",
        new URL("https://gw.test/x"),
      ).catch((e: unknown) => e);
      expect((error as { status: number }).status).toBe(502);
      expect((error as Error).message).toContain(`Muse Code returned a missing ${field}.`);
    },
  );
});

describe("muse-code device poll", () => {
  it("sends the device grant body and maps known error descriptions", async () => {
    const fetchMock = vi.fn(async () => jsonResponse({ error: "access_denied" }));
    vi.stubGlobal("fetch", fetchMock);
    const result = await adapter().pollToken!(adapter().config, "muse-dc");
    expect(result).toEqual({
      ok: false,
      data: { error: "access_denied", error_description: "Authorization denied." },
    });
    const [url, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe(TOKEN_URL);
    expect(init.method).toBe("POST");
    expect(init.redirect).toBe("error");
    expect(String(init.body)).toBe(
      "client_id=1031625952748946&device_code=muse-dc&grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code",
    );
    expect(init.headers).toMatchObject({
      Accept: "application/json",
      "User-Agent": "muse-code/1.0.2",
    });
  });

  it.each([
    ["authorization_pending", "Authorization pending."],
    ["slow_down", "Authorization pending."],
    ["expired_token", "Device code expired."],
    ["invalid_grant", "Authorization failed."],
  ])("maps %s to the pinned description", async (code, description) => {
    vi.stubGlobal("fetch", vi.fn(async () => jsonResponse({ error: code })));
    expect(await adapter().pollToken!(adapter().config, "dc")).toEqual({
      ok: false,
      data: { error: code, error_description: description },
    });
  });

  it("unknown errors and malformed JSON normalize to invalid_response", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(jsonResponse({ error: "future_error", error_description: "details" }))
      .mockResolvedValueOnce(new Response("<html>bad</html>", { status: 500 }));
    vi.stubGlobal("fetch", fetchMock);
    expect(await adapter().pollToken!(adapter().config, "dc")).toEqual({
      ok: false,
      data: { error: "invalid_response", error_description: "details" },
    });
    expect(await adapter().pollToken!(adapter().config, "dc")).toEqual({
      ok: false,
      data: { error: "invalid_response", error_description: "<html>bad</html>" },
    });
  });
});

describe("muse-code postExchange and mapTokens", () => {
  it("mints an API key, uses DCA as durable refresh grant, and maps the profile/meta", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(jsonResponse(DEVICE))
      .mockResolvedValueOnce(jsonResponse({ access_token: "dca:durable-1", expires_in: 7200 }))
      .mockResolvedValueOnce(jsonResponse({
        api_key: "sk-muse-1",
        base_url: "https://api.muse.test",
        user_email: "u@muse.test",
        user_full_name: "Muse User",
        subs_tier_name: "pro",
        subs_tier_id: 7,
        is_subs_active: true,
        has_payment_method: true,
        require_payment: false,
        can_subscribe: true,
      }));
    vi.stubGlobal("fetch", fetchMock);
    const { db, tokens } = stubDb();
    const env = envWith(db);
    await start(env, "muse-code", new URL("https://gw.test/x"));
    expect(await poll(env, "muse-code")).toEqual({ status: "connected" });
    const row = (await getToken(env, "muse-code"))!;
    expect(row.accessToken).toBe("sk-muse-1");
    expect(row.refreshToken).toBe("dca:durable-1");
    expect(row.accountLabel).toBe("Muse User");
    expect(row.expiresAt).toBeNull(); // minted API keys do not inherit DCA expiry
    expect(row.meta).toMatchObject({
      authKind: "oauth",
      baseUrl: "https://api.muse.test",
      email: "u@muse.test",
      name: "Muse User",
      subsTierName: "pro",
      subsTierId: 7,
      isSubsActive: true,
      hasPaymentMethod: true,
      requirePayment: false,
      canSubscribe: true,
    });
    expect(row.meta).not.toHaveProperty("dcaToken");
    expect(JSON.stringify(tokens.get("muse-code"))).not.toContain("dca:durable-1");
    expect(tokens.get("muse-code")!.refresh_token).toBeInstanceOf(Uint8Array);
    expect(row.meta?.dcaExpiresAt).toMatch(/^\d{4}-\d\d-\d\dT/);
    expect(row.meta?.lastRefresh).toMatch(/^\d{4}-\d\d-\d\dT/);
    const [url, init] = fetchMock.mock.calls[2] as unknown as [string, RequestInit];
    expect(url).toBe(MINT_URL);
    expect(init.headers).toMatchObject({
      Accept: "application/json",
      "User-Agent": "muse-code/1.0.2",
      Authorization: "Bearer dca:durable-1",
      "Content-Type": "application/json",
    });
    expect(init.body).toBe(JSON.stringify({ dca_token: "dca:durable-1" }));
  });

  it("mint HTTP failure is best-effort: saves a DCA-only row and connect succeeds", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(jsonResponse(DEVICE))
      .mockResolvedValueOnce(jsonResponse({ access_token: "dca:durable-2", expires_in: 7200 }))
      .mockResolvedValueOnce(new Response("mint unavailable", { status: 429 }));
    vi.stubGlobal("fetch", fetchMock);
    const { db, tokens } = stubDb();
    const env = envWith(db);
    await start(env, "muse-code", new URL("https://gw.test/x"));
    expect(await poll(env, "muse-code")).toEqual({ status: "connected" });
    const row = (await getToken(env, "muse-code"))!;
    expect(row.accessToken).toBe("dca:durable-2");
    expect(row.refreshToken).toBe("dca:durable-2");
    expect(row.meta).toMatchObject({ authKind: "oauth" });
    expect(row.meta).not.toHaveProperty("dcaToken");
    expect(JSON.stringify(tokens.get("muse-code"))).not.toContain("dca:durable-2");
    expect(row.meta).not.toHaveProperty("baseUrl");
  });

  it("mapTokens without access or DCA token fails with the pinned message", () => {
    expect(() => adapter().mapTokens({})).toThrow(
      "Muse Code device flow completed without an access token.",
    );
  });

  it("device completion without access_token fails with the pinned message", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(jsonResponse(DEVICE))
      .mockResolvedValueOnce(jsonResponse({}));
    vi.stubGlobal("fetch", fetchMock);
    const env = envWith(stubDb().db);
    await start(env, "muse-code", new URL("https://gw.test/x"));
    expect(await poll(env, "muse-code")).toEqual({
      status: "error",
      error: "Muse Code device flow completed without an access token.",
    });
  });
});

describe("muse-code refresh", () => {
  async function seedRefresh(env: Env) {
    await saveToken(env, {
      provider: "muse-code",
      accessToken: "old-api-key",
      refreshToken: "dca:refresh-1",
      expiresIn: 10,
      authKind: "oauth",
      meta: {
        dcaToken: "dca:refresh-1",
        authKind: "oauth",
        baseUrl: "https://old.muse.test",
        email: "old@muse.test",
        lastRefresh: "2026-11-15T00:00:00.000Z",
      },
    });
  }

  it("refresh hook remints and returns snake_case raw shape; mapTokens merges priorMeta", async () => {
    const fetchMock = vi.fn(async () =>
      jsonResponse({
        api_key: "sk-muse-refreshed",
        base_url: "https://new.muse.test",
        user_email: "new@muse.test",
        user_full_name: "New Muse",
        subs_tier_name: "team",
      }),
    );
    vi.stubGlobal("fetch", fetchMock);
    const { db, tokens } = stubDb();
    const env = envWith(db);
    await seedRefresh(env);
    expect(await ensureFreshToken(env, "muse-code")).toBe("sk-muse-refreshed");
    const [url, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe(MINT_URL);
    expect(init.headers).toMatchObject({
      Authorization: "Bearer dca:refresh-1",
      "User-Agent": "muse-code/1.0.2",
    });
    expect(init.body).toBe(JSON.stringify({ dca_token: "dca:refresh-1" }));
    const row = (await getToken(env, "muse-code"))!;
    expect(row.accessToken).toBe("sk-muse-refreshed");
    expect(row.refreshToken).toBe("dca:refresh-1");
    expect(row.meta).toMatchObject({
      baseUrl: "https://new.muse.test",
      email: "new@muse.test",
      name: "New Muse",
      subsTierName: "team",
      authKind: "oauth",
    });
    expect(row.meta).not.toHaveProperty("dcaToken");
    expect(row.meta?.lastRefresh).not.toBe("2026-11-15T00:00:00.000Z");
  });

  it.each([
    [429, "Muse Code key mint failed (HTTP 429).", "refresh rejected"],
    [401, "Muse Code key mint failed (HTTP 401).", "Muse Code key mint failed (HTTP 401)."],
  ])(
    "mint HTTP %i marks last_error, preserves tokens, and classifies unauthorized refresh",
    async (status, lastError, detail) => {
      vi.stubGlobal("fetch", vi.fn(async () => new Response("mint failed", { status })));
      const { db } = stubDb();
      const env = envWith(db);
      await seedRefresh(env);
      const before = (await getToken(env, "muse-code"))!;
      const error = await ensureFreshToken(env, "muse-code").catch((e: unknown) => e);
      expect(error).toBeInstanceOf(TokenExpiredError);
      expect((error as TokenExpiredError).detail).toContain(detail);
      const after = (await getToken(env, "muse-code"))!;
      expect(after.accessToken).toBe(before.accessToken);
      expect(after.refreshToken).toBe(before.refreshToken);
      expect(after.lastError).toContain(lastError);
    },
  );
});
