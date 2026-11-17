import { beforeEach, describe, expect, it, vi } from "vitest";
import { getToken, saveToken } from "../src/oauth/store";
import { ensureFreshToken, TokenExpiredError } from "../src/oauth/refresh";
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
  const a = getAdapter("kimi-coding");
  if (!a) throw new Error("kimi-coding adapter was not registered");
  return a;
}

const DEVICE_CODE = "kimi-device-1";
const DEVICE_URI = "https://auth.kimi.com/device";

beforeEach(() => {
  vi.unstubAllGlobals();
});

describe("kimi-coding registration", () => {
  it("is a device adapter with the pinned endpoints and client id", () => {
    expect(adapter().flowMode).toBe("device");
    expect(adapter().config).toMatchObject({
      clientId: "17e5f671-d194-4dfb-9706-5516cb48c098",
      deviceCodeUrl: "https://auth.kimi.com/api/oauth/device_authorization",
      tokenUrl: "https://auth.kimi.com/api/oauth/token",
    });
  });
});

describe("kimi-coding device start", () => {
  it("POSTs client_id only, carries all X-Msh identity headers, and defaults optional fields", async () => {
    const fetchMock = vi.fn(async () =>
      jsonResponse({
        device_code: DEVICE_CODE,
        user_code: "KIMI-123",
        verification_uri_complete: DEVICE_URI,
        // verification_uri missing → ""
        // interval missing → default 5
        expires_in: 900,
      }),
    );
    vi.stubGlobal("fetch", fetchMock);
    const env = envWith(stubDb().db);
    const result = await start(env, "kimi-coding", new URL("https://gw.test/x"));
    expect(result).toMatchObject({
      mode: "device",
      user_code: "KIMI-123",
      verification_uri: "",
      verification_uri_complete: DEVICE_URI,
      expires_in: 900,
      interval: 5,
    });
    const [url, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe("https://auth.kimi.com/api/oauth/device_authorization");
    expect(init.method).toBe("POST");
    expect(String(init.body)).toBe("client_id=17e5f671-d194-4dfb-9706-5516cb48c098");
    const headers = init.headers as Record<string, string>;
    expect(headers).toMatchObject({
      Accept: "application/json",
      "Content-Type": "application/x-www-form-urlencoded",
      "X-Msh-Platform": "kimi_code_cli",
      "X-Msh-Version": "2.1.1",
      "X-Msh-Device-Name": "freeai-gateway",
      "X-Msh-Device-Model": "cloudflare-worker",
      "X-Msh-Os-Version": "workers",
    });
    expect(headers["X-Msh-Device-Id"]).toMatch(/^[0-9a-f-]{36}$/i);
  });

  it.each(["device_code", "user_code", "verification_uri_complete"] as const)(
    "missing required %s → engine 502 names the field",
    async (missing) => {
      const payload: Record<string, unknown> = {
        device_code: DEVICE_CODE,
        user_code: "KIMI-123",
        verification_uri_complete: DEVICE_URI,
      };
      delete payload[missing];
      vi.stubGlobal("fetch", vi.fn(async () => jsonResponse(payload)));
      const error = await start(
        envWith(stubDb().db),
        "kimi-coding",
        new URL("https://gw.test/x"),
      ).catch((e: unknown) => e);
      expect(error).toBeInstanceOf(OAuthError);
      expect((error as OAuthError).status).toBe(502);
      expect((error as Error).message).toContain(`Device authorization response missing ${missing}`);
    },
  );
});

describe("kimi-coding stable device identity", () => {
  it("same generated deviceId goes to start headers, poll headers, and saved token meta", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(jsonResponse({
        device_code: DEVICE_CODE,
        user_code: "KIMI-2",
        verification_uri_complete: DEVICE_URI,
        expires_in: 900,
      }))
      .mockResolvedValueOnce(jsonResponse({
        access_token: "kimi-at",
        refresh_token: "kimi-rt",
        expires_in: 3600,
      }));
    vi.stubGlobal("fetch", fetchMock);
    const { db, pending } = stubDb();
    const env = envWith(db);
    await start(env, "kimi-coding", new URL("https://gw.test/x"));
    const startHeaders = (fetchMock.mock.calls[0] as unknown as [string, RequestInit])[1]
      .headers as Record<string, string>;
    const deviceId = startHeaders["X-Msh-Device-Id"];
    const rawPending = pending.get("kimi-coding")!;
    expect(JSON.stringify(rawPending)).not.toContain(deviceId);
    expect(String(rawPending.extra)).toMatch(/^enc:v1:/);
    expect(await poll(env, "kimi-coding")).toEqual({ status: "connected" });
    const pollHeaders = (fetchMock.mock.calls[1] as unknown as [string, RequestInit])[1]
      .headers as Record<string, string>;
    expect(pollHeaders["X-Msh-Device-Id"]).toBe(deviceId);
    const row = (await getToken(env, "kimi-coding"))!;
    expect(row.meta).toEqual({
      deviceId,
      deviceName: "freeai-gateway",
      deviceModel: "cloudflare-worker",
      osVersion: "workers",
    });
  });
});

describe("kimi-coding poll", () => {
  it("uses the stable meta deviceId and passes authorization_pending through", async () => {
    const fetchMock = vi.fn(async () => jsonResponse({ error: "authorization_pending" }));
    vi.stubGlobal("fetch", fetchMock);
    const result = await adapter().pollToken!(
      adapter().config,
      DEVICE_CODE,
      "unused-verifier",
      { deviceId: "stable-id" },
    );
    expect(result).toEqual({ ok: false, data: { error: "authorization_pending" } });
    const [url, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe("https://auth.kimi.com/api/oauth/token");
    expect(init.headers).toMatchObject({ "X-Msh-Device-Id": "stable-id" });
    expect(String(init.body)).toContain(`client_id=17e5f671-d194-4dfb-9706-5516cb48c098`);
    expect(String(init.body)).toContain(`device_code=${DEVICE_CODE}`);
    expect(String(init.body)).toContain(
      "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code",
    );
  });

  it("unknown poll errors normalize to invalid_response; malformed JSON is safe", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(jsonResponse({ error: "some_future_error", error_description: "details" }))
      .mockResolvedValueOnce(new Response("not json", { status: 200 }));
    vi.stubGlobal("fetch", fetchMock);
    expect(
      await adapter().pollToken!(adapter().config, DEVICE_CODE, undefined, { deviceId: "d" }),
    ).toEqual({
      ok: false,
      data: { error: "invalid_response", error_description: "details" },
    });
    expect(
      await adapter().pollToken!(adapter().config, DEVICE_CODE, undefined, { deviceId: "d" }),
    ).toEqual({
      ok: false,
      data: { error: "invalid_response", error_description: "not json" },
    });
  });
});

describe("kimi-coding refresh", () => {
  it("refreshes with priorMeta deviceId and returns snake_case tokens", async () => {
    const fetchMock = vi.fn(async () =>
      jsonResponse({ access_token: "kimi-new-at", refresh_token: "kimi-new-rt", expires_in: 3600 }),
    );
    vi.stubGlobal("fetch", fetchMock);
    const { db } = stubDb();
    const env = envWith(db);
    await saveToken(env, {
      provider: "kimi-coding",
      accessToken: "old-at",
      refreshToken: "old-rt",
      expiresIn: 10,
      authKind: "oauth",
      meta: {
        deviceId: "persisted-kimi-id",
        deviceName: "freeai-gateway",
        deviceModel: "cloudflare-worker",
        osVersion: "workers",
      },
    });
    expect(await ensureFreshToken(env, "kimi-coding")).toBe("kimi-new-at");
    const [url, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe("https://auth.kimi.com/api/oauth/token");
    expect((init.headers as Record<string, string>)["X-Msh-Device-Id"]).toBe("persisted-kimi-id");
    expect(String(init.body)).toContain("grant_type=refresh_token");
    expect(String(init.body)).toContain("refresh_token=old-rt");
    const row = (await getToken(env, "kimi-coding"))!;
    expect(row.refreshToken).toBe("kimi-new-rt");
    expect(row.meta?.deviceId).toBe("persisted-kimi-id");
  });

  it("missing priorMeta.deviceId throws reconnect-required and is recorded", async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    const { db } = stubDb();
    const env = envWith(db);
    await saveToken(env, {
      provider: "kimi-coding",
      accessToken: "old-at",
      refreshToken: "old-rt",
      expiresIn: 10,
      authKind: "oauth",
      meta: {},
    });
    await expect(ensureFreshToken(env, "kimi-coding")).rejects.toBeInstanceOf(TokenExpiredError);
    expect(fetchMock).not.toHaveBeenCalled();
    expect((await getToken(env, "kimi-coding"))?.lastError).toContain("device identity");
  });
});
