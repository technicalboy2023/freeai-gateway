import { beforeEach, describe, expect, it, vi } from "vitest";
import { handleOauthList } from "../src/admin/oauth";
import { getAdapter, poll, start } from "../src/oauth/engine";
import { ensureFreshToken, TokenExpiredError } from "../src/oauth/refresh";
import { getPending, getToken, saveToken } from "../src/oauth/store";
import type { Env } from "../src/env";
import type { OAuthAdapter, RawTokens } from "../src/oauth/types";

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
  const a = getAdapter("ghe-copilot");
  if (!a) throw new Error("ghe-copilot adapter was not registered");
  return a;
}

const GHE = "https://ghe.acme.com";
const START_URL = `https://gw.test/admin/api/oauth/ghe-copilot/start?gheUrl=${encodeURIComponent(`${GHE}/`)}`;

beforeEach(() => {
  vi.unstubAllGlobals();
});

describe("ghe-copilot adapter registration and start params", () => {
  it("is a device adapter and parses only trimmed https gheUrl, stripping trailing slashes", () => {
    expect(adapter().flowMode).toBe("device");
    expect(adapter().instructions).toContain(
      "POST /admin/api/oauth/ghe-copilot/start?gheUrl=https://<ghe-host>",
    );
    expect(adapter().instructions).toContain("github.com Copilot uses the github card");
    expect(adapter().parseStartParams!(new URL("https://gw.test/x?gheUrl=%20https%3A%2F%2Fghe.acme.com%2F%20"))).toEqual({
      gheUrl: GHE,
    });
    expect(adapter().parseStartParams!(new URL("https://gw.test/x?gheUrl=http%3A%2F%2Fghe.acme.com"))).toBeUndefined();
    expect(adapter().parseStartParams!(new URL("https://gw.test/x"))).toBeUndefined();
  });

  it("listAdapters exposes the manual-start instructions for the card", async () => {
    const res = await handleOauthList(envWith(stubDb().db));
    expect(res.status).toBe(200);
    const body = (await res.json()) as { providers: Array<{ prefix: string; instructions?: string }> };
    expect(body.providers.find((p) => p.prefix === "ghe-copilot")?.instructions).toContain("?gheUrl=");
  });
});

describe("ghe-copilot device start", () => {
  it("derives endpoint from gheUrl, allow-lists response fields, and encrypts gheUrl in pending extras", async () => {
    const fetchMock = vi.fn(async () =>
      jsonResponse({
        device_code: "dc-1",
        user_code: "GHE-123",
        verification_uri: `${GHE}/login/device`,
        verification_uri_complete: `${GHE}/login/device?user_code=GHE-123`,
        expires_in: 600,
        interval: 5,
        foo: "must-not-escape",
      }),
    );
    vi.stubGlobal("fetch", fetchMock);
    const { db, pending } = stubDb();
    const env = envWith(db);
    const result = await start(env, "ghe-copilot", new URL(START_URL));
    expect(result).toEqual({
      mode: "device",
      user_code: "GHE-123",
      verification_uri: `${GHE}/login/device`,
      verification_uri_complete: `${GHE}/login/device?user_code=GHE-123`,
      expires_in: 600,
      interval: 5,
    });
    expect(JSON.stringify(result)).not.toContain("must-not-escape");
    const [url, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe(`${GHE}/login/device/code`);
    expect(init.method).toBe("POST");
    expect(init.headers).toMatchObject({
      Accept: "application/json",
      "Content-Type": "application/x-www-form-urlencoded",
    });
    expect(String(init.body)).toContain("client_id=");
    expect(String(init.body)).toContain("scope=read%3Auser");
    const raw = pending.get("ghe-copilot")!;
    expect(JSON.stringify(raw)).not.toContain("ghe.acme.com");
    expect(String(raw.extra)).toMatch(/^enc:v1:/);
    expect((await getPending(env, "ghe-copilot"))?.extra).toEqual({ gheUrl: GHE });
  });

  it("non-ok start returns 502 with the pinned HTTP message", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => new Response("no", { status: 503 })));
    const env = envWith(stubDb().db);
    const error = await start(env, "ghe-copilot", new URL(START_URL)).catch((e: unknown) => e);
    expect((error as { status: number }).status).toBe(502);
    expect((error as Error).message).toContain("Device code request failed (HTTP 503)");
  });

  it("missing/invalid gheUrl → 502 with the provider-specific instructions", async () => {
    const env = envWith(stubDb().db);
    for (const url of ["https://gw.test/x", "https://gw.test/x?gheUrl=http%3A%2F%2Fghe.acme.com"]) {
      const error = await start(env, "ghe-copilot", new URL(url)).catch((e: unknown) => e);
      expect((error as { status: number }).status).toBe(502);
      expect((error as Error).message).toContain("gheUrl is required for GHE Copilot OAuth");
    }
  });
});

describe("ghe-copilot poll and error normalization", () => {
  it("poll uses the same encrypted pending gheUrl; known errors pass and unknown codes normalize", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(jsonResponse({
        device_code: "dc-2",
        user_code: "GHE-2",
        verification_uri: `${GHE}/login/device`,
        expires_in: 600,
        interval: 5,
      }))
      .mockResolvedValueOnce(jsonResponse({ error: "slow_down", error_description: "wait a little" }));
    vi.stubGlobal("fetch", fetchMock);
    const { db, pending } = stubDb();
    const env = envWith(db);
    await start(env, "ghe-copilot", new URL(START_URL));
    const raw = pending.get("ghe-copilot")!;
    expect(JSON.stringify(raw)).not.toContain("ghe.acme.com");
    expect(await poll(env, "ghe-copilot")).toEqual({ status: "pending", error: "slow_down" });
    const [pollUrl, pollInit] = fetchMock.mock.calls[1] as unknown as [string, RequestInit];
    expect(pollUrl).toBe(`${GHE}/login/oauth/access_token`);
    expect(String(pollInit.body)).toContain("grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code");

    const direct = vi.fn(async () => jsonResponse({ error: "new_upstream_error", error_description: "safe detail" }));
    vi.stubGlobal("fetch", direct);
    const result = await adapter().pollToken!(adapter().config, "dc-x", undefined, { gheUrl: GHE });
    expect(result).toEqual({
      ok: false,
      data: { error: "invalid_response", error_description: "safe detail" },
    });
  });

  it("passes known terminal error description through to the engine result shape", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        jsonResponse({ error: "expired_token", error_description: "Device code expired" }),
      ),
    );
    const result = await adapter().pollToken!(adapter().config, "dc-x", undefined, { gheUrl: GHE });
    expect(result).toEqual({
      ok: false,
      data: { error: "expired_token", error_description: "Device code expired" },
    });
  });
});

describe("ghe-copilot postExchange", () => {
  it("fetches GHES Copilot/user endpoints and persists per-connection metadata", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(jsonResponse({
        device_code: "dc-3",
        user_code: "GHE-3",
        verification_uri: `${GHE}/login/device`,
        expires_in: 600,
        interval: 5,
      }))
      .mockResolvedValueOnce(jsonResponse({ access_token: "ghes-at", refresh_token: "ghes-rt", expires_in: 3600 }))
      .mockResolvedValueOnce(jsonResponse({
        token: "copilot-1",
        expires_at: "2026-11-17T00:00:00Z",
        endpoints: { api: "https://copilot-api.acme.com", proxy: "https://copilot-proxy.acme.com" },
      }))
      .mockResolvedValueOnce(jsonResponse({
        id: 55,
        login: "enterprise-user",
        name: "Enterprise User",
        email: "u@ghe.acme.com",
      }));
    vi.stubGlobal("fetch", fetchMock);
    const { db, tokens } = stubDb();
    const env = envWith(db);
    await start(env, "ghe-copilot", new URL(START_URL));
    expect(await poll(env, "ghe-copilot")).toEqual({ status: "connected" });
    const row = (await getToken(env, "ghe-copilot"))!;
    expect(row.accountLabel).toBe("enterprise-user");
    expect(row.meta).toMatchObject({
      gheUrl: GHE,
      copilotApiUrl: "https://copilot-api.acme.com",
      copilotProxyUrl: "https://copilot-proxy.acme.com",
      copilotTokenExpiresAt: "2026-11-17T00:00:00Z",
      githubUserId: 55,
      githubLogin: "enterprise-user",
      githubName: "Enterprise User",
      githubEmail: "u@ghe.acme.com",
      autoSync: true,
    });
    expect(row.meta).not.toHaveProperty("copilotToken");
    expect(row).toMatchObject({ secrets: { copilotToken: "copilot-1" } });
    expect(JSON.stringify(tokens.get("ghe-copilot"))).not.toContain("copilot-1");
    expect((fetchMock.mock.calls[2] as unknown as [string])[0]).toBe(
      `${GHE}/api/v3/copilot_internal/v2/token`,
    );
    expect((fetchMock.mock.calls[3] as unknown as [string])[0]).toBe(`${GHE}/api/v3/user`);
  });

  it("Copilot/user endpoints are best-effort and don't block a successful OAuth connection", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(jsonResponse({
        device_code: "dc-4",
        user_code: "GHE-4",
        verification_uri: `${GHE}/login/device`,
        expires_in: 600,
        interval: 5,
      }))
      .mockResolvedValueOnce(jsonResponse({ access_token: "ghes-at-2", expires_in: 3600 }))
      .mockResolvedValueOnce(new Response("no copilot", { status: 403 }))
      .mockResolvedValueOnce(new Response("no user", { status: 403 }));
    vi.stubGlobal("fetch", fetchMock);
    const { db } = stubDb();
    const env = envWith(db);
    await start(env, "ghe-copilot", new URL(START_URL));
    expect(await poll(env, "ghe-copilot")).toEqual({ status: "connected" });
    const row = (await getToken(env, "ghe-copilot"))!;
    expect(row.accessToken).toBe("ghes-at-2");
    expect(row.meta).toMatchObject({ gheUrl: GHE, autoSync: true });
    expect(row.meta).not.toHaveProperty("copilotToken");
  });
});

describe("ghe-copilot refresh", () => {
  it("uses meta.gheUrl endpoint, returns snake_case and mapTokens preserves prior GHES metadata", async () => {
    const fetchMock = vi.fn(async () =>
      jsonResponse({ access_token: "ghes-new-at", refresh_token: "ghes-new-rt", expires_in: 3600 }),
    );
    vi.stubGlobal("fetch", fetchMock);
    const { db } = stubDb();
    const env = envWith(db);
    await saveToken(env, {
      provider: "ghe-copilot",
      accessToken: "old-at",
      refreshToken: "old-rt",
      expiresIn: 10,
      authKind: "oauth",
      meta: {
        gheUrl: GHE,
        copilotApiUrl: "https://copilot-api.acme.com",
        copilotProxyUrl: "https://copilot-proxy.acme.com",
        githubLogin: "octo",
      },
    });
    expect(await ensureFreshToken(env, "ghe-copilot")).toBe("ghes-new-at");
    const [url, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe(`${GHE}/login/oauth/access_token`);
    expect(String(init.body)).toContain("grant_type=refresh_token");
    expect(String(init.body)).toContain("client_id=");
    expect(String(init.body)).toContain("refresh_token=old-rt");
    const row = (await getToken(env, "ghe-copilot"))!;
    expect(row.refreshToken).toBe("ghes-new-rt");
    expect(row.meta).toMatchObject({
      gheUrl: GHE,
      copilotApiUrl: "https://copilot-api.acme.com",
      copilotProxyUrl: "https://copilot-proxy.acme.com",
      githubLogin: "octo",
    });
  });

  it("missing meta.gheUrl throws and records last_error", async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    const { db } = stubDb();
    const env = envWith(db);
    await saveToken(env, {
      provider: "ghe-copilot",
      accessToken: "old-at",
      refreshToken: "old-rt",
      expiresIn: 10,
      authKind: "oauth",
      meta: {},
    });
    await expect(ensureFreshToken(env, "ghe-copilot")).rejects.toBeInstanceOf(TokenExpiredError);
    expect(fetchMock).not.toHaveBeenCalled();
    expect((await getToken(env, "ghe-copilot"))?.lastError).toContain("no gheUrl in connection meta");
  });
});
