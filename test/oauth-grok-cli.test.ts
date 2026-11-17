import { beforeEach, describe, expect, it, vi } from "vitest";
import { complete, getAdapter, OAuthError, poll, start } from "../src/oauth/engine";
import { getToken } from "../src/oauth/store";
import type { Env } from "../src/env";
import type { OAuthAdapter } from "../src/oauth/types";

const KEY = btoa(String.fromCharCode(...new Uint8Array(32).fill(0x41)))
  .replace(/\+/g, "-")
  .replace(/\//g, "_")
  .replace(/=+$/, "");
const CLIENT_ID = "b1a00492-073a-47ea-816f-4c329264a828";
const ISSUER = "https://auth.x.ai";
const DEVICE_URL = `${ISSUER}/oauth2/device/code`;
const TOKEN_URL = `${ISSUER}/oauth2/token`;
const DEVICE_SCOPE =
  "openid profile email offline_access grok-cli:access api:access conversations:read conversations:write workspaces:read workspaces:write";
const PREFERRED_AUTH_KEY = `${ISSUER}::${CLIENT_ID}`;

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

function grok(): OAuthAdapter {
  const adapter = getAdapter("grok-cli");
  if (!adapter) throw new Error("grok-cli adapter was not registered");
  return adapter;
}

function deviceResponse(overrides: Record<string, unknown> = {}) {
  return {
    device_code: "grok-device-1",
    user_code: "GROK-123",
    verification_uri: "https://auth.x.ai/device",
    verification_uri_complete: "https://auth.x.ai/device?user_code=GROK-123",
    expires_in: 1800,
    interval: 5,
    ...overrides,
  };
}

beforeEach(() => {
  vi.unstubAllGlobals();
});

describe("grok-cli device registration and start", () => {
  it("sends the pinned device scope/referrer and Grok OAuth headers", async () => {
    expect(grok().flowMode).toBe("device");
    expect(grok().config).toMatchObject({
      clientId: CLIENT_ID,
      issuer: ISSUER,
      deviceCodeUrl: DEVICE_URL,
      tokenUrl: TOKEN_URL,
      deviceScope: DEVICE_SCOPE,
      browserScope: "openid profile email offline_access grok-cli:access",
    });
    const fetchMock = vi.fn(async () => jsonResponse(deviceResponse()));
    vi.stubGlobal("fetch", fetchMock);
    const { db, pending } = stubDb();
    const env = envWith(db);
    const result = await start(env, "grok-cli", new URL("https://gw.test/admin/api/oauth/grok-cli/start"));
    expect(result).toMatchObject({
      mode: "device",
      user_code: "GROK-123",
      verification_uri: "https://auth.x.ai/device",
      verification_uri_complete: "https://auth.x.ai/device?user_code=GROK-123",
      expires_in: 1800,
      interval: 5,
    });
    const [url, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe(DEVICE_URL);
    expect(init.method).toBe("POST");
    expect(init.headers).toEqual({
      Accept: "application/json",
      "Content-Type": "application/x-www-form-urlencoded",
      "x-grok-client-version": "1.0.41",
      "x-grok-client-surface": "ui",
    });
    const body = new URLSearchParams(String(init.body));
    expect([...body.keys()].sort()).toEqual(["client_id", "scope", "referrer"].sort());
    expect(body.get("client_id")).toBe(CLIENT_ID);
    expect(body.get("scope")).toBe(DEVICE_SCOPE);
    expect(body.get("referrer")).toBe("grok-build");
    const row = pending.get("grok-cli")!;
    expect(Number(row.expires_at) - Number(row.created_at)).toBeGreaterThanOrEqual(1_799_999);
    expect(Number(row.expires_at) - Number(row.created_at)).toBeLessThanOrEqual(1_800_000);
  });

  it.each(["device_code", "user_code", "verification_uri"] as const)(
    "missing required %s becomes a 502",
    async (field) => {
      const payload = deviceResponse();
      delete (payload as Record<string, unknown>)[field];
      vi.stubGlobal("fetch", vi.fn(async () => jsonResponse(payload)));
      const error = await start(
        envWith(stubDb().db),
        "grok-cli",
        new URL("https://gw.test/start"),
      ).catch((e: unknown) => e);
      expect(error).toBeInstanceOf(OAuthError);
      expect((error as OAuthError).status).toBe(502);
    },
  );

  it("rejects invalid user-code characters with the pinned message", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => jsonResponse(deviceResponse({ user_code: "GROK 123" }))));
    const error = await start(
      envWith(stubDb().db),
      "grok-cli",
      new URL("https://gw.test/start"),
    ).catch((e: unknown) => e);
    expect((error as OAuthError).status).toBe(502);
    expect((error as Error).message).toContain("Grok returned an invalid device code");
  });

  it("accepts loopback HTTP verification URLs but rejects remote HTTP and control characters", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(jsonResponse(deviceResponse({ verification_uri: "http://127.0.0.1:56122/device" })))
      .mockResolvedValueOnce(jsonResponse(deviceResponse({ verification_uri: "http://evil.com/device" })))
      .mockResolvedValueOnce(jsonResponse(deviceResponse({ verification_uri: "https://auth.x.ai/\nmalicious" })));
    vi.stubGlobal("fetch", fetchMock);
    const { db } = stubDb();
    const result = await start(envWith(db), "grok-cli", new URL("https://gw.test/start"));
    expect(result).toMatchObject({ verification_uri: "http://127.0.0.1:56122/device" });
    for (let i = 0; i < 2; i++) {
      const error = await start(
        envWith(stubDb().db),
        "grok-cli",
        new URL("https://gw.test/start"),
      ).catch((e: unknown) => e);
      expect((error as OAuthError).status).toBe(502);
      if (i === 0) {
        expect((error as Error).message).toContain("Grok returned an unsupported verification URL");
      }
    }
  });

  it("defaults omitted expiry and interval", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => jsonResponse(deviceResponse({ expires_in: undefined, interval: 0 }))));
    const result = await start(
      envWith(stubDb().db),
      "grok-cli",
      new URL("https://gw.test/start"),
    );
    expect(result).toMatchObject({ expires_in: 1800, interval: 5 });
  });
});

describe("grok-cli device poll", () => {
  it("sends token endpoint device-grant fields with OAuth headers", async () => {
    const fetchMock = vi.fn(async () => jsonResponse({ access_token: "device-at" }));
    vi.stubGlobal("fetch", fetchMock);
    const result = await grok().pollToken!(grok().config, "device-code-2");
    expect(result).toEqual({ ok: true, data: { access_token: "device-at" } });
    const [url, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe(TOKEN_URL);
    expect(init.method).toBe("POST");
    expect(init.headers).toEqual({
      Accept: "application/json",
      "Content-Type": "application/x-www-form-urlencoded",
      "x-grok-client-version": "1.0.41",
      "x-grok-client-surface": "ui",
    });
    const body = new URLSearchParams(String(init.body));
    expect([...body.keys()].sort()).toEqual(["client_id", "device_code", "grant_type"].sort());
    expect(body.get("client_id")).toBe(CLIENT_ID);
    expect(body.get("device_code")).toBe("device-code-2");
    expect(body.get("grant_type")).toBe("urn:ietf:params:oauth:grant-type:device_code");
  });
});

describe("grok-cli browser/device token mapping", () => {
  const idToken = jwt({ email: "grok@example.com", name: "Grok User" });

  it("maps OIDC identity, raw token fields, and scope/tokenType metadata", () => {
    const mapped = grok().mapTokens({
      access_token: "eyJ.access.token",
      refresh_token: "grok-rt",
      id_token: idToken,
      expires_in: 21600,
      scope: "openid profile",
      token_type: "Bearer",
    });
    expect(mapped).toEqual({
      accessToken: "eyJ.access.token",
      refreshToken: "grok-rt",
      expiresIn: 21600,
      email: "grok@example.com",
      name: "Grok User",
      meta: { scope: "openid profile", tokenType: "Bearer", autoSync: true },
    });
  });

  it.each([0, -5, Number.NaN])("clamps browser expiry %s to one second", (expiresIn) => {
    expect(grok().mapTokens({ access_token: "at", expires_in: expiresIn }).expiresIn).toBe(1);
  });

  it("defaults absent browser expiry and scope/token type", () => {
    expect(grok().mapTokens({ access_token: "at" })).toMatchObject({
      expiresIn: 21600,
      email: null,
      name: null,
      meta: { scope: DEVICE_SCOPE, tokenType: "Bearer", autoSync: true },
    });
  });
});

describe("grok-cli paste import", () => {
  it("imports a raw JWT, resolves identity claims, and uses exp for expiry", async () => {
    const rawJwt = jwt({
      email: "team@example.com",
      sub: "subject-1",
      principal_type: "TEAM",
      principal_id: "team-from-principal",
      team_id: "team-claim",
      organization_id: "org-claim",
      tier: 3,
      exp: Math.floor(Date.now() / 1000) + 3600,
    });
    const { db } = stubDb();
    const env = envWith(db);
    await complete(env, "grok-cli", { token: rawJwt });
    const row = (await getToken(env, "grok-cli"))!;
    expect(row.accessToken).toBe(rawJwt);
    expect(row.refreshToken).toBeNull();
    expect(row.accountLabel).toBe("team@example.com");
    expect(row.expiresAt).toBeGreaterThan(Date.now() + 3_000_000);
    expect(row.meta).toEqual({
      userId: "subject-1",
      email: "team@example.com",
      teamId: "team-from-principal",
      tier: 3,
      principalType: "team",
      principalId: "team-from-principal",
      organizationId: "org-claim",
      autoSync: true,
    });
  });

  it.each([
    ["arbitrary text", "this is not a JWT"],
    ["wrong segment count", "header.payload"],
    ["invalid base64 payload", "header.%%%.signature"],
    ["invalid JSON payload", "header.bm90LWpzb24.signature"],
    ["wrapped malformed accessToken", JSON.stringify({ accessToken: "plain-text-token" })],
    [
      "malformed auth.json key",
      JSON.stringify({
        accessToken: {
          [PREFERRED_AUTH_KEY]: { key: "plain-text-token", refresh_token: "must-not-save" },
        },
      }),
    ],
  ])("rejects %s without persisting a token", async (_caseName, token) => {
    const { db, tokens } = stubDb();
    const error = await complete(envWith(db), "grok-cli", { token }).catch((e: unknown) => e);

    expect(error).toBeInstanceOf(OAuthError);
    expect((error as OAuthError).status).toBe(400);
    expect(tokens.has("grok-cli")).toBe(false);
  });

  it("parses auth.json, prefers the issuer/client entry, and clamps expired expires_at", async () => {
    const otherJwt = jwt({ email: "wrong@example.com", sub: "wrong-user" });
    const preferredJwt = jwt({
      email: "org@example.com",
      sub: "subject-org",
      principal_type: "ORGANIZATION",
      principal_id: "org-from-principal",
      team_id: "team-claim",
    });
    const authJson = JSON.stringify({
      accessToken: {
        "https://other.invalid::other-client": { key: otherJwt, refresh_token: "wrong-rt" },
        [PREFERRED_AUTH_KEY]: {
          key: preferredJwt,
          refresh_token: "org-rt",
          expires_at: "2026-01-01T00:00:00Z",
        },
      },
    });
    const { db } = stubDb();
    const env = envWith(db);
    await complete(env, "grok-cli", { token: authJson });
    const row = (await getToken(env, "grok-cli"))!;
    expect(row.accessToken).toBe(preferredJwt);
    expect(row.refreshToken).toBe("org-rt");
    expect(row.accountLabel).toBe("org@example.com");
    expect(row.expiresAt! - Date.now()).toBeLessThanOrEqual(1000);
    expect(row.meta).toEqual({
      userId: "subject-org",
      email: "org@example.com",
      teamId: "team-claim",
      tier: 1,
      principalType: "organization",
      principalId: "org-from-principal",
      organizationId: "org-from-principal",
      autoSync: true,
    });
  });

  it("falls back to the first usable auth.json scope entry when preferred key is absent", async () => {
    const fallbackJwt = jwt({ email: "fallback@example.com", sub: "fallback-user" });
    const { db } = stubDb();
    const env = envWith(db);
    await complete(
      env,
      "grok-cli",
      {
        token: JSON.stringify({
          accessToken: {
            "https://other.invalid::other-client": {
              key: fallbackJwt,
              refresh_token: "fallback-rt",
            },
          },
        }),
      },
    );
    const row = (await getToken(env, "grok-cli"))!;
    expect(row.accessToken).toBe(fallbackJwt);
    expect(row.refreshToken).toBe("fallback-rt");
    expect(row.accountLabel).toBe("fallback@example.com");
  });

  it("parses JSON-wrapped accessToken and supports absent refresh_token", async () => {
    const token = jwt({ email: "wrapped@example.com", sub: "wrapped-user" });
    const { db } = stubDb();
    const env = envWith(db);
    await complete(env, "grok-cli", { token: JSON.stringify({ accessToken: token }) });
    const row = (await getToken(env, "grok-cli"))!;
    expect(row.accessToken).toBe(token);
    expect(row.refreshToken).toBeNull();
    expect(row.meta).not.toHaveProperty("refreshToken");
  });

  it("refresh uses the standard grant against tokenUrl", async () => {
    const fetchMock = vi.fn(async () =>
      jsonResponse({
        access_token: "grok-refreshed",
        refresh_token: "grok-rt-2",
        expires_in: 3600,
        scope: "openid profile",
      }),
    );
    vi.stubGlobal("fetch", fetchMock);
    const { db } = stubDb();
    const env = envWith(db);
    const adapter = grok();
    const { saveToken } = await import("../src/oauth/store");
    await saveToken(env, {
      provider: "grok-cli",
      accessToken: "old-at",
      refreshToken: "old-rt",
      expiresIn: 10,
      email: "saved@grok.test",
      name: "Saved Grok Account",
      meta: {
        userId: "saved-user",
        email: "saved@grok.test",
        teamId: "saved-team",
        tier: 3,
        principalType: "team",
        principalId: "saved-team",
        organizationId: "saved-org",
        scope: "old-scope",
        tokenType: "Bearer",
        customProfileField: "keep",
        autoSync: true,
      },
      authKind: "oauth",
    });
    expect(await (await import("../src/oauth/refresh")).ensureFreshToken(env, "grok-cli")).toBe(
      "grok-refreshed",
    );
    const [url, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe(adapter.config.tokenUrl);
    const body = new URLSearchParams(String(init.body));
    expect(body.get("grant_type")).toBe("refresh_token");
    expect(body.get("client_id")).toBe(CLIENT_ID);
    expect(body.get("refresh_token")).toBe("old-rt");
    expect(await getToken(env, "grok-cli")).toMatchObject({
      accountLabel: "Saved Grok Account",
      meta: {
        userId: "saved-user",
        email: "saved@grok.test",
        teamId: "saved-team",
        tier: 3,
        principalType: "team",
        principalId: "saved-team",
        organizationId: "saved-org",
        scope: "openid profile",
        tokenType: "Bearer",
        customProfileField: "keep",
        autoSync: true,
      },
    });
  });

  it("uses fresh OIDC fields over prior metadata and preserves unrelated values", () => {
    const mapped = grok().mapTokens(
      {
        access_token: "fresh-at",
        id_token: jwt({
          email: "fresh@example.com",
          name: "Fresh User",
          sub: "fresh-subject",
          principal_type: "TEAM",
          principal_id: "fresh-team",
          tier: 5,
        }),
        scope: "fresh-scope",
      },
      undefined,
      {
        userId: "saved-user",
        email: "saved@example.com",
        scope: "saved-scope",
        tokenType: "Bearer",
        customProfileField: "keep",
        teamId: "saved-team",
        tier: 2,
        principalType: "team",
        principalId: "saved-team",
        organizationId: "saved-org",
      },
    );

    expect(mapped.email).toBe("fresh@example.com");
    expect(mapped.name).toBe("Fresh User");
    expect(mapped.meta).toMatchObject({
      email: "fresh@example.com",
      userId: "fresh-subject",
      teamId: "fresh-team",
      tier: 5,
      principalType: "team",
      principalId: "fresh-team",
      organizationId: "saved-org",
      scope: "fresh-scope",
      tokenType: "Bearer",
      customProfileField: "keep",
    });
  });
});
