import { beforeEach, describe, expect, it, vi } from "vitest";
import { complete, getAdapter, OAuthError, start } from "../src/oauth/engine";
import { ensureFreshToken, TokenExpiredError } from "../src/oauth/refresh";
import { getToken, saveToken } from "../src/oauth/store";
import type { Env } from "../src/env";
import type { OAuthAdapter } from "../src/oauth/types";

const KEY = btoa(String.fromCharCode(...new Uint8Array(32).fill(0x41)))
  .replace(/\+/g, "-")
  .replace(/\//g, "_")
  .replace(/=+$/, "");
const ORIGIN = "https://gw.test";
const CLIPASS_REFRESH_URL = "https://api.cline.bot/api/v1/auth/refresh";
const CN_REFRESH_URL = "https://copilot.tencent.com/v2/plugin/auth/token/refresh";
const INTL_REFRESH_URL = "https://www.codebuddy.ai/v2/plugin/auth/token/refresh";

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

function embeddedCode(value: unknown): string {
  return btoa(JSON.stringify(value));
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

function adapter(prefix: string): OAuthAdapter {
  const result = getAdapter(prefix);
  if (!result) throw new Error(`${prefix} adapter was not registered`);
  return result;
}

async function saveExpiredToken(env: Env, provider: string, refreshToken: string): Promise<void> {
  await saveToken(env, {
    provider,
    accessToken: `${provider}-old-access`,
    refreshToken,
    expiresIn: 10,
    email: "saved@example.com",
    name: "Saved Account",
    authKind: "oauth",
  });
}

beforeEach(() => {
  vi.unstubAllGlobals();
});

describe("ClinePass alias", () => {
  it("shares Cline's WorkOS start and embedded-code completion under its own prefix", async () => {
    const cline = adapter("cline");
    const clinepass = adapter("clinepass");
    expect(clinepass.flowMode).toBe("paste-code");
    expect(clinepass.config).toBe(cline.config);
    expect(clinepass.buildAuthUrl).toBe(cline.buildAuthUrl);
    expect(clinepass.exchangeToken).toBe(cline.exchangeToken);
    expect(clinepass.mapTokens).toBe(cline.mapTokens);
    expect(clinepass.importToken).toBeUndefined();
    expect(clinepass.instructions).toBe(
      "ClinePass — same Cline WorkOS sign-in. Open the URL, sign in, then paste the returned authorization code here.",
    );

    const { db, pending } = stubDb();
    const env = envWith(db);
    const result = await start(env, "clinepass", new URL(`${ORIGIN}/admin/api/oauth/clinepass/start`));
    expect(result.mode).toBe("paste-code");
    if (result.mode !== "paste-code") throw new Error("expected paste-code flow");
    const authUrl = new URL(result.authUrl);
    expect(authUrl.origin + authUrl.pathname).toBe("https://api.cline.bot/api/v1/auth/authorize");
    expect(authUrl.searchParams.get("client_type")).toBe("extension");
    expect(authUrl.searchParams.get("callback_url")).toBe(
      `${ORIGIN}/admin/oauth/clinepass/callback`,
    );
    expect(authUrl.searchParams.get("redirect_uri")).toBe(
      `${ORIGIN}/admin/oauth/clinepass/callback`,
    );

    const code = embeddedCode({
      accessToken: "clinepass-access",
      refreshToken: "clinepass-refresh",
      email: "clinepass@example.com",
      firstName: "Cline",
      lastName: "Pass",
      expiresAt: "2030-01-01T00:00:00Z",
    });
    const completed = await complete(env, "clinepass", { code });
    expect(completed).toEqual({ connected: true, accountLabel: "Cline Pass" });
    expect((await getToken(env, "clinepass"))?.accessToken).toBe("clinepass-access");
    expect((await getToken(env, "clinepass"))?.refreshToken).toBe("clinepass-refresh");
    expect(pending.has("clinepass")).toBe(false);
  });
});

describe("Cline refresh", () => {
  it("unwraps the success envelope, computes expiresAt, and rotates the refresh token", async () => {
    const expiresAt = new Date(Date.now() + 3_600_000).toISOString();
    const fetchMock = vi.fn(async () =>
      jsonResponse({
        data: {
          accessToken: "cline-new-access",
          refreshToken: "cline-new-refresh",
          expiresAt,
        },
      }),
    );
    vi.stubGlobal("fetch", fetchMock);
    const { db } = stubDb();
    const env = envWith(db);
    await saveExpiredToken(env, "cline", "cline-old-refresh");
    expect(await ensureFreshToken(env, "cline")).toBe("cline-new-access");

    const [url, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe(CLIPASS_REFRESH_URL);
    expect(init.method).toBe("POST");
    expect(init.headers).toMatchObject({ "Content-Type": "application/json" });
    expect(JSON.parse(String(init.body))).toEqual({
      refreshToken: "cline-old-refresh",
      grantType: "refresh_token",
      clientType: "extension",
    });
    const row = (await getToken(env, "cline"))!;
    expect(row.refreshToken).toBe("cline-new-refresh");
    expect(row.expiresAt).toBeGreaterThanOrEqual(Date.parse(expiresAt) - 1000);
    expect(row.expiresAt).toBeLessThanOrEqual(Date.parse(expiresAt));
    expect(row.lastError).toBeNull();
  });

  it("preserves saved profile metadata when the refresh response omits it", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        jsonResponse({
          data: {
            accessToken: "cline-profile-refreshed",
            refreshToken: "cline-profile-refresh-2",
          },
        }),
      ),
    );
    const env = envWith(stubDb().db);
    await saveToken(env, {
      provider: "cline",
      accessToken: "cline-profile-old-access",
      refreshToken: "cline-profile-old-refresh",
      expiresIn: 10,
      email: "saved@cline.test",
      name: "Saved Cline",
      meta: {
        firstName: "Saved",
        lastName: "Cline",
        email: "saved@cline.test",
        accountTier: "pro",
      },
      authKind: "oauth",
    });

    expect(await ensureFreshToken(env, "cline")).toBe("cline-profile-refreshed");
    expect(await getToken(env, "cline")).toMatchObject({
      accountLabel: "Saved Cline",
      meta: {
        firstName: "Saved",
        lastName: "Cline",
        email: "saved@cline.test",
        accountTier: "pro",
      },
    });
  });

  it("uses fresh name/email fields over prior metadata", () => {
    const mapped = adapter("cline").mapTokens(
      {
        access_token: "cline-fresh-access",
        firstName: "Fresh",
        lastName: "Cline",
        email: "fresh@cline.test",
      },
      undefined,
      {
        firstName: "Saved",
        lastName: "User",
        email: "saved@cline.test",
        accountTier: "pro",
      },
    );

    expect(mapped.name).toBe("Fresh Cline");
    expect(mapped.email).toBe("fresh@cline.test");
    expect(mapped.meta).toMatchObject({
      firstName: "Fresh",
      lastName: "Cline",
      email: "fresh@cline.test",
      accountTier: "pro",
    });
  });

  it.each([
    ["failed to refresh token: invalid_grant", "invalid_grant"],
    ["invalid_request: refresh credential rejected", "invalid_request"],
  ])("%s is classified as a terminal Cline refresh rejection", async (upstreamError, code) => {
    const fetchMock = vi.fn(async () =>
      jsonResponse({ error: upstreamError }, 400),
    );
    vi.stubGlobal("fetch", fetchMock);
    const { db } = stubDb();
    const env = envWith(db);
    await saveExpiredToken(env, "cline", "cline-dead-refresh");
    const error = await ensureFreshToken(env, "cline").catch((err: unknown) => err);
    expect(error).toBeInstanceOf(TokenExpiredError);
    expect((await getToken(env, "cline"))?.lastError).toBe(`cline refresh rejected: ${code}`);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("rejects refresh if the adapter config has no refresh URL", async () => {
    const cline = adapter("cline");
    const config = { ...cline.config };
    delete config.refreshUrl;
    await expect(cline.refresh!(config, "refresh-token")).rejects.toThrow(
      "Cline refresh URL is not configured",
    );
  });
});

describe("CodeBuddy refresh", () => {
  it.each([
    [
      "codebuddy-cn",
      CN_REFRESH_URL,
      "CLI/2.108.1 CodeBuddy/2.108.1",
      "copilot.tencent.com",
      "cn-new-refresh",
      "cn-new-refresh",
    ],
    [
      "codebuddy-intl",
      INTL_REFRESH_URL,
      "IDE/2.108.1 CodeBuddy/2.108.1",
      "www.codebuddy.ai",
      undefined,
      "codebuddy-intl-old-refresh",
    ],
  ])(
    "%s uses its pinned endpoint/headers and refreshes the token",
    async (prefix, refreshUrl, userAgent, domain, responseRefreshToken, expectedRefreshToken) => {
      const fetchMock = vi.fn(async () =>
        jsonResponse({
          code: 0,
          data: {
            accessToken: `${prefix}-new-access`,
            ...(responseRefreshToken ? { refreshToken: responseRefreshToken } : {}),
            expiresIn: 7200,
          },
        }),
      );
      vi.stubGlobal("fetch", fetchMock);
      const { db } = stubDb();
      const env = envWith(db);
      await saveExpiredToken(env, prefix, `${prefix}-old-refresh`);
      expect(await ensureFreshToken(env, prefix)).toBe(`${prefix}-new-access`);

      const [url, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
      expect(url).toBe(refreshUrl);
      expect(init.method).toBe("POST");
      expect(init.headers).toEqual({
        "Content-Type": "application/json",
        Accept: "application/json",
        "User-Agent": userAgent,
        "X-Requested-With": "XMLHttpRequest",
        "X-Domain": domain,
        "X-Refresh-Token": `${prefix}-old-refresh`,
        "X-Auth-Refresh-Source": "plugin",
        "X-Product": "SaaS",
      });
      expect(JSON.parse(String(init.body))).toEqual({});
      expect((await getToken(env, prefix))?.refreshToken).toBe(expectedRefreshToken);
    },
  );

  it.each([
    [{ code: 17, msg: "refresh denied", data: {} }, 200, "CodeBuddy token refresh returned no token"],
    [{ code: 0, data: {} }, 200, "CodeBuddy token refresh returned no token"],
    ["upstream unavailable", 503, "Failed to refresh CodeBuddy token (503)"],
  ])("persists CodeBuddy's provider-specific failure detail", async (payload, status, expectedError) => {
    const fetchMock = vi.fn(async () =>
      typeof payload === "string"
        ? new Response(payload, { status })
        : jsonResponse(payload, status),
    );
    vi.stubGlobal("fetch", fetchMock);
    const { db } = stubDb();
    const env = envWith(db);
    await saveExpiredToken(env, "codebuddy-cn", "codebuddy-dead-refresh");
    await expect(ensureFreshToken(env, "codebuddy-cn")).rejects.toBeInstanceOf(TokenExpiredError);
    expect((await getToken(env, "codebuddy-cn"))?.lastError).toBe(expectedError);
  });
});
