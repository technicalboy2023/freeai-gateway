import { beforeEach, describe, expect, it, vi } from "vitest";
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

function github(): OAuthAdapter {
  const adapter = getAdapter("github");
  if (!adapter) throw new Error("github adapter was not registered");
  return adapter;
}

beforeEach(() => {
  vi.unstubAllGlobals();
});

describe("github registration", () => {
  it("registers the device adapter and pinned configuration", () => {
    const adapter = github();
    expect(adapter.flowMode).toBe("device");
    expect(adapter.config).toMatchObject({
      clientId: "Iv1.b507a08c87ecfe98",
      deviceCodeUrl: "https://github.com/login/device/code",
      tokenUrl: "https://github.com/login/oauth/access_token",
      userInfoUrl: "https://api.github.com/user",
      copilotTokenUrl: "https://api.github.com/copilot_internal/v2/token",
      scopes: "read:user",
      apiVersion: "2026-08-01",
      userAgent: "GitHubCopilotChat/1.0.91",
    });
  });
});

describe("github device start", () => {
  it("sends the pinned form request and passes the response through StartResult", async () => {
    const fetchMock = vi.fn(async () =>
      jsonResponse({
        device_code: "dc-1",
        user_code: "ABCD-1234",
        verification_uri: "https://github.com/login/device",
        verification_uri_complete: "https://github.com/login/device?user_code=ABCD-1234",
        expires_in: 900,
        interval: 5,
      }),
    );
    vi.stubGlobal("fetch", fetchMock);
    const env = envWith(stubDb().db);
    const result = await start(env, "github", new URL("https://gw.test/x"));
    expect(result).toEqual({
      mode: "device",
      user_code: "ABCD-1234",
      verification_uri: "https://github.com/login/device",
      verification_uri_complete: "https://github.com/login/device?user_code=ABCD-1234",
      expires_in: 900,
      interval: 5,
    });
    const [url, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe("https://github.com/login/device/code");
    expect(init.method).toBe("POST");
    expect(init.headers).toEqual({
      Accept: "application/json",
      "Content-Type": "application/x-www-form-urlencoded",
    });
    expect(String(init.body)).toBe("client_id=Iv1.b507a08c87ecfe98&scope=read%3Auser");
  });

  it("non-ok response becomes an engine 502 containing upstream text", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => new Response("device denied", { status: 503 })));
    const env = envWith(stubDb().db);
    const error = await start(env, "github", new URL("https://gw.test/x")).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(OAuthError);
    expect((error as OAuthError).status).toBe(502);
    expect((error as Error).message).toContain("device denied");
  });
});

describe("github device poll", () => {
  it("sends the device grant form and normalizes authorization_pending", async () => {
    const fetchMock = vi.fn(async () => jsonResponse({ error: "authorization_pending" }));
    vi.stubGlobal("fetch", fetchMock);
    const result = await github().pollToken!(github().config, "dc-1");
    expect(result).toEqual({ ok: false, data: { error: "authorization_pending" } });
    const [url, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe("https://github.com/login/oauth/access_token");
    expect(init.method).toBe("POST");
    expect(init.headers).toEqual({
      Accept: "application/json",
      "Content-Type": "application/x-www-form-urlencoded",
    });
    expect(String(init.body)).toBe(
      "client_id=Iv1.b507a08c87ecfe98&device_code=dc-1&grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code",
    );
  });

  it("non-JSON poll response is normalized with invalid_response + original text", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => new Response("upstream body", { status: 200 })));
    expect(await github().pollToken!(github().config, "dc-1")).toEqual({
      ok: false,
      data: { error: "invalid_response", error_description: "upstream body" },
    });
  });

  it("engine keeps polling for authorization_pending", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(jsonResponse({
        device_code: "dc-2",
        user_code: "ABCD-2",
        verification_uri: "https://github.com/login/device",
        expires_in: 600,
        interval: 5,
      }))
      .mockResolvedValueOnce(jsonResponse({ error: "authorization_pending" }));
    vi.stubGlobal("fetch", fetchMock);
    const env = envWith(stubDb().db);
    await start(env, "github", new URL("https://gw.test/x"));
    expect(await poll(env, "github")).toEqual({ status: "pending", error: "authorization_pending" });
  });
});

describe("github postExchange", () => {
  it("fetches Copilot token + user info and persists all mapped metadata", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(jsonResponse({
        device_code: "dc-3",
        user_code: "ABCD-3",
        verification_uri: "https://github.com/login/device",
        expires_in: 600,
        interval: 5,
      }))
      .mockResolvedValueOnce(jsonResponse({ access_token: "gh-at", refresh_token: "gh-rt", expires_in: 3600 }))
      .mockResolvedValueOnce(jsonResponse({ token: "copilot-at", expires_at: "2026-11-17T00:00:00Z" }))
      .mockResolvedValueOnce(jsonResponse({ id: 123, login: "octo", name: "Octocat", email: "octo@example.com" }));
    vi.stubGlobal("fetch", fetchMock);
    const { db, tokens } = stubDb();
    const env = envWith(db);
    await start(env, "github", new URL("https://gw.test/x"));
    expect(await poll(env, "github")).toEqual({ status: "connected" });
    const row = (await getToken(env, "github"))!;
    expect(row.accessToken).toBe("gh-at");
    expect(row.refreshToken).toBe("gh-rt");
    expect(row.accountLabel).toBe("octo");
    expect(row.meta).toMatchObject({
      copilotTokenExpiresAt: "2026-11-17T00:00:00Z",
      githubUserId: 123,
      githubLogin: "octo",
      githubName: "Octocat",
      githubEmail: "octo@example.com",
      autoSync: true,
    });
    expect(row.meta).not.toHaveProperty("copilotToken");
    expect(row).toMatchObject({ secrets: { copilotToken: "copilot-at" } });
    expect(JSON.stringify(tokens.get("github"))).not.toContain("copilot-at");
    const copilotCall = fetchMock.mock.calls[2] as unknown as [string, RequestInit];
    expect(copilotCall[0]).toBe("https://api.github.com/copilot_internal/v2/token");
    expect(copilotCall[1].headers).toMatchObject({
      Authorization: "Bearer gh-at",
      Accept: "application/json",
      "X-GitHub-Api-Version": "2026-08-01",
      "User-Agent": "GitHubCopilotChat/1.0.91",
    });
    const userInfoCall = fetchMock.mock.calls[3] as unknown as [string, RequestInit];
    expect(userInfoCall[0]).toBe("https://api.github.com/user");
    expect(userInfoCall[1].headers).toMatchObject({
      Authorization: "Bearer gh-at",
      "X-GitHub-Api-Version": "2026-08-01",
      "User-Agent": "GitHubCopilotChat/1.0.91",
    });
  });

  it("Copilot endpoint non-2xx is best-effort; connect succeeds without copilotToken", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(jsonResponse({
        device_code: "dc-4",
        user_code: "ABCD-4",
        verification_uri: "https://github.com/login/device",
        expires_in: 600,
        interval: 5,
      }))
      .mockResolvedValueOnce(jsonResponse({ access_token: "gh-at-2", refresh_token: "gh-rt-2", expires_in: 3600 }))
      .mockResolvedValueOnce(new Response("no copilot", { status: 403 }))
      .mockResolvedValueOnce(jsonResponse({ id: 7, login: "no-copilot" }));
    vi.stubGlobal("fetch", fetchMock);
    const { db } = stubDb();
    const env = envWith(db);
    await start(env, "github", new URL("https://gw.test/x"));
    expect(await poll(env, "github")).toEqual({ status: "connected" });
    const row = (await getToken(env, "github"))!;
    expect(row.accessToken).toBe("gh-at-2");
    expect(row.meta).not.toHaveProperty("copilotToken");
    expect(row.meta).toMatchObject({ githubLogin: "no-copilot", autoSync: true });
  });
});

describe("github refresh", () => {
  it("uses the standard refresh grant (client_id + refresh_token, no client_secret)", async () => {
    const fetchMock = vi.fn(async () =>
      jsonResponse({ access_token: "gh-refreshed", refresh_token: "gh-rt-2", expires_in: 3600 }),
    );
    vi.stubGlobal("fetch", fetchMock);
    const { db } = stubDb();
    const env = envWith(db);
    const adapter = github();
    // Inside the 5-minute skew; standardRefresh should use config.tokenUrl.
    await saveToken(
      env,
      Object.assign(
        {
          provider: "github",
          accessToken: "old-at",
          refreshToken: "old-rt",
          expiresIn: 10,
          email: "saved@example.com",
          name: "saved-login",
          meta: {
            githubUserId: 123,
            githubLogin: "saved-login",
            githubName: "Saved Name",
            githubEmail: "saved@example.com",
            copilotTokenExpiresAt: "2026-11-17T00:00:00Z",
            customProfileField: "preserve-me",
            autoSync: true,
          },
          authKind: "oauth",
        },
        { secrets: { copilotToken: "existing-copilot-token" } },
      ),
    );
    expect(await ensureFreshToken(env, "github")).toBe("gh-refreshed");
    const [url, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe(adapter.config.tokenUrl);
    expect(init.method).toBe("POST");
    expect(String(init.body)).toContain("grant_type=refresh_token");
    expect(String(init.body)).toContain("client_id=Iv1.b507a08c87ecfe98");
    expect(String(init.body)).toContain("refresh_token=old-rt");
    expect(String(init.body)).not.toContain("client_secret");
    expect(await getToken(env, "github")).toMatchObject({
      accountLabel: "saved-login",
      meta: {
        githubUserId: 123,
        githubLogin: "saved-login",
        githubName: "Saved Name",
        githubEmail: "saved@example.com",
        copilotTokenExpiresAt: "2026-11-17T00:00:00Z",
        customProfileField: "preserve-me",
        autoSync: true,
      },
      secrets: { copilotToken: "existing-copilot-token" },
    });
  });

  it("prefers fresh enrichment while retaining other metadata and encrypted secrets", () => {
    const mapped = github().mapTokens(
      { access_token: "new-at" },
      {
        githubLogin: "fresh-login",
        githubName: "Fresh Name",
        copilotToken: "fresh-copilot-token",
      },
      { githubLogin: "saved-login", customProfileField: "keep" },
      { copilotToken: "old-copilot-token" },
    );

    expect(mapped.meta).toMatchObject({
      githubLogin: "fresh-login",
      customProfileField: "keep",
    });
    expect(mapped.meta).not.toHaveProperty("copilotToken");
    expect(mapped.secrets).toMatchObject({ copilotToken: "fresh-copilot-token" });
  });
});
