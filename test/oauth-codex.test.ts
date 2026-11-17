import { beforeEach, describe, expect, it, vi } from "vitest";
import { complete, getAdapter, start } from "../src/oauth/engine";
import { ensureFreshToken } from "../src/oauth/refresh";
import { getToken, saveToken } from "../src/oauth/store";
import type { Env } from "../src/env";
import type { OAuthAdapter } from "../src/oauth/types";

const KEY = btoa(String.fromCharCode(...new Uint8Array(32).fill(0x41)))
  .replace(/\+/g, "-")
  .replace(/\//g, "_")
  .replace(/=+$/, "");
const CLIENT_ID = "app_EMoamEEZ73f0CkXaXp7hrann";
const OPENAI_AUTH = "https://api.openai.com/auth";
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
  return `eyJhbGciOiJub25lIn0.${encoded}.signature`;
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

function codex(): OAuthAdapter {
  const adapter = getAdapter("codex");
  if (!adapter) throw new Error("codex adapter was not registered");
  return adapter;
}

function authInfo(planType = "free") {
  return {
    chatgpt_account_id: "acct-123",
    chatgpt_plan_type: planType,
    chatgpt_user_id: "user-456",
    organizations: [
      { id: "org-1", is_default: true, role: "member", title: "Personal" },
      { id: "org-2", is_default: false, role: "admin", title: "Acme Team" },
    ],
  };
}

beforeEach(() => {
  vi.unstubAllGlobals();
});

describe("shared JWT payload decoder", () => {
  it("decodes padded/base64url UTF-8 payloads and returns null for malformed JWTs", async () => {
    const { decodeJwtPayload } = await import("../src/oauth/providers/jwt");
    const payload = { email: "codé@example.com", active: true };
    expect(decodeJwtPayload(jwt(payload))).toEqual(payload);
    expect(decodeJwtPayload("not-a-jwt")).toBeNull();
    expect(decodeJwtPayload("a.b.c")).toBeNull();
    expect(decodeJwtPayload("a.eyJmb28iOg.c")).toBeNull();
  });
});

describe("Codex authorization and workspace mapping", () => {
  it("builds the exact OAuth query with the engine-resolved callback redirect", async () => {
    const { db } = stubDb();
    const result = await start(envWith(db), "codex", new URL(`${ORIGIN}/admin/api/oauth/codex/start`));
    expect(result.mode).toBe("paste-code");
    if (result.mode !== "paste-code") throw new Error("expected paste-code flow");
    expect(codex().redirectUri).toBeUndefined();

    const authUrl = new URL(result.authUrl);
    expect(authUrl.origin + authUrl.pathname).toBe("https://auth.openai.com/oauth/authorize");
    expect(authUrl.searchParams.get("response_type")).toBe("code");
    expect(authUrl.searchParams.get("client_id")).toBe(CLIENT_ID);
    expect(authUrl.searchParams.get("redirect_uri")).toBe(`${ORIGIN}/admin/oauth/codex/callback`);
    expect(authUrl.searchParams.get("scope")).toBe("openid profile email offline_access");
    expect(authUrl.searchParams.get("code_challenge")).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(authUrl.searchParams.get("code_challenge_method")).toBe("S256");
    expect(authUrl.searchParams.get("id_token_add_organizations")).toBe("true");
    expect(authUrl.searchParams.get("codex_cli_simplified_flow")).toBe("true");
    expect(authUrl.searchParams.get("originator")).toBe("codex_cli_rs");
    expect(authUrl.searchParams.get("prompt")).toBe("login");
    expect(authUrl.searchParams.get("state")).toBe(result.state);
    expect([...authUrl.searchParams.keys()].sort()).toEqual(
      [
        "response_type",
        "client_id",
        "redirect_uri",
        "scope",
        "code_challenge",
        "code_challenge_method",
        "id_token_add_organizations",
        "codex_cli_simplified_flow",
        "originator",
        "prompt",
        "state",
      ].sort(),
    );
  });

  it("selects an eligible non-default workspace from a free-plan id_token and stores organizations", async () => {
    const idToken = jwt({ email: "codex@example.com", [OPENAI_AUTH]: authInfo("free") });
    const fetchMock = vi.fn(async () =>
      jsonResponse({ access_token: "codex-at", refresh_token: "codex-rt", id_token: idToken }),
    );
    vi.stubGlobal("fetch", fetchMock);
    const { db } = stubDb();
    const env = envWith(db);
    await start(env, "codex", new URL(`${ORIGIN}/start`));
    const result = await complete(env, "codex", { code: "auth-code" }, new URL(`${ORIGIN}/admin/oauth/codex/callback`));
    expect(result).toEqual({ connected: true, accountLabel: "codex@example.com" });

    const [tokenUrl, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
    expect(tokenUrl).toBe("https://auth.openai.com/oauth/token");
    expect(init.method).toBe("POST");
    const body = new URLSearchParams(String(init.body));
    expect([...body.keys()].sort()).toEqual(
      ["grant_type", "client_id", "code", "redirect_uri", "code_verifier"].sort(),
    );
    expect(body.get("grant_type")).toBe("authorization_code");
    expect(body.get("client_id")).toBe(CLIENT_ID);
    expect(body.get("code")).toBe("auth-code");
    expect(body.get("redirect_uri")).toBe(`${ORIGIN}/admin/oauth/codex/callback`);
    expect(body.get("code_verifier")).toMatch(/^[A-Za-z0-9_-]{43}$/);

    const row = (await getToken(env, "codex"))!;
    expect(row.accessToken).toBe("codex-at");
    expect(row.refreshToken).toBe("codex-rt");
    expect(row.accountLabel).toBe("codex@example.com");
    expect(row.meta).toEqual({
      workspaceId: "org-2",
      workspacePlanType: "team",
      chatgptUserId: "user-456",
      organizations: authInfo("free").organizations,
    });
  });

  it("team plan keeps chatgpt_account_id as workspace and no id_token still connects with null authInfo", async () => {
    const teamToken = jwt({
      email: "team@example.com",
      [OPENAI_AUTH]: { ...authInfo("team"), organizations: [] },
    });
    const { db: teamDb } = stubDb();
    const teamEnv = envWith(teamDb);
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => jsonResponse({ access_token: "team-at", id_token: teamToken })),
    );
    await start(teamEnv, "codex", new URL(`${ORIGIN}/start`));
    await complete(teamEnv, "codex", { code: "team-code" }, new URL(`${ORIGIN}/admin/oauth/codex/callback`));
    expect((await getToken(teamEnv, "codex"))?.meta).toEqual({
      workspaceId: "acct-123",
      workspacePlanType: "team",
      chatgptUserId: "user-456",
      organizations: [],
    });

    const { db: noIdDb } = stubDb();
    const noIdEnv = envWith(noIdDb);
    const noIdFetch = vi.fn(async () => jsonResponse({ access_token: "no-id-at" }));
    vi.stubGlobal("fetch", noIdFetch);
    await start(noIdEnv, "codex", new URL(`${ORIGIN}/start`));
    const result = await complete(
      noIdEnv,
      "codex",
      { code: "no-id-code" },
      new URL(`${ORIGIN}/admin/oauth/codex/callback`),
    );
    expect(result).toEqual({ connected: true, accountLabel: null });
    const extra = await codex().postExchange!({ access_token: "no-id-at" });
    expect(extra).toEqual({ email: null, authInfo: null });
    expect((await getToken(noIdEnv, "codex"))?.meta).toEqual({
      workspaceId: null,
      workspacePlanType: null,
      chatgptUserId: null,
      organizations: null,
    });
  });
});

describe("Codex refresh", () => {
  it("uses the standard refresh grant and never sends scope", async () => {
    const fetchMock = vi.fn(async () =>
      jsonResponse({ access_token: "codex-refreshed", refresh_token: "codex-rt-2", expires_in: 3600 }),
    );
    vi.stubGlobal("fetch", fetchMock);
    const { db } = stubDb();
    const env = envWith(db);
    await saveToken(env, {
      provider: "codex",
      accessToken: "old-at",
      refreshToken: "old-rt",
      expiresIn: 10,
      authKind: "oauth",
    });
    expect(await ensureFreshToken(env, "codex")).toBe("codex-refreshed");
    const [url, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe("https://auth.openai.com/oauth/token");
    expect(init.method).toBe("POST");
    const body = new URLSearchParams(String(init.body));
    expect([...body.keys()].sort()).toEqual(["grant_type", "client_id", "refresh_token"].sort());
    expect(body.get("grant_type")).toBe("refresh_token");
    expect(body.get("client_id")).toBe(CLIENT_ID);
    expect(body.get("refresh_token")).toBe("old-rt");
    expect(body.has("scope")).toBe(false);
  });
});
