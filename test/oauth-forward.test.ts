import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { forwardOr400, forwardToProvider, MissingKeyError, MissingTokenError } from "../src/forward";
import { registerAdapter } from "../src/oauth/engine";
import { saveToken } from "../src/oauth/store";
import type { Env } from "../src/env";
import type { Resolved } from "../src/providers";
import type { OAuthAdapter } from "../src/oauth/types";

const KEY = btoa(String.fromCharCode(...new Uint8Array(32).fill(0x41)))
  .replace(/\+/g, "-")
  .replace(/\//g, "_")
  .replace(/=+$/, "");

function stubDb() {
  const config: Record<string, string> = {};
  const tokens = new Map<string, Record<string, unknown>>();
  const db = {
    prepare: (sql: string) => ({
      bind: (...params: unknown[]) => ({
        first: async <T,>() => {
          if (!sql.startsWith("SELECT")) return null;
          if (sql.includes("oauth_tokens")) {
            const row = tokens.get(String(params[0]));
            return row ? (row as T) : null;
          }
          const key = params[0] as string;
          return key in config ? ({ value: config[key] } as T) : null;
        },
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

function envWith(extra: Record<string, unknown> = {}): Env {
  return { DB: stubDb().db, OAUTH_ENCRYPTION_KEY: KEY, ...extra } as unknown as Env;
}

function oauthResolved(): Resolved {
  return {
    prefix: "fakeoauth",
    baseURL: "https://up.test",
    auth: "bearer",
    oauth: true,
    model: "m",
  } as unknown as Resolved;
}

const oauthAdapter: OAuthAdapter = {
  prefix: "fakeoauth",
  flowMode: "paste",
  config: { tokenUrl: "https://up.test/token", clientId: "cid-1" },
  mapTokens: (tokens) => ({
    accessToken: String(tokens.access_token),
    refreshToken: (tokens.refresh_token as string) ?? null,
    expiresIn: (tokens.expires_in as number) ?? 3600,
  }),
};

registerAdapter(oauthAdapter);

let fetchMock: ReturnType<typeof vi.fn>;

beforeEach(() => {
  fetchMock = vi.fn(async () => new Response("{}", { status: 200 }));
  vi.stubGlobal("fetch", fetchMock);
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("forwardToProvider: oauth bearer", () => {
  it("uses the decrypted store token; no env key consulted", async () => {
    const env = envWith(); // no FAKEOAUTH key secret exists at all
    await saveToken(env, { provider: "fakeoauth", accessToken: "stored-at", expiresIn: 3600, authKind: "paste" });
    const res = await forwardToProvider(oauthResolved(), "/chat/completions", { m: 1 }, env);
    expect(res.status).toBe(200);
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("https://up.test/chat/completions");
    expect((init.headers as Record<string, string>)["authorization"]).toBe("Bearer stored-at");
    expect(JSON.stringify(init.body)).toContain("m");
  });

  it("expired token → refresh POST first, forward carries the rotated token", async () => {
    const env = envWith();
    await saveToken(env, {
      provider: "fakeoauth",
      accessToken: "old-at",
      expiresIn: 10, // within REFRESH_SKEW_SEC
      refreshToken: "old-rt",
      authKind: "paste",
    });
    fetchMock.mockResolvedValueOnce(
      new Response(JSON.stringify({ access_token: "new-at", refresh_token: "new-rt", expires_in: 7200 }), {
        status: 200,
        headers: { "content-type": "application/json" },
      }),
    );
    const res = await forwardToProvider(oauthResolved(), "/chat/completions", { m: 1 }, env);
    expect(res.status).toBe(200);
    expect(fetchMock).toHaveBeenCalledTimes(2);
    const [, refreshInit] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(String(refreshInit.body)).toContain("grant_type=refresh_token");
    const [, forwardInit] = fetchMock.mock.calls[1] as [string, RequestInit];
    expect((forwardInit.headers as Record<string, string>)["authorization"]).toBe("Bearer new-at");
  });

  it("not connected → MissingTokenError (400 semantics)", async () => {
    const env = envWith();
    await expect(forwardToProvider(oauthResolved(), "/chat/completions", { m: 1 }, env)).rejects.toThrow(
      MissingTokenError,
    );
  });
});

describe("forwardOr400: oauth", () => {
  it("not connected → 400 with meta.error missing-token:fakeoauth", async () => {
    const env = envWith();
    const meta: { error?: string } = {};
    const res = await forwardOr400(oauthResolved(), "/chat/completions", { m: 1 }, env, undefined, meta);
    expect(res.status).toBe(400);
    const body = (await res.json()) as { error: { message: string } };
    expect(body.error.message).toContain("fakeoauth");
    expect(meta.error).toBe("missing-token:fakeoauth");
  });

  it("oauth 400 skip-in-chain semantics: MissingTokenError is not a 502", async () => {
    const env = envWith();
    const meta: { error?: string } = {};
    const res = await forwardOr400(oauthResolved(), "/chat/completions", { m: 1 }, env, undefined, meta);
    expect(res.status).toBe(400);
    expect(meta.error).not.toBe("network-error:fakeoauth");
  });
});

describe("non-oauth regression", () => {
  const groqResolved: Resolved = {
    prefix: "groq",
    baseURL: "https://api.groq.com/openai/v1",
    auth: "bearer",
    keySecret: "GROQ_API_KEY",
    model: "m",
  } as unknown as Resolved;

  it("oauth undefined → providerKey still used", async () => {
    const env = envWith({ GROQ_API_KEY: "sk-groq-test" });
    await forwardToProvider(groqResolved, "/chat/completions", { m: 1 }, env);
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("https://api.groq.com/openai/v1/chat/completions");
    expect((init.headers as Record<string, string>)["authorization"]).toBe("Bearer sk-groq-test");
  });

  it("missing key → MissingKeyError (unchanged)", async () => {
    const env = envWith(); // no GROQ_API_KEY
    await expect(forwardToProvider(groqResolved, "/chat/completions", { m: 1 }, env)).rejects.toThrow(
      MissingKeyError,
    );
  });
});
