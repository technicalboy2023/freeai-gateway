import { beforeEach, describe, expect, it, vi } from "vitest";
import gateway from "../src/index";
import { getAdapter, OAuthError, start } from "../src/oauth/engine";
import { savePending, saveToken } from "../src/oauth/store";
import { handleLogin } from "../src/admin/auth";
import type { Env } from "../src/env";

const KEY = btoa(String.fromCharCode(...new Uint8Array(32).fill(0x41)))
  .replace(/\+/g, "-")
  .replace(/\//g, "_")
  .replace(/=+$/, "");

const ctx = { waitUntil: () => {} } as unknown as ExecutionContext;

function stubDb() {
  const config: Record<string, string> = {};
  const tokens = new Map<string, Record<string, unknown>>();
  const pending = new Map<string, Record<string, unknown>>();
  const calls: Array<{ sql: string; params: unknown[] }> = [];
  const db = {
    prepare: (sql: string) => ({
      bind: (...params: unknown[]) => {
        calls.push({ sql, params });
        return {
          first: async <T,>() => {
            if (!sql.startsWith("SELECT")) return null;
            if (sql.includes("oauth_pending")) {
              const row = pending.get(String(params[0]));
              return row ? (row as T) : null;
            }
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
        };
      },
    }),
  } as unknown as D1Database;
  return { db, tokens, pending, calls };
}

function envWith(extra: Record<string, unknown> = {}): Env {
  return { ADMIN_PASSWORD: "adm-pass", OAUTH_ENCRYPTION_KEY: KEY, ...extra } as unknown as Env;
}

async function adminCookie(env: Env): Promise<string> {
  const res = await handleLogin(
    new Request("https://gw.test/admin/api/login", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ password: "adm-pass" }),
    }),
    env,
  );
  return (res.headers.get("set-cookie") ?? "").match(/admin_session=([^;]*)/)![1];
}

function adminReq(path: string, init: RequestInit = {}, cookie = ""): Request {
  const headers: Record<string, string> = { ...((init.headers as Record<string, string>) ?? {}) };
  if (cookie) headers.cookie = `admin_session=${cookie}`;
  return new Request(`https://gw.test${path}`, { ...init, headers });
}

/** JSON response helper (same shape as the provider test harnesses). */
function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

beforeEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

/* ---------------- kilocode envelope validation ---------------- */

describe("kilocode start envelope", () => {
  it("unwraps {data:{code,link,expiresIn}} and maps the device shape", async () => {
    const k = getAdapter("kilocode")!;
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        jsonResponse({ data: { code: "kilo-1", link: "https://kilo.ai/verify", expiresIn: 600 } }),
      ),
    );
    const d = await k.requestDeviceCode!(k.config);
    expect(d).toEqual({
      device_code: "kilo-1",
      user_code: "kilo-1",
      verification_uri: "https://kilo.ai/verify",
      verification_uri_complete: "https://kilo.ai/verify",
      expires_in: 600,
      interval: 3,
    });
  });

  it("empty/missing data.code → error naming the field", async () => {
    const k = getAdapter("kilocode")!;
    vi.stubGlobal("fetch", vi.fn(async () => jsonResponse({ data: { code: "", link: "https://v" } })));
    await expect(k.requestDeviceCode!(k.config)).rejects.toThrow(
      "Kilocode device auth response is missing code",
    );
    vi.stubGlobal("fetch", vi.fn(async () => jsonResponse({ data: {} })));
    await expect(k.requestDeviceCode!(k.config)).rejects.toThrow(
      "Kilocode device auth response is missing code",
    );
  });

  it("empty/missing data.link → error naming the field", async () => {
    const k = getAdapter("kilocode")!;
    vi.stubGlobal("fetch", vi.fn(async () => jsonResponse({ data: { code: "k-1", link: "" } })));
    await expect(k.requestDeviceCode!(k.config)).rejects.toThrow(
      "Kilocode device auth response is missing link",
    );
  });

  it("engine start wraps the envelope error as 502 naming the field", async () => {
    const { db } = stubDb();
    const env = envWith({ DB: db });
    vi.stubGlobal("fetch", vi.fn(async () => jsonResponse({ data: { code: "" } })));
    await expect(start(env, "kilocode", new URL("https://gw.test/x"))).rejects.toThrow(
      /kilocode device start failed: Kilocode device auth response is missing code/,
    );
    try {
      await start(env, "kilocode", new URL("https://gw.test/x"));
    } catch (err) {
      expect((err as OAuthError).status).toBe(502);
    }
  });
});

/* ---------------- handleTestProvider oauth branch ---------------- */

describe("handleTestProvider oauth fallback", () => {
  it("connected oauth adapter → {ok:true, provider, auth:'oauth'} (no missing-key)", async () => {
    const { db } = stubDb();
    const env = envWith({ DB: db });
    await saveToken(env, { provider: "cline", accessToken: "at-1", authKind: "oauth" });
    const res = await gateway.fetch(
      adminReq("/admin/api/providers/cline/test", { method: "POST" }, await adminCookie(env)),
      env,
      ctx,
    );
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ ok: true, provider: "cline", auth: "oauth" });
  });

  it("oauth adapter not connected → {ok:false, reason:'not_connected'}", async () => {
    const { db } = stubDb();
    const env = envWith({ DB: db });
    const res = await gateway.fetch(
      adminReq("/admin/api/providers/cline/test", { method: "POST" }, await adminCookie(env)),
      env,
      ctx,
    );
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ ok: false, reason: "not_connected" });
  });

  it("API-key provider test path unchanged; truly unknown prefix still 404", async () => {
    const { db } = stubDb();
    const env = envWith({ DB: db });
    const res = await gateway.fetch(
      adminReq("/admin/api/providers/nope/test", { method: "POST" }, await adminCookie(env)),
      env,
      ctx,
    );
    expect(res.status).toBe(404);
  });
});

/* ---------------- SQL-recorder downgrade (miniflare peer-range failed) ---------------- */

describe("D1 SQL recorder (miniflare fallback)", () => {
  it("savePending: exact upsert columns (extra included) + enc:v1: on every sensitive bind", async () => {
    const rec = stubDb();
    const recEnv = envWith({ DB: rec.db });
    await savePending(recEnv, {
      provider: "ghe-copilot",
      mode: "device",
      state: "st-secret-1",
      codeVerifier: "verifier-secret-2",
      deviceCode: "dc-secret-3",
      extra: { gheUrl: "https://ghe.acme.com" },
      ttlSec: 600,
    });
    const insert = rec.calls.find((c) => c.sql.startsWith("INSERT INTO oauth_pending"));
    expect(insert).toBeDefined();
    const sql = insert!.sql;
    // exact upsert shape: full column list incl. extra, and extra in the update
    expect(sql).toContain("(provider, mode, state, code_verifier, device_code, extra, created_at, expires_at)");
    expect(sql).toContain("VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)");
    expect(sql).toContain("ON CONFLICT(provider) DO UPDATE SET");
    expect(sql).toContain("extra = excluded.extra");
    // every sensitive TEXT bind is enc:v1: ciphertext — no plaintext anywhere
    const [, , state, verifier, deviceCode, extra] = insert!.params;
    for (const v of [state, verifier, deviceCode, extra]) {
      expect(String(v)).toMatch(/^enc:v1:/);
    }
    const blob = `${sql} ${insert!.params.map((p) => String(p)).join(" ")}`;
    expect(blob).not.toContain("st-secret-1");
    expect(blob).not.toContain("verifier-secret-2");
    expect(blob).not.toContain("dc-secret-3");
    expect(blob).not.toContain("ghe.acme.com");
  });

  it("saveToken: exact upsert incl. last_error reset; access/refresh are BLOBs (never string binds)", async () => {
    const rec = stubDb();
    const recEnv = envWith({ DB: rec.db });
    await saveToken(recEnv, {
      provider: "kilocode",
      accessToken: "sk-visible-secret",
      refreshToken: "rt-visible-secret",
      expiresIn: 120,
      authKind: "oauth",
    });
    const insert = rec.calls.find((c) => c.sql.startsWith("INSERT INTO oauth_tokens"));
    expect(insert).toBeDefined();
    const sql = insert!.sql;
    expect(sql).toContain("ON CONFLICT(provider) DO UPDATE SET");
    expect(sql).toContain("last_error = NULL");
    expect(sql).toContain("access_token = excluded.access_token");
    const [, access, refresh] = insert!.params;
    expect(access).toBeInstanceOf(Uint8Array);
    expect(refresh).toBeInstanceOf(Uint8Array);
    const blob = `${sql} ${insert!.params.map((p) => String(p)).join(" ")}`;
    expect(blob).not.toContain("sk-visible-secret");
    expect(blob).not.toContain("rt-visible-secret");
  });
});
