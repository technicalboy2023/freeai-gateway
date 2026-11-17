import { describe, expect, it, vi } from "vitest";
import gateway from "../src/index";
import { runChain } from "../src/fallback";
import { handleLogin } from "../src/admin/auth";
import type { Env } from "../src/env";

function stubDb(
  opts: {
    configRows?: Record<string, string>;
    logRows?: unknown[];
    statsResults?: unknown[];
    failAll?: boolean;
  } = {},
) {
  const rows: Record<string, string> = { ...(opts.configRows ?? {}) };
  const runCalls: Array<{ sql: string; params: unknown[] }> = [];
  const selectCalls: Array<{ sql: string; params: unknown[] }> = [];
  const db = {
    prepare: (sql: string) => ({
      bind: (...params: unknown[]) => ({
        first: async <T,>() => {
          if (!sql.startsWith("SELECT")) return null;
          const key = params[0] as string;
          return key in rows ? ({ value: rows[key] } as T) : null;
        },
        all: async <T,>() => {
          if (opts.failAll) throw new Error("d1 unavailable");
          selectCalls.push({ sql, params });
          if (sql.includes("GROUP BY")) {
            return { results: opts.statsResults ?? [] } as unknown;
          }
          return { results: opts.logRows ?? [] } as unknown;
        },
        run: async () => {
          runCalls.push({ sql, params });
          if (sql.includes("INSERT INTO config")) {
            rows[params[0] as string] = params[1] as string;
          }
          return { success: true };
        },
      }),
    }),
  } as unknown as D1Database;
  return { db, rows, runCalls, selectCalls };
}

const ctx = { waitUntil: () => {} } as unknown as ExecutionContext;

function envWith(extra: Record<string, unknown> = {}): Env {
  return {
    ADMIN_PASSWORD: "adm-pass",
    GROQ_API_KEY: "sk-groq-test",
    GEMINI_API_KEY: "sk-gemini-test",
    FALLBACK_CHAINS: JSON.stringify({ fast: ["groq", "gemini"] }),
    ...extra,
  } as unknown as Env;
}

function loginReq(password: string): Request {
  return new Request("https://gw.test/admin/api/login", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ password }),
  });
}

async function adminCookie(env: Env): Promise<string> {
  const res = await handleLogin(loginReq("adm-pass"), env);
  return (res.headers.get("set-cookie") ?? "").match(/admin_session=([^;]*)/)![1];
}

function adminReq(path: string, init: RequestInit = {}, cookie = ""): Request {
  const headers: Record<string, string> = {
    ...((init.headers as Record<string, string>) ?? {}),
  };
  if (cookie) headers.cookie = `admin_session=${cookie}`;
  return new Request(`https://gw.test${path}`, { ...init, headers });
}

function chatReq(model: string): Request {
  return new Request("https://gw.test/v1/chat/completions", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ model, messages: [] }),
  });
}

describe("GET /admin/api/fallbacks", () => {
  it("D1 row wins over env", async () => {
    const env = envWith({
      DB: stubDb({ configRows: { fallback_chains: '{"primary":["nvidia","zen"]}' } }).db,
    });
    const res = await gateway.fetch(
      adminReq("/admin/api/fallbacks", {}, await adminCookie(env)),
      env,
      ctx,
    );
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({
      chains: [{ name: "primary", providers: ["nvidia", "zen"] }],
    });
  });

  it("env fallback when no D1 row", async () => {
    const env = envWith({ DB: stubDb().db });
    const res = await gateway.fetch(
      adminReq("/admin/api/fallbacks", {}, await adminCookie(env)),
      env,
      ctx,
    );
    expect(await res.json()).toEqual({
      chains: [{ name: "fast", providers: ["groq", "gemini"] }],
    });
  });

  it("default chain when neither D1 nor env has chains", async () => {
    const env = envWith({ FALLBACK_CHAINS: undefined, DB: stubDb().db });
    const res = await gateway.fetch(
      adminReq("/admin/api/fallbacks", {}, await adminCookie(env)),
      env,
      ctx,
    );
    expect(await res.json()).toEqual({
      chains: [{ name: "default", providers: ["groq", "gemini"] }],
    });
  });

  it("PUT {chains:[]} then GET shows the empty state — no phantom default", async () => {
    const { db, rows } = stubDb();
    const env = envWith({ DB: db });
    const cookie = await adminCookie(env);
    const put = await gateway.fetch(
      adminReq(
        "/admin/api/fallbacks",
        {
          method: "PUT",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ chains: [] }),
        },
        cookie,
      ),
      env,
      ctx,
    );
    expect(put.status).toBe(200);
    expect(rows.fallback_chains).toBe("{}");
    const get = await gateway.fetch(
      adminReq("/admin/api/fallbacks", {}, cookie),
      env,
      ctx,
    );
    expect(get.status).toBe(200);
    // A D1 row exists (persisted "{}"), so GET must reflect it exactly —
    // showing DEFAULT_CHAINS here would lie about live config.
    expect(await get.json()).toEqual({ chains: [] });
  });
});

describe("PUT /admin/api/fallbacks", () => {
  it("valid chains persist and override env for the proxy", async () => {
    const { db, rows } = stubDb();
    const env = envWith({ DB: db });
    const res = await gateway.fetch(
      adminReq(
        "/admin/api/fallbacks",
        {
          method: "PUT",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ chains: [{ name: "fast", providers: ["gemini"] }] }),
        },
        await adminCookie(env),
      ),
      env,
      ctx,
    );
    expect(res.status).toBe(200);
    expect(rows.fallback_chains).toBe('{"fast":["gemini"]}');
    // Proxy now uses the D1 chain (gemini only), ignoring env chains.
    const fetchMock = vi.fn(async () => new Response("{}", { status: 200 }));
    vi.stubGlobal("fetch", fetchMock);
    const chat = await runChain(chatReq("fast/m"), env, ctx);
    expect(chat.status).toBe(200);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url] = fetchMock.mock.calls[0] as unknown as [string];
    expect(url).toContain("generativelanguage.googleapis.com");
  });

  it("unknown provider prefix → 400 naming it", async () => {
    const env = envWith({ DB: stubDb().db });
    const res = await gateway.fetch(
      adminReq(
        "/admin/api/fallbacks",
        {
          method: "PUT",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({
            chains: [{ name: "fast", providers: ["groq", "nope"] }],
          }),
        },
        await adminCookie(env),
      ),
      env,
      ctx,
    );
    expect(res.status).toBe(400);
    const body = (await res.json()) as { error: { message: string } };
    expect(body.error.message).toContain("Unknown provider prefix 'nope'");
  });

  it("without DB → 503", async () => {
    const env = envWith();
    const res = await gateway.fetch(
      adminReq(
        "/admin/api/fallbacks",
        {
          method: "PUT",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ chains: [{ name: "fast", providers: ["groq"] }] }),
        },
        await adminCookie(env),
      ),
      env,
      ctx,
    );
    expect(res.status).toBe(503);
  });

  it("chain name colliding with a provider prefix → 400 (unreachable dead config)", async () => {
    const env = envWith({ DB: stubDb().db });
    const res = await gateway.fetch(
      adminReq(
        "/admin/api/fallbacks",
        {
          method: "PUT",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({
            chains: [{ name: "groq", providers: ["gemini"] }],
          }),
        },
        await adminCookie(env),
      ),
      env,
      ctx,
    );
    expect(res.status).toBe(400);
    const body = (await res.json()) as { error: { message: string } };
    expect(body.error.message).toContain("groq");
    expect(body.error.message).toContain("provider");
  });

  it("duplicate chain names → 400 (last-wins collapse lies about the save)", async () => {
    const env = envWith({ DB: stubDb().db });
    const res = await gateway.fetch(
      adminReq(
        "/admin/api/fallbacks",
        {
          method: "PUT",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({
            chains: [
              { name: "fast", providers: ["groq"] },
              { name: "fast", providers: ["gemini"] },
            ],
          }),
        },
        await adminCookie(env),
      ),
      env,
      ctx,
    );
    expect(res.status).toBe(400);
    const body = (await res.json()) as { error: { message: string } };
    expect(body.error.message).toContain("Duplicate chain name 'fast'");
  });
});

describe("GET /admin/api/logs", () => {
  it("returns rows desc by ts, honoring limit", async () => {
    const logRows = [
      { id: 2, ts: 200, provider: "gemini", model: "m", status: 200 },
      { id: 1, ts: 100, provider: "groq", model: "m", status: 429 },
    ];
    const { db, selectCalls } = stubDb({ logRows });
    const env = envWith({ DB: db });
    const cookie = await adminCookie(env);
    const res = await gateway.fetch(
      adminReq("/admin/api/logs?limit=50", {}, cookie),
      env,
      ctx,
    );
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ logs: logRows });
    expect(selectCalls[0].sql).toContain("ORDER BY ts DESC");
    expect(selectCalls[0].sql).toContain("LIMIT ?1");
    expect(selectCalls[0].params[0]).toBe(50);
    const res2 = await gateway.fetch(
      adminReq("/admin/api/logs?limit=2", {}, cookie),
      env,
      ctx,
    );
    expect(res2.status).toBe(200);
    expect(selectCalls.at(-1)!.params[0]).toBe(2);
  });

  it("without DB → 503", async () => {
    const env = envWith();
    const res = await gateway.fetch(
      adminReq("/admin/api/logs", {}, await adminCookie(env)),
      env,
      ctx,
    );
    expect(res.status).toBe(503);
  });
});

describe("GET /admin/api/stats", () => {
  it("per-provider requests/errors/avgLatencyMs over a 7d window", async () => {
    const statsResults = [
      { provider: "groq", requests: 10, errors: 2, avgLatencyMs: 120.5 },
      { provider: "gemini", requests: 4, errors: 0, avgLatencyMs: 300 },
    ];
    const { db, selectCalls } = stubDb({ statsResults });
    const env = envWith({ DB: db });
    const res = await gateway.fetch(
      adminReq("/admin/api/stats", {}, await adminCookie(env)),
      env,
      ctx,
    );
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ stats: statsResults });
    expect(selectCalls[0].sql).toContain("GROUP BY provider");
    expect(selectCalls[0].sql).toContain("status >= 400");
    expect(selectCalls[0].sql).toContain("status = 0");
    const since = selectCalls[0].params[0] as number;
    const now = Date.now();
    expect(since).toBeGreaterThan(now - 7 * 24 * 60 * 60 * 1000 - 2000);
    expect(since).toBeLessThanOrEqual(now);
  });

  it("without DB → 503", async () => {
    const env = envWith();
    const res = await gateway.fetch(
      adminReq("/admin/api/stats", {}, await adminCookie(env)),
      env,
      ctx,
    );
    expect(res.status).toBe(503);
  });
});

describe("POST /admin/api/logs/prune", () => {
  function pruneReq(body: unknown, cookie: string): Request {
    return adminReq(
      "/admin/api/logs/prune",
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(body),
      },
      cookie,
    );
  }

  it("deletes rows older than N days (SQL + cutoff param)", async () => {
    const { db, runCalls } = stubDb();
    const env = envWith({ DB: db });
    const res = await gateway.fetch(
      pruneReq({ olderThanDays: 7 }, await adminCookie(env)),
      env,
      ctx,
    );
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ ok: true, olderThanDays: 7 });
    const call = runCalls.find((c) => c.sql.includes("DELETE FROM request_logs"));
    expect(call).toBeDefined();
    expect(call!.sql).toContain("ts <");
    const cutoff = call!.params[0] as number;
    const target = Date.now() - 7 * 24 * 60 * 60 * 1000;
    expect(cutoff).toBeGreaterThan(target - 2000);
    expect(cutoff).toBeLessThanOrEqual(target + 2000);
  });

  it("invalid olderThanDays (0, negative, wrong type) → 400", async () => {
    const env = envWith({ DB: stubDb().db });
    const cookie = await adminCookie(env);
    for (const bad of [0, -3, "7", null]) {
      const res = await gateway.fetch(pruneReq({ olderThanDays: bad }, cookie), env, ctx);
      expect(res.status).toBe(400);
    }
  });

  it("without DB → 503", async () => {
    const env = envWith();
    const res = await gateway.fetch(
      pruneReq({ olderThanDays: 7 }, await adminCookie(env)),
      env,
      ctx,
    );
    expect(res.status).toBe(503);
  });
});

describe("admin gate", () => {
  it("fallbacks/logs/stats without a session → 401", async () => {
    const env = envWith();
    const paths: Array<[string, RequestInit]> = [
      ["/admin/api/fallbacks", { method: "GET" }],
      [
        "/admin/api/fallbacks",
        {
          method: "PUT",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ chains: [] }),
        },
      ],
      ["/admin/api/logs", { method: "GET" }],
      ["/admin/api/stats", { method: "GET" }],
    ];
    for (const [path, init] of paths) {
      const res = await gateway.fetch(adminReq(path, init), env, ctx);
      expect(res.status).toBe(401);
    }
  });
});
