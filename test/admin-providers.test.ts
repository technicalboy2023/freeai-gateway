import { afterEach, describe, expect, it, vi } from "vitest";
import gateway from "../src/index";
import { handleChat } from "../src/chat";
import { runChain } from "../src/fallback";
import { handleLogin } from "../src/admin/auth";
import type { Env } from "../src/env";

/** D1 stub: SELECT reads `rows`, run() captures calls and persists config upserts into `rows`. */
function stubDb(
  rows: Record<string, string> = {},
  opts: { failQuery?: boolean } = {},
) {
  const runCalls: Array<{ sql: string; params: unknown[] }> = [];
  const db = {
    prepare: (sql: string) => ({
      bind: (...params: unknown[]) => ({
        first: async <T,>() => {
          if (opts.failQuery) throw new Error("d1 unavailable");
          if (!sql.startsWith("SELECT")) return null;
          const key = params[0] as string;
          return key in rows ? ({ value: rows[key] } as T) : null;
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
  return { db, runCalls, rows };
}

const ctx = { waitUntil: () => {} } as unknown as ExecutionContext;

function envWith(extra: Record<string, unknown> = {}): Env {
  return {
    ADMIN_PASSWORD: "adm-pass",
    GROQ_API_KEY: "sk-groq-test",
    GEMINI_API_KEY: "sk-gemini-test",
    ANTHROPIC_API_KEY: "sk-ant-test",
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

function adminReq(
  path: string,
  init: RequestInit = {},
  cookie = "",
): Request {
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

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("GET /admin/api/providers", () => {
  it("lists registry with enabled/keyConfigured/freeModels and NO key material", async () => {
    const env = envWith({ DB: stubDb({ providers_enabled: '{"nvidia":false}' }).db });
    const res = await gateway.fetch(
      adminReq("/admin/api/providers", {}, await adminCookie(env)),
      env,
      ctx,
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as { providers: Array<Record<string, unknown>> };
    expect(body.providers).toHaveLength(8);
    const nvidia = body.providers.find((p) => p.prefix === "nvidia");
    expect(nvidia!.enabled).toBe(false);
    expect(nvidia!.keyConfigured).toBe(false);
    const groq = body.providers.find((p) => p.prefix === "groq");
    expect(groq!.enabled).toBe(true);
    expect(groq!.keyConfigured).toBe(true);
    expect(groq!.freeModels).toContain("llama-3.3-70b-versatile");
    expect(JSON.stringify(body)).not.toContain("sk-groq-test");
    expect(JSON.stringify(body)).not.toContain("sk-ant-test");
  });
});

describe("POST /admin/api/providers/:prefix/toggle", () => {
  it("writes the providers_enabled map, merging existing entries", async () => {
    const { db, rows } = stubDb({ providers_enabled: '{"groq":false}' });
    const env = envWith({ DB: db });
    const res = await gateway.fetch(
      adminReq(
        "/admin/api/providers/nvidia/toggle",
        {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ enabled: false }),
        },
        await adminCookie(env),
      ),
      env,
      ctx,
    );
    expect(res.status).toBe(200);
    expect(JSON.parse(rows.providers_enabled!)).toEqual({ groq: false, nvidia: false });
  });

  it("unknown prefix → 404", async () => {
    const env = envWith({ DB: stubDb().db });
    const res = await gateway.fetch(
      adminReq(
        "/admin/api/providers/nope/toggle",
        {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ enabled: true }),
        },
        await adminCookie(env),
      ),
      env,
      ctx,
    );
    expect(res.status).toBe(404);
    const body = (await res.json()) as { error: { message: string } };
    expect(body.error.message).toContain("Unknown provider 'nope'");
  });

  it("D1 read failure → 503 and ZERO writes (no silent wipe of the enabled map)", async () => {
    const { db, runCalls } = stubDb(
      { providers_enabled: '{"groq":false}' },
      { failQuery: true },
    );
    const env = envWith({ DB: db });
    const res = await gateway.fetch(
      adminReq(
        "/admin/api/providers/nvidia/toggle",
        {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ enabled: false }),
        },
        await adminCookie(env),
      ),
      env,
      ctx,
    );
    expect(res.status).toBe(503);
    const body = (await res.json()) as { error: { message: string } };
    expect(body.error.message).toContain("D1");
    const inserts = runCalls.filter((c) => c.sql.includes("INSERT INTO config"));
    expect(inserts).toHaveLength(0);
  });

  it("no DB binding → clean 503 (parity with PUT fallbacks), not 500", async () => {
    const env = envWith(); // no DB
    const res = await gateway.fetch(
      adminReq(
        "/admin/api/providers/groq/toggle",
        {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ enabled: true }),
        },
        await adminCookie(env),
      ),
      env,
      ctx,
    );
    expect(res.status).toBe(503);
    const body = (await res.json()) as { error: { message: string } };
    expect(body.error.message).toContain("D1");
  });
});

describe("POST /admin/api/providers/:prefix/test", () => {
  it("pings the provider with its key; returns ok/status/latencyMs, never the key", async () => {
    const fetchMock = vi.fn(async () => new Response('{"data":[]}', { status: 200 }));
    vi.stubGlobal("fetch", fetchMock);
    const env = envWith();
    const res = await gateway.fetch(
      adminReq("/admin/api/providers/groq/test", { method: "POST" }, await adminCookie(env)),
      env,
      ctx,
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as { ok: boolean; status: number; latencyMs: number };
    expect(body.ok).toBe(true);
    expect(body.status).toBe(200);
    expect(typeof body.latencyMs).toBe("number");
    const [url, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe("https://api.groq.com/openai/v1/models");
    expect(init.method).toBe("GET");
    expect((init.headers as Record<string, string>).authorization).toBe("Bearer sk-groq-test");
    expect(JSON.stringify(body)).not.toContain("sk-groq-test");
  });

  it("upstream 401 → ok:false with the upstream status", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => new Response("no", { status: 401 })));
    const env = envWith();
    const res = await gateway.fetch(
      adminReq("/admin/api/providers/groq/test", { method: "POST" }, await adminCookie(env)),
      env,
      ctx,
    );
    const body = (await res.json()) as { ok: boolean; status: number };
    expect(body.ok).toBe(false);
    expect(body.status).toBe(401);
  });

  it("network failure → ok:false with status 0", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => {
      throw new Error("dns fail");
    }));
    const env = envWith();
    const res = await gateway.fetch(
      adminReq("/admin/api/providers/groq/test", { method: "POST" }, await adminCookie(env)),
      env,
      ctx,
    );
    const body = (await res.json()) as { ok: boolean; status: number };
    expect(body.ok).toBe(false);
    expect(body.status).toBe(0);
  });
});

describe("admin gate", () => {
  it("providers endpoints without a session → 401", async () => {
    const env = envWith();
    const list = await gateway.fetch(
      adminReq("/admin/api/providers"),
      env,
      ctx,
    );
    expect(list.status).toBe(401);
    const toggle = await gateway.fetch(
      adminReq("/admin/api/providers/groq/toggle", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ enabled: true }),
      }),
      env,
      ctx,
    );
    expect(toggle.status).toBe(401);
  });
});

describe("enabled-check integration (proxy path)", () => {
  it("disabled provider → 400 naming it, no upstream call (DB present)", async () => {
    const fetchMock = vi.fn(async () => new Response("{}", { status: 200 }));
    vi.stubGlobal("fetch", fetchMock);
    const env = envWith({
      DB: stubDb({ providers_enabled: '{"nvidia":false}' }).db,
    });
    const res = await handleChat(chatReq("nvidia/m"), env, ctx);
    expect(res.status).toBe(400);
    const body = (await res.json()) as { error: { message: string } };
    expect(body.error.message).toContain("nvidia");
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("fail-open: providers_enabled env var but NO DB binding → provider still works", async () => {
    const fetchMock = vi.fn(async () => new Response("{}", { status: 200 }));
    vi.stubGlobal("fetch", fetchMock);
    const env = envWith({ providers_enabled: '{"nvidia":false}', NVIDIA_API_KEY: "sk-nv-test" });
    const res = await handleChat(chatReq("nvidia/m"), env, ctx);
    expect(res.status).toBe(200);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("fallback chains skip a disabled provider (logged as attempt error 'disabled')", async () => {
    const fetchMock = vi.fn(async () => new Response("{}", { status: 200 }));
    vi.stubGlobal("fetch", fetchMock);
    const { db, runCalls } = stubDb({ providers_enabled: '{"groq":false}' });
    const env = envWith({ DB: db });
    const res = await runChain(chatReq("fast/m"), env, ctx);
    expect(res.status).toBe(200);
    expect(fetchMock).toHaveBeenCalledTimes(1); // only gemini was called
    const logRows = runCalls
      .filter((c) => c.sql.includes("INSERT INTO request_logs"))
      .map((c) => c.params as unknown[]);
    expect(logRows).toHaveLength(2);
    expect(logRows[0][1]).toBe("groq");
    expect(logRows[0][3]).toBe(0);
    expect(logRows[0][7]).toBe(1);
    expect(logRows[0][8]).toBe("disabled");
    expect(logRows[1][1]).toBe("gemini");
    expect(logRows[1][3]).toBe(200);
    expect(logRows[1][7]).toBe(2);
  });
});
