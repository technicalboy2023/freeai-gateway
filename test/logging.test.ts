import { afterEach, describe, expect, it, vi } from "vitest";
import { logRequest } from "../src/logging";
import { handleChat } from "../src/chat";
import { handleMessages } from "../src/messages";
import { runChain } from "../src/fallback";
import type { Env } from "../src/env";

/** Minimal D1Database stub capturing INSERT calls. */
function stubDb(opts: { failRun?: boolean } = {}) {
  const rows: Array<{ sql: string; params: unknown[] }> = [];
  const db = {
    prepare: (sql: string) => ({
      bind: (...params: unknown[]) => ({
        first: async () => null,
        run: async () => {
          if (opts.failRun) throw new Error("d1 write failed");
          rows.push({ sql, params });
          return { success: true };
        },
      }),
    }),
  } as unknown as D1Database;
  return { db, rows };
}

const captured: Promise<unknown>[] = [];
const ctx = {
  waitUntil: (p: Promise<unknown>) => captured.push(p),
} as unknown as ExecutionContext;

afterEach(() => {
  vi.unstubAllGlobals();
  captured.length = 0;
});

describe("logRequest (unit)", () => {
  it("inserts one row with all entry fields", async () => {
    const { db, rows } = stubDb();
    await logRequest(db, {
      ts: 1000,
      provider: "groq",
      model: "llama",
      status: 200,
      latencyMs: 42,
      stream: true,
      chain: "fast",
      attempt: 2,
      error: null,
    });
    expect(rows).toHaveLength(1);
    expect(rows[0].sql).toContain("INSERT INTO request_logs");
    expect(rows[0].params).toEqual([1000, "groq", "llama", 200, 42, 1, "fast", 2, null]);
  });

  it("swallows D1 write failures (logging must never break the request)", async () => {
    const { db } = stubDb({ failRun: true });
    await expect(
      logRequest(db, {
        ts: 1,
        provider: "groq",
        model: "m",
        status: 200,
        latencyMs: 1,
        stream: false,
      }),
    ).resolves.toBeUndefined();
  });

  it("no-ops without a DB binding", async () => {
    await expect(
      logRequest(undefined, {
        ts: 1,
        provider: "g",
        model: "m",
        status: 200,
        latencyMs: 1,
        stream: false,
      }),
    ).resolves.toBeUndefined();
  });
});

describe("proxy logging integration", () => {
  const envWith = (extra: Record<string, unknown> = {}) =>
    ({
      GATEWAY_KEY: "gwk",
      GROQ_API_KEY: "gk",
      GEMINI_API_KEY: "gmk",
      ANTHROPIC_API_KEY: "ak",
      FALLBACK_CHAINS: JSON.stringify({ fast: ["groq", "gemini"] }),
      ...extra,
    }) as unknown as Env;

  function chatReq(model: string): Request {
    return new Request("https://gw.test/v1/chat/completions", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ model, messages: [] }),
    });
  }

  it("direct chat request logs provider/model/status/stream=false", async () => {
    const { db, rows } = stubDb();
    vi.stubGlobal("fetch", vi.fn(async () => new Response("{}", { status: 200 })));
    await handleChat(chatReq("groq/llama"), envWith({ DB: db }), ctx);
    await Promise.all(captured);
    expect(rows).toHaveLength(1);
    const params = rows[0].params as unknown[];
    expect(params[1]).toBe("groq");
    expect(params[2]).toBe("llama");
    expect(params[3]).toBe(200);
    expect(params[5]).toBe(0);
    expect(params[6]).toBeNull();
  });

  it("messages request logs anthropic provider with chain/attempt null", async () => {
    const { db, rows } = stubDb();
    vi.stubGlobal("fetch", vi.fn(async () => new Response("{}", { status: 200 })));
    const req = new Request("https://gw.test/v1/messages", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ model: "claude-sonnet-4", messages: [], max_tokens: 1 }),
    });
    await handleMessages(req, envWith({ DB: db }), ctx);
    await Promise.all(captured);
    expect(rows).toHaveLength(1);
    const params = rows[0].params as unknown[];
    expect(params[1]).toBe("anthropic");
    expect(params[3]).toBe(200);
    expect(params[6]).toBeNull();
    expect(params[7]).toBeNull();
  });

  it("fallback attempts log chain/attempt per provider (429 then 200)", async () => {
    const { db, rows } = stubDb();
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(new Response("rl", { status: 429 }))
      .mockResolvedValueOnce(new Response("{}", { status: 200 }));
    vi.stubGlobal("fetch", fetchMock);
    await runChain(chatReq("fast/llama"), envWith({ DB: db }), ctx);
    await Promise.all(captured);
    expect(rows).toHaveLength(2);
    expect((rows[0].params as unknown[])[1]).toBe("groq");
    expect((rows[0].params as unknown[])[3]).toBe(429);
    expect((rows[0].params as unknown[])[6]).toBe("fast");
    expect((rows[0].params as unknown[])[7]).toBe(1);
    expect((rows[1].params as unknown[])[1]).toBe("gemini");
    expect((rows[1].params as unknown[])[3]).toBe(200);
    expect((rows[1].params as unknown[])[7]).toBe(2);
  });

  it("no DB binding → proxy unaffected and nothing scheduled", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => new Response("{}", { status: 200 })));
    const res = await handleChat(chatReq("groq/llama"), envWith(), ctx);
    expect(res.status).toBe(200);
    await Promise.all(captured);
    expect(captured).toHaveLength(0);
  });

  it("direct chat with unreachable provider logs error tag naming the provider", async () => {
    const { db, rows } = stubDb();
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => {
        throw new Error("dns fail");
      }),
    );
    const res = await handleChat(chatReq("groq/llama"), envWith({ DB: db }), ctx);
    expect(res.status).toBe(502);
    await Promise.all(captured);
    expect(rows).toHaveLength(1);
    const params = rows[0].params as unknown[];
    expect(params[3]).toBe(502);
    expect(params[8]).toBe("network-error:groq");
  });

  it("direct chat with missing key logs error naming the secret", async () => {
    const { db, rows } = stubDb();
    const e = envWith({ GROQ_API_KEY: undefined, DB: db });
    const res = await handleChat(chatReq("groq/llama"), e, ctx);
    expect(res.status).toBe(400);
    await Promise.all(captured);
    expect(rows).toHaveLength(1);
    const params = rows[0].params as unknown[];
    expect(params[3]).toBe(400);
    expect(params[8]).toBe("missing-key:GROQ_API_KEY");
  });
});
