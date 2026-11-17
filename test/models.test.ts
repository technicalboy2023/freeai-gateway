import { describe, expect, it } from "vitest";
import worker from "../src/index";
import type { Env } from "../src/env";

const env = { GATEWAY_KEY: "gwk" } as Env;
const ctx = {} as unknown as ExecutionContext;

describe("GET /v1/models", () => {
  it("returns openai-style list with provider-prefixed ids", async () => {
    const res = await worker.fetch(new Request("https://gw.test/v1/models"), env, ctx);
    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      object: string;
      data: Array<{ id: string; object: string; owned_by: string }>;
    };
    expect(body.object).toBe("list");
    const ids = body.data.map((m) => m.id);
    expect(ids).toContain("groq/llama-3.3-70b-versatile");
    expect(ids).toContain("gemini/gemini-2.0-flash");
    expect(ids).toContain("openrouter/deepseek/deepseek-r1:free");
    expect(ids).toContain("anthropic/claude-sonnet-4-5");
    for (const m of body.data) {
      expect(m.object).toBe("model");
      expect(m.owned_by).toBeTruthy();
    }
  });
});

describe("disabled-provider filtering (review fix)", () => {
  function stubDb(rows: Record<string, string>) {
    const db = {
      prepare: (sql: string) => ({
        bind: (...params: unknown[]) => ({
          first: async <T,>() => {
            if (!sql.startsWith("SELECT")) return null;
            const key = params[0] as string;
            return key in rows ? ({ value: rows[key] } as T) : null;
          },
        }),
      }),
    } as unknown as D1Database;
    return db;
  }

  it("hides disabled providers' models when a DB binding is present", async () => {
    const e = {
      GATEWAY_KEY: "gwk",
      DB: stubDb({ providers_enabled: '{"nvidia":false}' }),
    } as unknown as Env;
    const res = await worker.fetch(new Request("https://gw.test/v1/models"), e, ctx);
    expect(res.status).toBe(200);
    const body = (await res.json()) as { data: Array<{ id: string }> };
    const ids = body.data.map((m) => m.id);
    expect(ids.some((id) => id.startsWith("nvidia/"))).toBe(false);
    expect(ids).toContain("groq/llama-3.3-70b-versatile");
  });
});

describe("cache headers (review fix)", () => {
  it("json responses carry cache-control: no-store", async () => {
    const res = await worker.fetch(new Request("https://gw.test/"), env, ctx);
    expect(res.headers.get("cache-control")).toBe("no-store");
  });
});

describe("CORS", () => {
  it("OPTIONS any path returns 204 with CORS headers", async () => {
    const res = await worker.fetch(
      new Request("https://gw.test/v1/chat/completions", { method: "OPTIONS" }),
      env,
      ctx,
    );
    expect(res.status).toBe(204);
    expect(res.headers.get("access-control-allow-origin")).toBe("*");
    expect(res.headers.get("access-control-allow-methods")).toContain("POST");
    expect(res.headers.get("access-control-allow-headers")!.toLowerCase()).toContain(
      "authorization",
    );
  });

  it("normal json responses carry CORS headers", async () => {
    const res = await worker.fetch(new Request("https://gw.test/"), env, ctx);
    expect(res.headers.get("access-control-allow-origin")).toBe("*");
  });

  it("auth failures carry CORS headers too", async () => {
    const res = await worker.fetch(
      new Request("https://gw.test/v1/chat/completions", { method: "POST" }),
      env,
      ctx,
    );
    expect(res.status).toBe(401);
    expect(res.headers.get("access-control-allow-origin")).toBe("*");
  });
});
