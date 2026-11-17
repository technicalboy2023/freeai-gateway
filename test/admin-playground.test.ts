import { afterEach, describe, expect, it, vi } from "vitest";
import gateway from "../src/index";
import { handleLogin } from "../src/admin/auth";
import type { Env } from "../src/env";

function stubDb() {
  const logRows: Array<{ sql: string; params: unknown[] }> = [];
  const db = {
    prepare: (sql: string) => ({
      bind: (...params: unknown[]) => ({
        first: async () => null,
        all: async () => ({ results: [] }),
        run: async () => {
          logRows.push({ sql, params });
          return { success: true };
        },
      }),
    }),
  } as unknown as D1Database;
  return { db, logRows };
}

const ctx = { waitUntil: (p: Promise<unknown>) => captured.push(p) } as unknown as ExecutionContext;
const captured: Promise<unknown>[] = [];

afterEach(() => {
  vi.unstubAllGlobals();
  captured.length = 0;
});

function envWith(extra: Record<string, unknown> = {}): Env {
  return {
    ADMIN_PASSWORD: "adm-pass",
    GROQ_API_KEY: "sk-groq-test",
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

function playgroundReq(
  body: Record<string, unknown>,
  cookie: string,
): Request {
  return new Request("https://gw.test/admin/api/playground", {
    method: "POST",
    headers: { "content-type": "application/json", cookie: `admin_session=${cookie}` },
    body: JSON.stringify(body),
  });
}

describe("POST /admin/api/playground", () => {
  it("forwards with the provider key (no GATEWAY_KEY needed), rewrites model, passes response through", async () => {
    const fetchMock = vi.fn(async () => new Response('{"choices":[]}', { status: 200 }));
    vi.stubGlobal("fetch", fetchMock);
    const env = envWith({ DB: stubDb().db });
    const res = await gateway.fetch(
      playgroundReq(
        { model: "groq/llama-3.3-70b", messages: [{ role: "user", content: "hi" }], stream: false },
        await adminCookie(env),
      ),
      env,
      ctx,
    );
    expect(res.status).toBe(200);
    expect(await res.text()).toBe('{"choices":[]}');
    const [url, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe("https://api.groq.com/openai/v1/chat/completions");
    expect(JSON.parse(init.body as string).model).toBe("llama-3.3-70b");
    expect((init.headers as Record<string, string>).authorization).toBe("Bearer sk-groq-test");
  });

  it("stream:true → SSE passthrough", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => new Response("data: {\"delta\":\"a\"}\n\ndata: [DONE]\n\n", {
        status: 200,
        headers: { "content-type": "text/event-stream" },
      })),
    );
    const env = envWith({ DB: stubDb().db });
    const res = await gateway.fetch(
      playgroundReq(
        { model: "groq/llama-3.3-70b", messages: [], stream: true },
        await adminCookie(env),
      ),
      env,
      ctx,
    );
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toBe("text/event-stream");
    expect(await res.text()).toContain("data: [DONE]");
  });

  it("without admin cookie → 401 (gateway key present or absent)", async () => {
    const fetchMock = vi.fn(async () => new Response("{}", { status: 200 }));
    vi.stubGlobal("fetch", fetchMock);
    const noKey = envWith();
    const res1 = await gateway.fetch(
      new Request("https://gw.test/admin/api/playground", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ model: "groq/m", messages: [] }),
      }),
      noKey,
      ctx,
    );
    expect(res1.status).toBe(401);
    const withKey = envWith({ GATEWAY_KEY: "gwk-test" });
    const res2 = await gateway.fetch(
      new Request("https://gw.test/admin/api/playground", {
        method: "POST",
        headers: {
          "content-type": "application/json",
          authorization: "Bearer gwk-test",
        },
        body: JSON.stringify({ model: "groq/m", messages: [] }),
      }),
      withKey,
      ctx,
    );
    expect(res2.status).toBe(401);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("playground requests are logged to request_logs", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => new Response("{}", { status: 200 })));
    const { db, logRows } = stubDb();
    const env = envWith({ DB: db });
    await gateway.fetch(
      playgroundReq(
        { model: "groq/llama-3.3-70b", messages: [], stream: false },
        await adminCookie(env),
      ),
      env,
      ctx,
    );
    await Promise.all(captured);
    const inserts = logRows.filter((r) => r.sql.includes("INSERT INTO request_logs"));
    expect(inserts).toHaveLength(1);
    const params = inserts[0].params as unknown[];
    expect(params[1]).toBe("groq");
    expect(params[3]).toBe(200);
    expect(params[6]).toBeNull();
    expect(params[7]).toBeNull();
  });
});
