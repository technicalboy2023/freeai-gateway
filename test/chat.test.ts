import { afterEach, describe, expect, it, vi } from "vitest";
import worker from "../src/index";
import { handleChat } from "../src/chat";
import type { Env } from "../src/env";

const baseEnv = {
  GATEWAY_KEY: "gwk",
  GROQ_API_KEY: "groqkey",
  ANTHROPIC_API_KEY: "ak-key",
} as Env;

function chatRequest(model: string, env: Env): Promise<Response> {
  const req = new Request("https://gw.test/v1/chat/completions", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ model, messages: [{ role: "user", content: "hi" }] }),
  });
  return handleChat(req, env);
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("error hardening (final review fixes)", () => {
  const ctx = {} as unknown as ExecutionContext;

  it("returns 502 json when provider is unreachable (direct call)", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => {
        throw new Error("dns failure");
      }),
    );
    const res = await chatRequest("groq/llama-3.3-70b", baseEnv);
    expect(res.status).toBe(502);
    const body = (await res.json()) as { error: { message: string } };
    expect(body.error.message).toContain("groq");
  });

  it("route-level chat: 502 json with CORS on provider outage", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => {
        throw new Error("tls failure");
      }),
    );
    const req = new Request("https://gw.test/v1/chat/completions", {
      method: "POST",
      headers: { authorization: "Bearer gwk", "content-type": "application/json" },
      body: JSON.stringify({ model: "groq/m1", messages: [] }),
    });
    const res = await worker.fetch(req, baseEnv, ctx);
    expect(res.status).toBe(502);
    expect(res.headers.get("access-control-allow-origin")).toBe("*");
    expect(((await res.json()) as { error: unknown }).error).toBeTruthy();
  });

  it("route-level messages: 502 json with CORS on provider outage", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => {
        throw new Error("dns failure");
      }),
    );
    const req = new Request("https://gw.test/v1/messages", {
      method: "POST",
      headers: { authorization: "Bearer gwk", "content-type": "application/json" },
      body: JSON.stringify({ model: "claude-sonnet-4", messages: [], max_tokens: 1 }),
    });
    const res = await worker.fetch(req, baseEnv, ctx);
    expect(res.status).toBe(502);
    expect(res.headers.get("access-control-allow-origin")).toBe("*");
  });

  it("forwards anthropic-beta header and blocks spoofed x-api-key", async () => {
    const fetchMock = vi.fn(async () => new Response("{}", { status: 200 }));
    vi.stubGlobal("fetch", fetchMock);
    const req = new Request("https://gw.test/v1/messages", {
      method: "POST",
      headers: {
        authorization: "Bearer gwk",
        "content-type": "application/json",
        "anthropic-beta": "prompt-caching-2024-07-31",
        "x-api-key": "spoofed",
      },
      body: JSON.stringify({ model: "claude-sonnet-4", messages: [], max_tokens: 1 }),
    });
    await worker.fetch(req, baseEnv, ctx);
    const calls = fetchMock.mock.calls as unknown as [string, RequestInit][];
    const headers = calls[0][1].headers as Record<string, string>;
    expect(headers["anthropic-beta"]).toBe("prompt-caching-2024-07-31");
    expect(headers["x-api-key"]).toBe("ak-key");
  });

  it("chain prefix that is also a real provider resolves as the provider", async () => {
    const fetchMock = vi.fn(async () => new Response("{}", { status: 200 }));
    vi.stubGlobal("fetch", fetchMock);
    const e = {
      GATEWAY_KEY: "gwk",
      OPENAI_API_KEY: "oai",
      FALLBACK_CHAINS: JSON.stringify({ openai: ["groq"] }),
    } as unknown as Env;
    const req = new Request("https://gw.test/v1/chat/completions", {
      method: "POST",
      headers: { authorization: "Bearer gwk", "content-type": "application/json" },
      body: JSON.stringify({ model: "openai/gpt-4o", messages: [] }),
    });
    const res = await worker.fetch(req, e, ctx);
    expect(res.status).toBe(200);
    const calls = fetchMock.mock.calls as unknown as [string][];
    expect(calls[0][0]).toContain("api.openai.com");
  });
});

describe("POST /v1/chat/completions", () => {
  it("forwards to provider baseURL with bearer key and prefix-stripped model", async () => {
    const fetchMock = vi.fn(
      async () =>
        new Response(JSON.stringify({ choices: [] }), {
          status: 200,
          headers: { "content-type": "application/json" },
        }),
    );
    vi.stubGlobal("fetch", fetchMock);

    const res = await chatRequest("groq/llama-3.3-70b", baseEnv);

    expect(res.status).toBe(200);
    expect(fetchMock).toHaveBeenCalledOnce();
    const calls = fetchMock.mock.calls as unknown as [string, RequestInit][];
    const [url, init] = calls[0];
    expect(url).toBe("https://api.groq.com/openai/v1/chat/completions");
    expect((init.headers as Record<string, string>)["authorization"]).toBe("Bearer groqkey");
    const sent = JSON.parse(init.body as string) as { model: string };
    expect(sent.model).toBe("llama-3.3-70b");
  });

  it("returns 400 json naming the secret when provider key is missing", async () => {
    const res = await chatRequest("groq/llama-3.3-70b", { GATEWAY_KEY: "gwk" } as Env);
    expect(res.status).toBe(400);
    const body = (await res.json()) as { error: { message: string } };
    expect(body.error.message).toContain("GROQ_API_KEY");
  });

  it("passes upstream 4xx/5xx status and body through untouched", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => new Response("upstream oops", { status: 429 })),
    );
    const res = await chatRequest("groq/llama-3.3-70b", baseEnv);
    expect(res.status).toBe(429);
    expect(await res.text()).toBe("upstream oops");
  });

  it("returns SSE stream responses as-is (headers + ReadableStream body)", async () => {
    const stream = new ReadableStream({
      start(controller) {
        controller.enqueue(new TextEncoder().encode("data: {\"delta\":\"hi\"}\n\n"));
        controller.close();
      },
    });
    vi.stubGlobal(
      "fetch",
      vi.fn(
        async () =>
          new Response(stream, {
            status: 200,
            headers: { "content-type": "text/event-stream" },
          }),
      ),
    );
    const res = await chatRequest("groq/llama-3.3-70b", baseEnv);
    expect(res.headers.get("content-type")).toBe("text/event-stream");
    expect(res.body).toBeInstanceOf(ReadableStream);
    expect((await res.text()).startsWith("data: ")).toBe(true);
  });

  it("returns 404 json for unknown provider prefix", async () => {
    const res = await chatRequest("foo/bar", baseEnv);
    expect(res.status).toBe(404);
    const body = (await res.json()) as { error: { message: string } };
    expect(body.error.message).toContain("foo");
  });

  it("returns 400 on malformed json body", async () => {
    const req = new Request("https://gw.test/v1/chat/completions", {
      method: "POST",
      body: "not json",
    });
    const res = await handleChat(req, baseEnv);
    expect(res.status).toBe(400);
  });

  it("full route through worker fetch with gateway auth", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => new Response("{}", { status: 200 })));
    const req = new Request("https://gw.test/v1/chat/completions", {
      method: "POST",
      headers: { authorization: "Bearer gwk", "content-type": "application/json" },
      body: JSON.stringify({ model: "groq/m1", messages: [] }),
    });
    const res = await worker.fetch(req, baseEnv, {} as unknown as ExecutionContext);
    expect(res.status).toBe(200);
  });
});
