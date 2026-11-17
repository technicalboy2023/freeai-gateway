import { afterEach, describe, expect, it, vi } from "vitest";
import { runChain } from "../src/fallback";
import type { Env } from "../src/env";

const baseEnv = {
  GATEWAY_KEY: "gwk",
  GROQ_API_KEY: "groqkey",
  GEMINI_API_KEY: "gemkey",
  OPENROUTER_API_KEY: "okey",
  FALLBACK_CHAINS: JSON.stringify({ fast: ["groq", "gemini", "openrouter"] }),
} as unknown as Env;

function chainRequest(model: string, e: Env): Promise<Response> {
  const req = new Request("https://gw.test/v1/chat/completions", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ model, messages: [{ role: "user", content: "hi" }] }),
  });
  return runChain(req, e);
}

function sse(): Response {
  const stream = new ReadableStream({
    start(c) {
      c.enqueue(new TextEncoder().encode("data: {}\n\n"));
      c.close();
    },
  });
  return new Response(stream, {
    status: 200,
    headers: { "content-type": "text/event-stream" },
  });
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("chain config validation (final review fix)", () => {
  it("chain value that is not a string array returns clear config error", async () => {
    const e = {
      GATEWAY_KEY: "gwk",
      GROQ_API_KEY: "k",
      FALLBACK_CHAINS: JSON.stringify({ fast: "groq" }),
    } as unknown as Env;
    const res = await chainRequest("fast/any-model", e);
    expect(res.status).toBe(500);
    const body = (await res.json()) as { error: { message: string } };
    expect(body.error.message).toContain("FALLBACK_CHAINS");
    expect(body.error.message).toContain("fast");
  });

  it("malformed FALLBACK_CHAINS json returns clear config error", async () => {
    const e = { GATEWAY_KEY: "gwk", FALLBACK_CHAINS: "{oops" } as unknown as Env;
    const res = await chainRequest("fast/any-model", e);
    expect(res.status).toBe(500);
    const body = (await res.json()) as { error: { message: string } };
    expect(body.error.message).toContain("FALLBACK_CHAINS");
  });
});

describe("fallback chains", () => {
  it("tries next provider on 429 and returns the successful one", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(new Response("rate limited", { status: 429 }))
      .mockResolvedValueOnce(new Response(JSON.stringify({ ok: true }), { status: 200 }));
    vi.stubGlobal("fetch", fetchMock);

    const res = await chainRequest("fast/any-model", baseEnv);

    expect(res.status).toBe(200);
    expect(JSON.stringify(await res.json())).toContain("ok");
    const calls = fetchMock.mock.calls as unknown as [string][];
    expect(calls[0][0]).toContain("https://api.groq.com/openai/v1");
    expect(calls[1][0]).toContain("https://generativelanguage.googleapis.com/v1beta/openai");
  });

  it("tries next provider on 5xx too", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(new Response("boom", { status: 503 }))
      .mockResolvedValueOnce(new Response("{}", { status: 200 }));
    vi.stubGlobal("fetch", fetchMock);
    const res = await chainRequest("fast/any-model", baseEnv);
    expect(res.status).toBe(200);
  });

  it("first success short-circuits (no further attempts)", async () => {
    const fetchMock = vi.fn().mockResolvedValueOnce(new Response("{}", { status: 200 }));
    vi.stubGlobal("fetch", fetchMock);
    const res = await chainRequest("fast/any-model", baseEnv);
    expect(res.status).toBe(200);
    expect(fetchMock).toHaveBeenCalledOnce();
  });

  it("returns 502 json listing every failed attempt when all providers fail", async () => {
    const fetchMock = vi.fn(async () => new Response("err", { status: 500 }));
    vi.stubGlobal("fetch", fetchMock);

    const res = await chainRequest("fast/any-model", baseEnv);

    expect(res.status).toBe(502);
    const body = (await res.json()) as { error: { message: string; attempts: unknown[] } };
    expect(body.error.attempts).toHaveLength(3);
    const serialized = JSON.stringify(body.error.attempts);
    expect(serialized).toContain("groq");
    expect(serialized).toContain("gemini");
    expect(serialized).toContain("openrouter");
  });

  it("returns SSE passthrough from whichever provider succeeds", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(new Response("rate limited", { status: 429 }))
      .mockResolvedValueOnce(sse());
    vi.stubGlobal("fetch", fetchMock);
    const res = await chainRequest("fast/any-model", baseEnv);
    expect(res.headers.get("content-type")).toBe("text/event-stream");
    expect(res.body).toBeInstanceOf(ReadableStream);
  });

  it("skips providers with missing keys and continues the chain", async () => {
    const e = {
      GATEWAY_KEY: "gwk",
      GEMINI_API_KEY: "gemkey",
      FALLBACK_CHAINS: JSON.stringify({ fast: ["groq", "gemini"] }),
    } as unknown as Env;
    const fetchMock = vi.fn(async () => new Response("{}", { status: 200 }));
    vi.stubGlobal("fetch", fetchMock);
    const res = await chainRequest("fast/any-model", e);
    expect(res.status).toBe(200);
    const calls = fetchMock.mock.calls as unknown as [string][];
    expect(calls[0][0]).toContain("generativelanguage.googleapis.com");
  });

  it("502 attempts name missing-key providers when the whole chain fails", async () => {
    const e = {
      GATEWAY_KEY: "gwk",
      FALLBACK_CHAINS: JSON.stringify({ fast: ["groq", "gemini"] }),
    } as unknown as Env;
    const res = await chainRequest("fast/any-model", e);
    expect(res.status).toBe(502);
    const body = (await res.json()) as { error: { attempts: unknown[] } };
    expect(JSON.stringify(body.error.attempts)).toContain("GROQ_API_KEY");
  });

  it("404 json for a model whose prefix is neither provider nor chain", async () => {
    const res = await chainRequest("nope/any-model", baseEnv);
    expect(res.status).toBe(404);
  });

  it("failed attempt bodies are cancelled before the next provider", async () => {
    let cancelled = false;
    const failing = (): Response => {
      const stream = new ReadableStream({
        cancel() {
          cancelled = true;
        },
        start(c) {
          c.enqueue(new TextEncoder().encode("partial"));
        },
      });
      return new Response(stream, { status: 500 });
    };
    const fetchMock = vi
      .fn()
      .mockImplementationOnce(failing)
      .mockResolvedValueOnce(new Response("{}", { status: 200 }));
    vi.stubGlobal("fetch", fetchMock);
    const res = await chainRequest("fast/any-model", baseEnv);
    expect(res.status).toBe(200);
    expect(cancelled).toBe(true);
  });
});
