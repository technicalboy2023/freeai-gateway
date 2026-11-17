import { afterEach, describe, expect, it, vi } from "vitest";
import { handleMessages } from "../src/messages";
import type { Env } from "../src/env";

const env = { GATEWAY_KEY: "gwk", ANTHROPIC_API_KEY: "ak-key" } as Env;

function messagesRequest(model: string, e: Env): Promise<Response> {
  const req = new Request("https://gw.test/v1/messages", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      model,
      max_tokens: 100,
      messages: [{ role: "user", content: "hi" }],
    }),
  });
  return handleMessages(req, e);
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("POST /v1/messages (Anthropic wire)", () => {
  it("forwards to anthropic /v1/messages with x-api-key + anthropic-version", async () => {
    const fetchMock = vi.fn(
      async () => new Response(JSON.stringify({ content: [] }), { status: 200 }),
    );
    vi.stubGlobal("fetch", fetchMock);

    const res = await messagesRequest("claude-sonnet-4", env);

    expect(res.status).toBe(200);
    expect(fetchMock).toHaveBeenCalledOnce();
    const calls = fetchMock.mock.calls as unknown as [string, RequestInit][];
    const [url, init] = calls[0];
    expect(url).toBe("https://api.anthropic.com/v1/messages");
    const headers = init.headers as Record<string, string>;
    expect(headers["x-api-key"]).toBe("ak-key");
    expect(headers["anthropic-version"]).toBe("2023-06-01");
    expect(headers.authorization).toBeUndefined();
    const sent = JSON.parse(init.body as string) as { model: string };
    expect(sent.model).toBe("claude-sonnet-4");
  });

  it("accepts anthropic/-prefixed model ids and strips the prefix", async () => {
    const fetchMock = vi.fn(
      async () => new Response("{}", { status: 200 }),
    );
    vi.stubGlobal("fetch", fetchMock);
    await messagesRequest("anthropic/claude-sonnet-4", env);
    const calls = fetchMock.mock.calls as unknown as [string, RequestInit][];
    const sent = JSON.parse(calls[0][1].body as string) as { model: string };
    expect(sent.model).toBe("claude-sonnet-4");
  });

  it("returns 400 json naming ANTHROPIC_API_KEY when secret missing", async () => {
    const res = await messagesRequest("claude-sonnet-4", { GATEWAY_KEY: "gwk" } as Env);
    expect(res.status).toBe(400);
    const body = (await res.json()) as { error: { message: string } };
    expect(body.error.message).toContain("ANTHROPIC_API_KEY");
  });

  it("passes upstream errors through untouched", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => new Response("overloaded", { status: 529 })),
    );
    const res = await messagesRequest("claude-sonnet-4", env);
    expect(res.status).toBe(529);
    expect(await res.text()).toBe("overloaded");
  });

  it("returns SSE stream passthrough for stream:true", async () => {
    const stream = new ReadableStream({
      start(controller) {
        controller.enqueue(new TextEncoder().encode("event: content_block_delta\n"));
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
    const res = await messagesRequest("claude-sonnet-4", env);
    expect(res.headers.get("content-type")).toBe("text/event-stream");
    expect(res.body).toBeInstanceOf(ReadableStream);
  });
});
