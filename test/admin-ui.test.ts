import { describe, expect, it } from "vitest";
import gateway from "../src/index";
import type { Env } from "../src/env";

/** Assets binding stub mirroring Workers static assets: path → file lookup. */
function assetsStub(files: Record<string, { body: string; type: string }>) {
  return {
    fetch: async (req: Request) => {
      const { pathname } = new URL(req.url);
      const f = files[pathname];
      return f
        ? new Response(f.body, { headers: { "content-type": f.type } })
        : new Response("not found", { status: 404 });
    },
  };
}

function envWith(extra: Record<string, unknown> = {}): Env {
  return {
    ADMIN_PASSWORD: "adm-pass",
    ...extra,
  } as unknown as Env;
}

const files = {
  "/admin": { body: "<!doctype html><html><body>FreeAI Gateway</body></html>", type: "text/html; charset=utf-8" },
  "/admin/app.js": { body: "console.log('app')", type: "text/javascript" },
  "/admin/app.css": { body: "body{color:#fff}", type: "text/css" },
};

describe("/admin console assets routing", () => {
  it("GET /admin → serves index.html via the ASSETS binding", async () => {
    const env = envWith({ ASSETS: assetsStub(files) });
    const res = await gateway.fetch(
      new Request("https://gw.test/admin"),
      env,
      {} as ExecutionContext,
    );
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toContain("text/html");
    expect(await res.text()).toContain("FreeAI Gateway");
  });

  it("GET /admin/app.js → serves JS", async () => {
    const env = envWith({ ASSETS: assetsStub(files) });
    const res = await gateway.fetch(
      new Request("https://gw.test/admin/app.js"),
      env,
      {} as ExecutionContext,
    );
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toContain("text/javascript");
    expect(await res.text()).toBe("console.log('app')");
  });

  it("GET /admin/app.css → serves CSS", async () => {
    const env = envWith({ ASSETS: assetsStub(files) });
    const res = await gateway.fetch(
      new Request("https://gw.test/admin/app.css"),
      env,
      {} as ExecutionContext,
    );
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toContain("text/css");
  });

  it("missing asset → 404 passthrough from ASSETS", async () => {
    const env = envWith({ ASSETS: assetsStub(files) });
    const res = await gateway.fetch(
      new Request("https://gw.test/admin/nope.txt"),
      env,
      {} as ExecutionContext,
    );
    expect(res.status).toBe(404);
    expect(await res.text()).toBe("not found");
  });

  it("POST /admin → 404 (assets are GET-only)", async () => {
    const env = envWith({ ASSETS: assetsStub(files) });
    const res = await gateway.fetch(
      new Request("https://gw.test/admin", { method: "POST" }),
      env,
      {} as ExecutionContext,
    );
    expect(res.status).toBe(404);
    const body = (await res.json()) as { error: { message: string } };
    expect(body.error.message).toContain("GET-only");
  });

  it("ASSETS binding absent → 500 clean JSON", async () => {
    const env = envWith();
    const res = await gateway.fetch(
      new Request("https://gw.test/admin"),
      env,
      {} as ExecutionContext,
    );
    expect(res.status).toBe(500);
    const body = (await res.json()) as { error: { message: string } };
    expect(body.error.message).toContain("ASSETS");
  });

  it("/admin/api/* is NOT hijacked by asset routing (no cookie → 401)", async () => {
    const env = envWith({ ASSETS: assetsStub(files) });
    const res = await gateway.fetch(
      new Request("https://gw.test/admin/api/providers"),
      env,
      {} as ExecutionContext,
    );
    expect(res.status).toBe(401);
  });
});
