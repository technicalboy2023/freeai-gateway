import { describe, expect, it } from "vitest";
import { checkAuth } from "../src/auth";
import type { Env } from "../src/env";

const env = { GATEWAY_KEY: "secret123" } as Env;

function req(auth?: string): Request {
  const headers = new Headers();
  if (auth !== undefined) headers.set("authorization", auth);
  return new Request("https://gw.test/v1/chat/completions", { headers });
}

describe("gateway bearer auth", () => {
  it("returns 401 json when no Authorization header", async () => {
    const res = await checkAuth(req(), env);
    expect(res).not.toBeNull();
    expect(res!.status).toBe(401);
    const body = (await res!.json()) as { error: { message: string } };
    expect(body.error.message).toContain("GATEWAY_KEY");
  });

  it("returns 401 json on wrong bearer key", async () => {
    const res = await checkAuth(req("Bearer wrong"), env);
    expect(res!.status).toBe(401);
    const body = (await res!.json()) as { error: { message: string } };
    expect(body.error.message).toContain("GATEWAY_KEY");
  });

  it("returns null (proceed) on correct gateway key", async () => {
    expect(await checkAuth(req("Bearer secret123"), env)).toBeNull();
  });

  it("fails closed when GATEWAY_KEY secret is not configured", async () => {
    const res = await checkAuth(req("Bearer secret123"), {} as Env);
    expect(res).not.toBeNull();
    expect(res!.status).toBe(401);
  });
});
