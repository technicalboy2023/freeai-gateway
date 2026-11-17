import { describe, expect, it } from "vitest";
import worker from "../src/index";
import type { Env } from "../src/env";

const env = {} as Env;
const ctx = {
  waitUntil: () => {},
  passThroughOnException: () => {},
} as unknown as ExecutionContext;

describe("health endpoint", () => {
  it("GET / returns gateway status json", async () => {
    const res = await worker.fetch(new Request("https://gw.test/"), env, ctx);
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ name: "freeai-gateway", status: "ok" });
  });
});
