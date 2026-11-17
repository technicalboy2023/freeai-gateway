import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { getAdapter } from "../src/oauth/engine";
import type { RawTokens } from "../src/oauth/types";

let fetchMock: ReturnType<typeof vi.fn>;

beforeEach(() => {
  fetchMock = vi.fn();
  vi.stubGlobal("fetch", fetchMock);
});

afterEach(() => {
  vi.unstubAllGlobals();
});

function jsonResponse(payload: unknown, status = 200): Response {
  return new Response(JSON.stringify(payload), {
    status,
    headers: { "content-type": "application/json" },
  });
}

describe("codebuddy registration", () => {
  it("cn: CLI platform on copilot.tencent.com with the captured UA pin", () => {
    const cn = getAdapter("codebuddy-cn");
    expect(cn).not.toBeNull();
    expect(cn?.flowMode).toBe("device");
    expect(cn?.config.stateUrl).toBe("https://copilot.tencent.com/v2/plugin/auth/state");
    expect(cn?.config.tokenUrl).toBe("https://copilot.tencent.com/v2/plugin/auth/token");
    expect(cn?.config.platform).toBe("CLI");
    expect(cn?.config.domain).toBe("copilot.tencent.com");
    expect(cn?.config.userAgent).toBe("CLI/2.108.1 CodeBuddy/2.108.1");
  });

  it("intl: ide platform on www.codebuddy.ai with the captured UA pin", () => {
    const intl = getAdapter("codebuddy-intl");
    expect(intl).not.toBeNull();
    expect(intl?.flowMode).toBe("device");
    expect(intl?.config.stateUrl).toBe("https://www.codebuddy.ai/v2/plugin/auth/state");
    expect(intl?.config.tokenUrl).toBe("https://www.codebuddy.ai/v2/plugin/auth/token");
    expect(intl?.config.platform).toBe("ide");
    expect(intl?.config.domain).toBe("www.codebuddy.ai");
    expect(intl?.config.userAgent).toBe("IDE/2.108.1 CodeBuddy/2.108.1");
  });
});

describe("requestDeviceCode", () => {
  it("cn: POSTs stateUrl?platform=CLI with the full header set", async () => {
    const cn = getAdapter("codebuddy-cn")!;
    fetchMock.mockResolvedValueOnce(
      jsonResponse({ code: 0, data: { state: "s1", authUrl: "https://auth.cn/x" } }),
    );
    const d = await cn.requestDeviceCode!(cn.config);
    expect(d).toEqual({
      device_code: "s1",
      user_code: "s1",
      verification_uri: "https://auth.cn/x",
      verification_uri_complete: "https://auth.cn/x",
      expires_in: 600,
      interval: 5,
    });
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("https://copilot.tencent.com/v2/plugin/auth/state?platform=CLI");
    expect(init.method).toBe("POST");
    const h = init.headers as Record<string, string>;
    expect(h["content-type"]).toBe("application/json");
    expect(h["accept"]).toBe("application/json");
    expect(h["user-agent"]).toBe("CLI/2.108.1 CodeBuddy/2.108.1");
    expect(h["x-requested-with"]).toBe("XMLHttpRequest");
    expect(h["x-domain"]).toBe("copilot.tencent.com");
    expect(h["x-no-authorization"]).toBe("true");
    expect(h["x-no-user-id"]).toBe("true");
    expect(h["x-product"]).toBe("SaaS");
    expect(JSON.parse(String(init.body))).toEqual({ platform: "CLI" });
  });

  it("intl: platform=ide, data.url variant accepted", async () => {
    const intl = getAdapter("codebuddy-intl")!;
    fetchMock.mockResolvedValueOnce(
      jsonResponse({ code: 0, data: { state: "s2", url: "https://auth.intl/x" } }),
    );
    const d = await intl.requestDeviceCode!(intl.config);
    expect(d.device_code).toBe("s2");
    expect(d.verification_uri).toBe("https://auth.intl/x");
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("https://www.codebuddy.ai/v2/plugin/auth/state?platform=ide");
    const h = init.headers as Record<string, string>;
    expect(h["user-agent"]).toBe("IDE/2.108.1 CodeBuddy/2.108.1");
    expect(h["x-domain"]).toBe("www.codebuddy.ai");
    expect(JSON.parse(String(init.body))).toEqual({ platform: "ide" });
  });

  it("!ok → 'CodeBuddy state request failed (<status>)'", async () => {
    const cn = getAdapter("codebuddy-cn")!;
    fetchMock.mockResolvedValueOnce(new Response("no", { status: 502 }));
    await expect(cn.requestDeviceCode!(cn.config)).rejects.toThrow("CodeBuddy state request failed (502)");
  });

  it("bad envelope → 'CodeBuddy state error: <msg | no state in response>'", async () => {
    const cn = getAdapter("codebuddy-cn")!;
    fetchMock.mockResolvedValueOnce(jsonResponse({ code: 1, msg: "quota exceeded" }));
    await expect(cn.requestDeviceCode!(cn.config)).rejects.toThrow("CodeBuddy state error: quota exceeded");
    fetchMock.mockResolvedValueOnce(jsonResponse({ code: 0, data: {} }));
    await expect(cn.requestDeviceCode!(cn.config)).rejects.toThrow("CodeBuddy state error: no state in response");
  });
});

describe("pollToken", () => {
  it("success envelope → tokens with defaults (refresh '', tokenType Bearer)", async () => {
    const cn = getAdapter("codebuddy-cn")!;
    fetchMock.mockResolvedValueOnce(
      jsonResponse({ code: 0, data: { accessToken: "cb-at", refreshToken: "cb-rt", tokenType: "Bearer", expiresIn: 3600 } }),
    );
    const r = await cn.pollToken!(cn.config, "s1");
    expect(r).toEqual({
      ok: true,
      data: { access_token: "cb-at", refresh_token: "cb-rt", token_type: "Bearer", expires_in: 3600 },
    });
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("https://copilot.tencent.com/v2/plugin/auth/token?state=s1");
    expect(init.method).toBe("GET");
    const h = init.headers as Record<string, string>;
    expect(h["x-no-enterprise-id"]).toBe("true");
    expect(h["x-no-department-info"]).toBe("true");
    expect(h["user-agent"]).toBe("CLI/2.108.1 CodeBuddy/2.108.1");
  });

  it("minimal envelope → refresh_token '' and expires_in undefined", async () => {
    const cn = getAdapter("codebuddy-cn")!;
    fetchMock.mockResolvedValueOnce(jsonResponse({ code: 0, data: { accessToken: "only" } }));
    const r = await cn.pollToken!(cn.config, "s1");
    expect(r.ok).toBe(true);
    expect(r.data.access_token).toBe("only");
    expect(r.data.refresh_token).toBe("");
    expect(r.data.token_type).toBe("Bearer");
    expect(r.data.expires_in).toBeUndefined();
  });

  it("non-zero code → {ok:false, data:{code, msg}} (engine deletes pending)", async () => {
    const cn = getAdapter("codebuddy-cn")!;
    fetchMock.mockResolvedValueOnce(jsonResponse({ code: 1, msg: "state expired" }));
    const r = await cn.pollToken!(cn.config, "s1");
    expect(r).toEqual({ ok: false, data: { code: 1, msg: "state expired" } });
  });

  it("!ok → request_failed", async () => {
    const intl = getAdapter("codebuddy-intl")!;
    fetchMock.mockResolvedValueOnce(new Response(null, { status: 500 }));
    const r = await intl.pollToken!(intl.config, "s2");
    expect(r).toEqual({ ok: false, data: { error: "request_failed" } });
  });
});

describe("mapTokens", () => {
  it("access/refresh pass through; expiresIn default 86400", () => {
    const cn = getAdapter("codebuddy-cn")!;
    const mapped = cn.mapTokens({ access_token: "a", refresh_token: "r", expires_in: 7200 } as RawTokens);
    expect(mapped.accessToken).toBe("a");
    expect(mapped.refreshToken).toBe("r");
    expect(mapped.expiresIn).toBe(7200);
    const minimal = cn.mapTokens({ access_token: "a" } as RawTokens);
    expect(minimal.expiresIn).toBe(86400);
    expect(minimal.refreshToken).toBeNull();
  });
});
