import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { getAdapter } from "../src/oauth/engine";
import type { RawTokens } from "../src/oauth/types";

const REDIRECT = "https://gw.test/admin";

function embeddedCode(obj: unknown, uriEncode = false): string {
  const b64 = btoa(JSON.stringify(obj));
  return uriEncode ? encodeURIComponent(b64) : b64;
}

const TOKEN_DATA = {
  accessToken: "at",
  refreshToken: "rt",
  email: "e@x.com",
  firstName: "A",
  lastName: "B",
  expiresAt: "2030-01-01T00:00:00Z",
};

let fetchMock: ReturnType<typeof vi.fn>;

beforeEach(() => {
  fetchMock = vi.fn();
  vi.stubGlobal("fetch", fetchMock);
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("cline adapter registration", () => {
  it("is registered as paste-code with the recon endpoints", () => {
    const cline = getAdapter("cline");
    expect(cline).not.toBeNull();
    expect(cline?.flowMode).toBe("paste-code");
    expect(cline?.config.authorizeUrl).toBe("https://api.cline.bot/api/v1/auth/authorize");
    expect(cline?.config.tokenExchangeUrl).toBe("https://api.cline.bot/api/v1/auth/token");
    expect(cline?.config.refreshUrl).toBe("https://api.cline.bot/api/v1/auth/refresh");
  });
});

describe("buildAuthUrl", () => {
  it("client_type=extension + callback_url/redirect_uri, no state/challenge", () => {
    const cline = getAdapter("cline");
    if (!cline?.buildAuthUrl) return;
    const url = cline.buildAuthUrl(cline.config, REDIRECT, "state-x", "challenge-x");
    expect(url.startsWith("https://api.cline.bot/api/v1/auth/authorize?")).toBe(true);
    const params = new URL(url).searchParams;
    expect(params.get("client_type")).toBe("extension");
    expect(params.get("callback_url")).toBe(REDIRECT);
    expect(params.get("redirect_uri")).toBe(REDIRECT);
    expect(params.get("state")).toBeNull();
    expect(params.get("challenge")).toBeNull();
  });
});

describe("exchangeToken — embedded path", () => {
  it("decodes plain base64 through the last } without any fetch", async () => {
    const cline = getAdapter("cline");
    if (!cline?.exchangeToken) return;
    const raw = await cline.exchangeToken(cline.config, embeddedCode(TOKEN_DATA), REDIRECT, "v", "s");
    expect(raw).toEqual({
      access_token: "at",
      refresh_token: "rt",
      email: "e@x.com",
      firstName: "A",
      lastName: "B",
      expires_at: "2030-01-01T00:00:00Z",
    });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("decodes the URI-encoded variant too", async () => {
    const cline = getAdapter("cline");
    if (!cline?.exchangeToken) return;
    const raw = await cline.exchangeToken(cline.config, embeddedCode(TOKEN_DATA, true), REDIRECT, "v", "s");
    expect(raw.access_token).toBe("at");
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("trailing junk after the JSON object is tolerated", async () => {
    const cline = getAdapter("cline");
    if (!cline?.exchangeToken) return;
    // Junk lives in the DECODED stream (base64 input stays clean) — decode
    // cuts through the last "}".
    const junkTail = btoa(JSON.stringify(TOKEN_DATA) + " trailing-plain-bytes");
    const raw = await cline.exchangeToken(cline.config, junkTail, REDIRECT, "v", "s");
    expect(raw.access_token).toBe("at");
  });
});

describe("exchangeToken — fallback POST", () => {
  it("garbage code POSTs tokenExchangeUrl with the exact body; nested data shape", async () => {
    const cline = getAdapter("cline");
    if (!cline?.exchangeToken) return;
    fetchMock.mockResolvedValueOnce(
      new Response(
        JSON.stringify({
          data: { accessToken: "at2", refreshToken: "rt2", userInfo: { email: "n@x.com" }, expiresAt: "2030-01-01T00:00:00Z" },
        }),
        { status: 200, headers: { "content-type": "application/json" } },
      ),
    );
    const raw = await cline.exchangeToken(cline.config, "%%%garbage%%%", REDIRECT, "v", "s");
    expect(raw.access_token).toBe("at2");
    expect(raw.refresh_token).toBe("rt2");
    expect(raw.email).toBe("n@x.com");
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("https://api.cline.bot/api/v1/auth/token");
    expect(init.method).toBe("POST");
    expect((init.headers as Record<string, string>)["content-type"]).toBe("application/json");
    expect(JSON.parse(String(init.body))).toEqual({
      grant_type: "authorization_code",
      code: "%%%garbage%%%",
      client_type: "extension",
      redirect_uri: REDIRECT,
    });
  });

  it("flat data shape works", async () => {
    const cline = getAdapter("cline");
    if (!cline?.exchangeToken) return;
    fetchMock.mockResolvedValueOnce(
      new Response(JSON.stringify({ accessToken: "flat-at", refreshToken: "flat-rt" }), { status: 200 }),
    );
    const raw = await cline.exchangeToken(cline.config, "%%%garbage%%%", REDIRECT, "v", "s");
    expect(raw.access_token).toBe("flat-at");
    expect(raw.refresh_token).toBe("flat-rt");
  });

  it("!ok → throws with the response text", async () => {
    const cline = getAdapter("cline");
    if (!cline?.exchangeToken) return;
    fetchMock.mockResolvedValueOnce(new Response("forbidden-by-proxy", { status: 403 }));
    await expect(cline.exchangeToken(cline.config, "%%%garbage%%%", REDIRECT, "v", "s")).rejects.toThrow(
      "Cline token exchange failed: forbidden-by-proxy",
    );
  });
});

describe("cline mapTokens", () => {
  const cline = getAdapter("cline");

  it("name from first+last; expiresIn derived from expires_at; meta kept", () => {
    if (!cline) return;
    const mapped = cline.mapTokens({
      access_token: "at",
      refresh_token: "rt",
      email: "e@x.com",
      firstName: "A",
      lastName: "B",
      expires_at: "2030-01-01T00:00:00Z",
    } as RawTokens);
    expect(mapped.accessToken).toBe("at");
    expect(mapped.refreshToken).toBe("rt");
    expect(mapped.name).toBe("A B");
    expect(mapped.email).toBe("e@x.com");
    expect(mapped.meta).toEqual({ firstName: "A", lastName: "B" });
    expect(typeof mapped.expiresIn).toBe("number");
    expect(mapped.expiresIn!).toBeGreaterThan(90_000_000); // 2030 is >3y out
  });

  it("no name parts → falls back to email; no expires_at → 3600", () => {
    if (!cline) return;
    const mapped = cline.mapTokens({ access_token: "x", email: "solo@x.com" });
    expect(mapped.name).toBe("solo@x.com");
    expect(mapped.expiresIn).toBe(3600);
    expect(mapped.meta).toEqual({ firstName: "", lastName: "" });
  });

  it("unparsable expires_at → 3600 fallback, not NaN", () => {
    if (!cline) return;
    const mapped = cline.mapTokens({ access_token: "x", expires_at: "not-a-date" });
    expect(mapped.expiresIn).toBe(3600);
  });
});
