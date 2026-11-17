import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { getAdapter } from "../src/oauth/engine";
import { fromBase64Url, toBase64Url } from "../src/oauth/providers/freebuff";
import type { PollResult, RawTokens } from "../src/oauth/types";

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

/* ------------------------------ kilocode ------------------------------ */

describe("kilocode registration", () => {
  it("is a device adapter on api.kilo.ai", () => {
    const k = getAdapter("kilocode");
    expect(k).not.toBeNull();
    expect(k?.flowMode).toBe("device");
    expect(k?.config.initiateUrl).toBe("https://api.kilo.ai/api/device-auth/codes");
    expect(k?.config.pollUrlBase).toBe("https://api.kilo.ai/api/device-auth/codes");
  });
});

describe("kilocode requestDeviceCode", () => {
  const k = () => getAdapter("kilocode")!;

  it("POSTs initiateUrl and maps the envelope (interval 3)", async () => {
    fetchMock.mockResolvedValueOnce(
      jsonResponse({ data: { code: "kilo-1", link: "https://kilo.ai/verify", expiresIn: 600 } }),
    );
    const d = await k().requestDeviceCode!(k().config);
    expect(d).toEqual({
      device_code: "kilo-1",
      user_code: "kilo-1",
      verification_uri: "https://kilo.ai/verify",
      verification_uri_complete: "https://kilo.ai/verify",
      expires_in: 600,
      interval: 3,
    });
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("https://api.kilo.ai/api/device-auth/codes");
    expect(init.method).toBe("POST");
    expect((init.headers as Record<string, string>)["content-type"]).toBe("application/json");
  });

  it("missing expiresIn → default 300", async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse({ data: { code: "c", link: "https://v" } }));
    const d = await k().requestDeviceCode!(k().config);
    expect(d.expires_in).toBe(300);
  });

  it("429 → exact throttle message", async () => {
    fetchMock.mockResolvedValueOnce(new Response("no", { status: 429 }));
    await expect(k().requestDeviceCode!(k().config)).rejects.toThrow(
      "Too many pending authorization requests. Please try again later.",
    );
  });

  it("other !ok → 'Device auth initiation failed: <text>'", async () => {
    fetchMock.mockResolvedValueOnce(new Response("boom", { status: 500 }));
    await expect(k().requestDeviceCode!(k().config)).rejects.toThrow("Device auth initiation failed: boom");
  });
});

describe("kilocode pollToken", () => {
  const k = () => getAdapter("kilocode")!;

  it("202 → authorization_pending", async () => {
    fetchMock.mockResolvedValueOnce(new Response(null, { status: 202 }));
    const r = await k().pollToken!(k().config, "dc-1");
    expect(r).toEqual({ ok: false, data: { error: "authorization_pending" } });
    expect((fetchMock.mock.calls[0] as [string])[0]).toBe("https://api.kilo.ai/api/device-auth/codes/dc-1");
  });

  it("403 → access_denied terminal", async () => {
    fetchMock.mockResolvedValueOnce(new Response(null, { status: 403 }));
    const r = await k().pollToken!(k().config, "dc-1");
    expect(r).toEqual({
      ok: false,
      data: { error: "access_denied", error_description: "Authorization denied by user" },
    });
  });

  it("410 → expired_token terminal", async () => {
    fetchMock.mockResolvedValueOnce(new Response(null, { status: 410 }));
    const r = await k().pollToken!(k().config, "dc-1");
    expect(r).toEqual({
      ok: false,
      data: { error: "expired_token", error_description: "Authorization code expired" },
    });
  });

  it("500 → poll_failed with status", async () => {
    fetchMock.mockResolvedValueOnce(new Response("oops", { status: 500 }));
    const r = await k().pollToken!(k().config, "dc-1");
    expect(r).toEqual({ ok: false, data: { error: "poll_failed", error_description: "Poll failed: 500" } });
  });

  it("approved + token → ok with access_token + _userEmail", async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse({ status: "approved", token: "k-at", userEmail: "u@x.com" }));
    const r = await k().pollToken!(k().config, "dc-1");
    expect(r).toEqual({ ok: true, data: { access_token: "k-at", _userEmail: "u@x.com" } });
  });

  it("ok without token → pending", async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse({ status: "pending" }));
    const r = await k().pollToken!(k().config, "dc-1");
    expect(r).toEqual({ ok: false, data: { error: "authorization_pending" } });
  });

  it("mapTokens: email from _userEmail, no refresh/expiry", () => {
    const mapped = k().mapTokens({ access_token: "k-at", _userEmail: "u@x.com" } as RawTokens);
    expect(mapped.accessToken).toBe("k-at");
    expect(mapped.email).toBe("u@x.com");
    expect(mapped.refreshToken).toBeNull();
    expect(mapped.expiresIn).toBeNull();
  });
});

/* ------------------------------ freebuff ------------------------------ */

describe("freebuff registration + fingerprint format", () => {
  it("is a device adapter on freebuff.com", () => {
    const f = getAdapter("freebuff");
    expect(f).not.toBeNull();
    expect(f?.flowMode).toBe("device");
    expect(f?.config.codeUrl).toBe("https://freebuff.com/api/auth/cli/code");
    expect(f?.config.statusUrl).toBe("https://freebuff.com/api/auth/cli/status");
  });
});

describe("freebuff requestDeviceCode", () => {
  const f = () => getAdapter("freebuff")!;
  const EXPIRES = "2030-01-01T00:00:00Z";

  it("POSTs {fingerprintId}; device_code round-trips; user_code strips prefix", async () => {
    fetchMock.mockResolvedValueOnce(
      jsonResponse({ loginUrl: "https://freebuff.com/l/1", fingerprintHash: "fh-1", expiresAt: EXPIRES }),
    );
    const d = await f().requestDeviceCode!(f().config);
    const state = JSON.parse(fromBase64Url(d.device_code)) as Record<string, unknown>;
    expect(state.fingerprintId).toMatch(/^codebuff-cli-[A-Za-z0-9_-]{8}$/);
    expect(state.fingerprintHash).toBe("fh-1");
    expect(state.expiresAt).toBe(EXPIRES);
    expect(d.user_code).toBe(String(state.fingerprintId).slice("codebuff-cli-".length));
    expect(d.user_code).toMatch(/^[A-Za-z0-9_-]{8}$/);
    expect(d.verification_uri).toBe("https://freebuff.com/l/1");
    expect(d.verification_uri_complete).toBe("https://freebuff.com/l/1");
    expect(d.interval).toBe(5);
    expect(d.expires_in).toBeGreaterThan(90_000_000);
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("https://freebuff.com/api/auth/cli/code");
    expect(init.method).toBe("POST");
    expect(JSON.parse(String(init.body))).toEqual({ fingerprintId: state.fingerprintId });
  });

  it("missing fields → 'missing required fields'", async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse({ loginUrl: "https://x" }));
    await expect(f().requestDeviceCode!(f().config)).rejects.toThrow(
      "Freebuff login URL response is missing required fields",
    );
    fetchMock.mockResolvedValueOnce(
      jsonResponse({ loginUrl: "https://x", fingerprintHash: "h", expiresAt: "not-a-date" }),
    );
    await expect(f().requestDeviceCode!(f().config)).rejects.toThrow(
      "Freebuff login URL response is missing required fields",
    );
  });

  it("!ok → 'Freebuff login URL request failed (<status>)'", async () => {
    fetchMock.mockResolvedValueOnce(new Response("no", { status: 500 }));
    await expect(f().requestDeviceCode!(f().config)).rejects.toThrow("Freebuff login URL request failed (500)");
  });
});

describe("freebuff pollToken", () => {
  const f = () => getAdapter("freebuff")!;

  function deviceCodeFor(state: Record<string, unknown>): string {
    return toBase64Url(btoa(JSON.stringify(state)));
  }

  const STATE = {
    fingerprintId: "codebuff-cli-abcdefgh",
    fingerprintHash: "fh-1",
    expiresAt: "2030-01-01T00:00:00Z",
  };

  it("ok + user.authToken → access_token + user fields + _fingerprintId", async () => {
    fetchMock.mockResolvedValueOnce(
      jsonResponse({ user: { authToken: "fb-at", email: "f@x.com", name: "FB User", id: "uid-1" } }),
    );
    const r: PollResult = await f().pollToken!(f().config, deviceCodeFor(STATE));
    expect(r.ok).toBe(true);
    expect(r.data).toEqual({
      access_token: "fb-at",
      _userEmail: "f@x.com",
      _userName: "FB User",
      _userId: "uid-1",
      _fingerprintId: "codebuff-cli-abcdefgh",
    });
    const [url] = fetchMock.mock.calls[0] as [string];
    const u = new URL(url);
    expect(u.origin + u.pathname).toBe("https://freebuff.com/api/auth/cli/status");
    expect(u.searchParams.get("fingerprintId")).toBe("codebuff-cli-abcdefgh");
    expect(u.searchParams.get("fingerprintHash")).toBe("fh-1");
    expect(u.searchParams.get("expiresAt")).toBe("2030-01-01T00:00:00Z");
  });

  it("ok without authToken + not expired → authorization_pending", async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse({ user: {} }));
    const r = await f().pollToken!(f().config, deviceCodeFor(STATE));
    expect(r).toEqual({ ok: false, data: { error: "authorization_pending" } });
  });

  it("ok without authToken + expired → expired_token", async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse({ user: {} }));
    const r = await f().pollToken!(f().config, deviceCodeFor({ ...STATE, expiresAt: "2020-01-01T00:00:00Z" }));
    expect(r).toEqual({ ok: false, data: { error: "expired_token", error_description: "Freebuff login expired" } });
  });

  it("429 → slow_down", async () => {
    fetchMock.mockResolvedValueOnce(new Response(null, { status: 429 }));
    const r = await f().pollToken!(f().config, deviceCodeFor(STATE));
    expect(r).toEqual({ ok: false, data: { error: "slow_down" } });
  });

  it("!ok + expired wins over slow_down", async () => {
    fetchMock.mockResolvedValueOnce(new Response(null, { status: 500 }));
    const r = await f().pollToken!(f().config, deviceCodeFor({ ...STATE, expiresAt: "2020-01-01T00:00:00Z" }));
    expect(r).toEqual({ ok: false, data: { error: "expired_token", error_description: "Freebuff login expired" } });
  });

  it("malformed device_code → invalid_request", async () => {
    expect(await f().pollToken!(f().config, "not-base64!!!")).toEqual({
      ok: false,
      data: { error: "invalid_request", error_description: "Malformed Freebuff login state" },
    });
    expect(await f().pollToken!(f().config, btoa("plain-text"))).toEqual({
      ok: false,
      data: { error: "invalid_request", error_description: "Malformed Freebuff login state" },
    });
  });

  it("mapTokens: optional keys only when present", () => {
    const full = f().mapTokens({
      access_token: "fb-at",
      _userEmail: "f@x.com",
      _userName: "FB User",
      _userId: "uid-1",
      _fingerprintId: "codebuff-cli-abcdefgh",
    } as RawTokens);
    expect(full.accessToken).toBe("fb-at");
    expect(full.email).toBe("f@x.com");
    expect(full.name).toBe("FB User");
    expect(full.refreshToken).toBeNull();
    expect(full.meta).toEqual({ userId: "uid-1", fingerprintId: "codebuff-cli-abcdefgh" });

    const minimal = f().mapTokens({ access_token: "fb-at" } as RawTokens);
    expect(minimal.email).toBeNull();
    expect(minimal.name).toBeNull();
    expect(minimal.meta).toBeUndefined();
  });
});
