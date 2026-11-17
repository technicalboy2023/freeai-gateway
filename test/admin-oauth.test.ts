import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import gateway from "../src/index";
import { handleLogin } from "../src/admin/auth";
import { complete, registerAdapter } from "../src/oauth/engine";
import type { Env } from "../src/env";
import type { OAuthAdapter, PollResult } from "../src/oauth/types";

const KEY = btoa(String.fromCharCode(...new Uint8Array(32).fill(0x41)))
  .replace(/\+/g, "-")
  .replace(/\//g, "_")
  .replace(/=+$/, "");

/**
 * Combined D1 stub: config rows (login throttle fail-open), oauth_tokens,
 * oauth_pending — same shapes as test/admin-providers + oauth-store stubs.
 */
function stubDb() {
  const config: Record<string, string> = {};
  const tokens = new Map<string, Record<string, unknown>>();
  const pending = new Map<string, Record<string, unknown>>();
  const db = {
    prepare: (sql: string) => ({
      bind: (...params: unknown[]) => ({
        first: async <T,>() => {
          if (!sql.startsWith("SELECT")) return null;
          if (sql.includes("oauth_pending")) {
            const row = pending.get(String(params[0]));
            return row ? (row as T) : null;
          }
          if (sql.includes("oauth_tokens")) {
            const row = tokens.get(String(params[0]));
            return row ? (row as T) : null;
          }
          const key = params[0] as string;
          return key in config ? ({ value: config[key] } as T) : null;
        },
        run: async () => {
          if (sql.startsWith("INSERT INTO oauth_tokens")) {
            const [provider, access, refresh, expiresAt, label, meta, authKind, connectedAt, lastRefreshAt] =
              params as [string, ...unknown[]];
            tokens.set(provider, {
              provider,
              access_token: access,
              refresh_token: refresh ?? null,
              expires_at: expiresAt ?? null,
              account_label: label ?? null,
              meta: meta ?? null,
              auth_kind: authKind,
              connected_at: connectedAt,
              last_refresh_at: lastRefreshAt ?? null,
              last_error: null,
            });
          }
          if (sql.startsWith("UPDATE oauth_tokens")) {
            const row = tokens.get(String(params[1]));
            if (row) row.last_error = params[0];
          }
          if (sql.startsWith("DELETE FROM oauth_tokens")) tokens.delete(String(params[0]));
          if (sql.startsWith("INSERT INTO oauth_pending")) {
            const [provider, mode, state, codeVerifier, deviceCode, extra, createdAt, expiresAt] =
              params as [string, ...unknown[]];
            pending.set(provider, {
              provider,
              mode,
              state: state ?? null,
              code_verifier: codeVerifier ?? null,
              device_code: deviceCode ?? null,
              extra: extra ?? null,
              created_at: createdAt,
              expires_at: expiresAt,
            });
          }
          if (sql.startsWith("DELETE FROM oauth_pending")) pending.delete(String(params[0]));
          return { success: true };
        },
      }),
    }),
  } as unknown as D1Database;
  return { db, tokens, pending };
}

const ctx = { waitUntil: () => {} } as unknown as ExecutionContext;

function envWith(extra: Record<string, unknown> = {}): Env {
  return { ADMIN_PASSWORD: "adm-pass", OAUTH_ENCRYPTION_KEY: KEY, ...extra } as unknown as Env;
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

function adminReq(path: string, init: RequestInit = {}, cookie = ""): Request {
  const headers: Record<string, string> = {
    ...((init.headers as Record<string, string>) ?? {}),
  };
  if (cookie) headers.cookie = `admin_session=${cookie}`;
  return new Request(`https://gw.test${path}`, { ...init, headers });
}

/** Mutable holder for staged device-poll outcomes. */
const devicePoll: { result: PollResult } = {
  result: { ok: false, data: { error: "authorization_pending" } },
};

function pasteAdapter(): OAuthAdapter {
  return {
    prefix: "fakeadm",
    flowMode: "paste",
    config: {},
    instructions: "Paste the admin-fake token.",
    importToken: async (raw) => {
      const t = raw.access_token;
      if (typeof t !== "string" || !t.startsWith("sk-fake-")) {
        throw new Error("Token does not look right");
      }
      return raw;
    },
    mapTokens: (t) => ({
      accessToken: String(t.access_token),
      expiresIn: 1200,
      name: "Admin Fake",
      meta: { src: "admin-test" },
    }),
  };
}

function deviceAdapter(): OAuthAdapter {
  return {
    prefix: "fakedev",
    flowMode: "device",
    config: {},
    requestDeviceCode: async () => ({
      device_code: "dc-9",
      user_code: "XY-99",
      verification_uri: "https://up.test/verify",
      expires_in: 300,
      interval: 5,
    }),
    pollToken: async () => devicePoll.result,
    mapTokens: (t) => ({ accessToken: String(t.access_token), expiresIn: 300, name: "Dev Fake" }),
  };
}

registerAdapter(pasteAdapter());
registerAdapter(deviceAdapter());

beforeEach(() => {
  devicePoll.result = { ok: false, data: { error: "authorization_pending" } };
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("401 gate", () => {
  it("all six oauth endpoints require the admin cookie", async () => {
    const env = envWith({ DB: stubDb().db });
    const reqs: Array<Request> = [
      adminReq("/admin/api/oauth"),
      adminReq("/admin/api/oauth/fakeadm/start", { method: "POST" }),
      adminReq("/admin/api/oauth/fakeadm/complete", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ token: "sk-fake-x" }),
      }),
      adminReq("/admin/api/oauth/fakedev/poll"),
      adminReq("/admin/api/oauth/fakeadm/status"),
      adminReq("/admin/api/oauth/fakeadm", { method: "DELETE" }),
    ];
    for (const req of reqs) {
      const res = await gateway.fetch(req, env, ctx);
      expect(res.status).toBe(401);
      expect(((await res.json()) as { error: { message: string } }).error.message).toBe("Unauthorized");
    }
  });
});

describe("GET /admin/api/oauth", () => {
  it("lists adapters with connection state; never secret material", async () => {
    const { db } = stubDb();
    const env = envWith({ DB: db });
    await complete(env, "fakeadm", { token: "sk-fake-secret-1" });
    const res = await gateway.fetch(
      adminReq("/admin/api/oauth", {}, await adminCookie(env)),
      env,
      ctx,
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as { providers: Array<Record<string, unknown>> };
    const paste = body.providers.find((p) => p.prefix === "fakeadm")!;
    expect(paste.flowMode).toBe("paste");
    expect(paste.connected).toBe(true);
    expect(paste.accountLabel).toBe("Admin Fake");
    expect(paste.instructions).toBe("Paste the admin-fake token.");
    const dev = body.providers.find((p) => p.prefix === "fakedev")!;
    expect(dev.flowMode).toBe("device");
    expect(dev.connected).toBe(false);
    expect(dev.instructions).toBeUndefined();
    const cursor = body.providers.find((p) => p.prefix === "cursor")!;
    expect(cursor.instructions).toBe(
      "Open the verification URL below and confirm the displayed code. Or connect with a Cursor token using the token-paste box.",
    );
    expect(JSON.stringify(body)).not.toContain("sk-fake-secret-1");
  });
});

describe("unknown prefix → 404", () => {
  it("start + status + disconnect name the unknown provider", async () => {
    const env = envWith({ DB: stubDb().db });
    const cookie = await adminCookie(env);
    const start = await gateway.fetch(
      adminReq("/admin/api/oauth/nope/start", { method: "POST" }, cookie),
      env,
      ctx,
    );
    expect(start.status).toBe(404);
    expect(((await start.json()) as { error: { message: string } }).error.message).toContain(
      "Unknown OAuth provider: nope",
    );
    const status = await gateway.fetch(adminReq("/admin/api/oauth/nope/status", {}, cookie), env, ctx);
    expect(status.status).toBe(404);
    const del = await gateway.fetch(adminReq("/admin/api/oauth/nope", { method: "DELETE" }, cookie), env, ctx);
    expect(del.status).toBe(404);
  });
});

describe("paste e2e through gateway.fetch", () => {
  it("login → start → complete {token} → status connected → disconnect clears", async () => {
    const { db } = stubDb();
    const env = envWith({ DB: db });
    const cookie = await adminCookie(env);

    const s = await gateway.fetch(
      adminReq("/admin/api/oauth/fakeadm/start", { method: "POST" }, cookie),
      env,
      ctx,
    );
    expect(s.status).toBe(200);
    expect(await s.json()).toEqual({ mode: "paste", instructions: "Paste the admin-fake token." });

    const c = await gateway.fetch(
      adminReq(
        "/admin/api/oauth/fakeadm/complete",
        {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ token: "sk-fake-ok" }),
        },
        cookie,
      ),
      env,
      ctx,
    );
    expect(c.status).toBe(200);
    const cb = (await c.json()) as { connected: boolean; accountLabel: string | null };
    expect(cb.connected).toBe(true);
    expect(cb.accountLabel).toBe("Admin Fake");

    const st = await gateway.fetch(adminReq("/admin/api/oauth/fakeadm/status", {}, cookie), env, ctx);
    const stb = (await st.json()) as { connected: boolean; flowMode: string; accountLabel: string | null };
    expect(stb.connected).toBe(true);
    expect(stb.flowMode).toBe("paste");
    expect(stb.accountLabel).toBe("Admin Fake");

    const d = await gateway.fetch(adminReq("/admin/api/oauth/fakeadm", { method: "DELETE" }, cookie), env, ctx);
    expect(d.status).toBe(200);
    expect(await d.json()).toEqual({ disconnected: "fakeadm" });

    const st2 = await gateway.fetch(adminReq("/admin/api/oauth/fakeadm/status", {}, cookie), env, ctx);
    expect(((await st2.json()) as { connected: boolean }).connected).toBe(false);
  });

  it("adapter importToken rejection → 400 with the adapter's message", async () => {
    const env = envWith({ DB: stubDb().db });
    const cookie = await adminCookie(env);
    const res = await gateway.fetch(
      adminReq(
        "/admin/api/oauth/fakeadm/complete",
        {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ token: "garbage" }),
        },
        cookie,
      ),
      env,
      ctx,
    );
    expect(res.status).toBe(400);
    expect(((await res.json()) as { error: { message: string } }).error.message).toContain(
      "Token does not look right",
    );
  });

  it("invalid JSON body → 400", async () => {
    const env = envWith({ DB: stubDb().db });
    const cookie = await adminCookie(env);
    const res = await gateway.fetch(
      adminReq(
        "/admin/api/oauth/fakeadm/complete",
        { method: "POST", headers: { "content-type": "application/json" }, body: "not json" },
        cookie,
      ),
      env,
      ctx,
    );
    expect(res.status).toBe(400);
    expect(((await res.json()) as { error: { message: string } }).error.message).toBe("Invalid JSON body");
  });
});

describe("device e2e through gateway.fetch", () => {
  it("start returns the verify shape; poll reports pending", async () => {
    const env = envWith({ DB: stubDb().db });
    const cookie = await adminCookie(env);
    const s = await gateway.fetch(
      adminReq("/admin/api/oauth/fakedev/start", { method: "POST" }, cookie),
      env,
      ctx,
    );
    expect(s.status).toBe(200);
    expect(await s.json()).toEqual({
      mode: "device",
      user_code: "XY-99",
      verification_uri: "https://up.test/verify",
      verification_uri_complete: "https://up.test/verify",
      expires_in: 300,
      interval: 5,
    });
    const p = await gateway.fetch(adminReq("/admin/api/oauth/fakedev/poll", {}, cookie), env, ctx);
    expect(p.status).toBe(200);
    expect(((await p.json()) as { status: string }).status).toBe("pending");
  });

  it("poll success → connected; status reflects the row", async () => {
    const { db } = stubDb();
    const env = envWith({ DB: db });
    const cookie = await adminCookie(env);
    devicePoll.result = { ok: true, data: { access_token: "dev-at" } };
    await gateway.fetch(
      adminReq("/admin/api/oauth/fakedev/start", { method: "POST" }, cookie),
      env,
      ctx,
    );
    const p = await gateway.fetch(adminReq("/admin/api/oauth/fakedev/poll", {}, cookie), env, ctx);
    expect(await p.json()).toEqual({ status: "connected" });
    const st = await gateway.fetch(adminReq("/admin/api/oauth/fakedev/status", {}, cookie), env, ctx);
    const stb = (await st.json()) as { connected: boolean; accountLabel: string | null };
    expect(stb.connected).toBe(true);
    expect(stb.accountLabel).toBe("Dev Fake");
  });
});

describe("missing OAUTH_ENCRYPTION_KEY → 503 (Review Focus #3)", () => {
  it("complete with DB present but no key → 503 with the pinned message", async () => {
    const env = envWith({ DB: stubDb().db, OAUTH_ENCRYPTION_KEY: undefined });
    const cookie = await adminCookie(env);
    const res = await gateway.fetch(
      adminReq(
        "/admin/api/oauth/fakeadm/complete",
        {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ token: "sk-fake-ok" }),
        },
        cookie,
      ),
      env,
      ctx,
    );
    expect(res.status).toBe(503);
    expect(((await res.json()) as { error: { message: string } }).error.message).toBe(
      "set OAUTH_ENCRYPTION_KEY secret first",
    );
  });
});

describe("route matching", () => {
  it("wrong method/action combos → 404 No admin route", async () => {
    const env = envWith({ DB: stubDb().db });
    const cookie = await adminCookie(env);
    const wrongs: Array<Request> = [
      adminReq("/admin/api/oauth/fakeadm/status", { method: "POST" }, cookie),
      adminReq("/admin/api/oauth/fakeadm/unknown-action", {}, cookie),
      adminReq("/admin/api/oauth/fakeadm/extra/deep", {}, cookie),
      adminReq("/admin/api/oauth", { method: "DELETE" }, cookie),
    ];
    for (const req of wrongs) {
      const res = await gateway.fetch(req, env, ctx);
      expect(res.status).toBe(404);
      expect(((await res.json()) as { error: { message: string } }).error.message).toContain("No admin route");
    }
  });

  it("no DB binding → 503, not 500 (parity with the providers toggle)", async () => {
    const env = envWith();
    const cookie = await adminCookie(env);
    const res = await gateway.fetch(adminReq("/admin/api/oauth", {}, cookie), env, ctx);
    expect(res.status).toBe(503);
    expect(((await res.json()) as { error: { message: string } }).error.message).toContain("DB binding");
  });

  it("paste complete without DB → 503 (store error keeps its own class)", async () => {
    const env = envWith();
    const cookie = await adminCookie(env);
    const res = await gateway.fetch(
      adminReq(
        "/admin/api/oauth/fakeadm/complete",
        {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ token: "sk-fake-ok" }),
        },
        cookie,
      ),
      env,
      ctx,
    );
    expect(res.status).toBe(503);
    expect(((await res.json()) as { error: { message: string } }).error.message).toContain("DB binding");
  });
});
