import { describe, expect, it } from "vitest";
import gateway from "../src/index";
import { checkAdmin, handleLogin, handleLogout, handleMe } from "../src/admin/auth";
import type { Env } from "../src/env";

const env = { ADMIN_PASSWORD: "pass123" } as unknown as Env;

/** Signs the wire format the gateway uses: hex(HMAC-SHA256(password, "admin:"+expiry)). */
async function signToken(password: string, expiry: number): Promise<string> {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const sig = await crypto.subtle.sign(
    "HMAC",
    key,
    new TextEncoder().encode(`admin:${expiry}`),
  );
  const hex = [...new Uint8Array(sig)]
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
  return `${expiry}.${hex}`;
}

function loginReq(password: string): Request {
  return new Request("https://gw.test/admin/api/login", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ password }),
  });
}

function cookieValue(res: Response): string | null {
  const m = (res.headers.get("set-cookie") ?? "").match(/admin_session=([^;]*)/);
  return m ? m[1] : null;
}

function reqWithCookie(token: string): Request {
  return new Request("https://gw.test/admin/api/me", {
    headers: { cookie: `admin_session=${token}` },
  });
}

describe("admin login", () => {
  it("correct password → 200 + HttpOnly SameSite=Strict 7d cookie with valid HMAC token", async () => {
    const res = await handleLogin(loginReq("pass123"), env);
    expect(res.status).toBe(200);
    const setCookie = res.headers.get("set-cookie") ?? "";
    expect(setCookie).toContain("HttpOnly");
    expect(setCookie).toContain("SameSite=Strict");
    expect(setCookie).toContain("Secure");
    expect(setCookie).toContain("Max-Age=604800");
    const token = cookieValue(res);
    expect(token).toMatch(/^\d+\.[0-9a-f]{64}$/);
    const expiry = Number(token!.split(".")[0]);
    expect(expiry).toBeGreaterThan(Date.now());
    expect(expiry).toBeLessThanOrEqual(Date.now() + 7 * 24 * 60 * 60 * 1000);
    expect(await checkAdmin(reqWithCookie(token!), env)).toBe(true);
  });

  it("wrong password → 401, no cookie", async () => {
    const res = await handleLogin(loginReq("nope"), env);
    expect(res.status).toBe(401);
    expect(cookieValue(res)).toBeNull();
  });

  it("ADMIN_PASSWORD unset → 503 (console disabled)", async () => {
    const res = await handleLogin(loginReq("anything"), {} as Env);
    expect(res.status).toBe(503);
  });
});

describe("checkAdmin", () => {
  it("accepts a token issued by login", async () => {
    const res = await handleLogin(loginReq("pass123"), env);
    const token = cookieValue(res)!;
    expect(await checkAdmin(reqWithCookie(token), env)).toBe(true);
  });

  it("rejects a tampered token", async () => {
    const token = await signToken("pass123", Date.now() + 60_000);
    const [expiry, sig] = token.split(".");
    const bad = `${expiry}.${sig.slice(0, 62)}ff`;
    expect(await checkAdmin(reqWithCookie(bad), env)).toBe(false);
  });

  it("rejects an expired token (even with a valid HMAC)", async () => {
    const token = await signToken("pass123", Date.now() - 1000);
    expect(await checkAdmin(reqWithCookie(token), env)).toBe(false);
  });

  it("rejects a garbage token (non-numeric expiry)", async () => {
    expect(await checkAdmin(reqWithCookie("junk.sig"), env)).toBe(false);
  });

  it("rejects when the cookie is missing", async () => {
    expect(await checkAdmin(new Request("https://gw.test/admin/api/me"), env)).toBe(false);
  });
});

describe("logout + routing", () => {
  it("logout clears the session cookie (Secure flag too)", () => {
    const res = handleLogout();
    expect(res.status).toBe(200);
    const setCookie = res.headers.get("set-cookie") ?? "";
    expect(setCookie).toContain("admin_session=");
    expect(setCookie).toContain("Max-Age=0");
    expect(setCookie).toContain("Secure");
  });

  it("POST /admin/api/login and GET /admin/api/me are wired through the worker", async () => {
    const login = await gateway.fetch(loginReq("pass123"), env, {} as ExecutionContext);
    expect(login.status).toBe(200);
    const token = cookieValue(login)!;
    const me = await gateway.fetch(reqWithCookie(token), env, {} as ExecutionContext);
    expect(me.status).toBe(200);
    expect(await me.json()).toEqual({ authenticated: true });
  });

  it("GET /admin/api/me without a session → 401", async () => {
    const me = await handleMe(new Request("https://gw.test/admin/api/me"), env);
    expect(me.status).toBe(401);
  });
});

/** D1 stub covering config + login_attempts tables; failAll simulates D1 down. */
function stubDb(opts: { failAll?: boolean } = {}) {
  const configRows: Record<string, string> = {};
  const attempts = new Map<string, { count: number; until: number }>();
  const runCalls: Array<{ sql: string; params: unknown[] }> = [];
  const db = {
    prepare: (sql: string) => ({
      bind: (...params: unknown[]) => ({
        first: async <T,>() => {
          if (opts.failAll) throw new Error("d1 unavailable");
          if (sql.includes("FROM login_attempts")) {
            const row = attempts.get(params[0] as string);
            return row ? (row as unknown as T) : null;
          }
          const key = params[0] as string;
          return key in configRows ? ({ value: configRows[key] } as T) : null;
        },
        run: async () => {
          if (opts.failAll) throw new Error("d1 unavailable");
          runCalls.push({ sql, params });
          if (sql.includes("INSERT INTO config")) {
            configRows[params[0] as string] = params[1] as string;
          }
          if (sql.includes("INSERT INTO login_attempts")) {
            attempts.set(params[0] as string, {
              count: params[1] as number,
              until: params[2] as number,
            });
          }
          if (sql.includes("DELETE FROM login_attempts")) {
            attempts.delete(params[0] as string);
          }
          return { success: true };
        },
      }),
    }),
  } as unknown as D1Database;
  return { db, attempts, runCalls };
}

describe("login throttle (brute-force protection)", () => {
  function envWithDb(db: D1Database): Env {
    return { ADMIN_PASSWORD: "pass123", DB: db } as unknown as Env;
  }

  it("5 wrong attempts lock the IP: 6th attempt (even correct) → 429 + Retry-After", async () => {
    const { db, attempts } = stubDb();
    const e = envWithDb(db);
    for (let i = 0; i < 5; i++) {
      const res = await handleLogin(loginReq("nope"), e);
      expect(res.status).toBe(401);
    }
    const locked = await handleLogin(loginReq("pass123"), e);
    expect(locked.status).toBe(429);
    const retryAfter = locked.headers.get("retry-after");
    expect(Number(retryAfter)).toBeGreaterThan(0);
    expect(Number(retryAfter)).toBeLessThanOrEqual(15 * 60);
    const body = (await locked.json()) as { error: { message: string } };
    expect(body.error.message).toContain("Too many failed login attempts");
    // lock row recorded with a future until
    const row = attempts.get("unknown")!;
    expect(row.count).toBe(5);
    expect(row.until).toBeGreaterThan(Date.now());
  });

  it("a successful login clears the attempt counter", async () => {
    const { db, attempts } = stubDb();
    const e = envWithDb(db);
    await handleLogin(loginReq("nope"), e);
    await handleLogin(loginReq("nope"), e);
    const ok = await handleLogin(loginReq("pass123"), e);
    expect(ok.status).toBe(200);
    expect(attempts.has("unknown")).toBe(false);
    // further wrong attempts start from zero again
    for (let i = 0; i < 4; i++) await handleLogin(loginReq("nope"), e);
    const notLocked = await handleLogin(loginReq("nope"), e);
    expect(notLocked.status).toBe(401); // 4 fresh failures < 5 → no lock yet
  });

  it("fail-open: no DB binding → login still works", async () => {
    const e = { ADMIN_PASSWORD: "pass123" } as unknown as Env;
    for (let i = 0; i < 7; i++) {
      const res = await handleLogin(loginReq(i < 6 ? "nope" : "pass123"), e);
      expect([401, 200]).toContain(res.status);
    }
  });

  it("fail-open: D1 errors don't block login", async () => {
    const { db } = stubDb({ failAll: true });
    const e = envWithDb(db);
    const ok = await handleLogin(loginReq("pass123"), e);
    expect(ok.status).toBe(200);
    const bad = await handleLogin(loginReq("nope"), e);
    expect(bad.status).toBe(401);
  });
});
