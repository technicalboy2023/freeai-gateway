import { jsonResponse } from "../http";

/**
 * Admin console auth. Separate from the GATEWAY_KEY proxy auth:
 * ADMIN_PASSWORD secret signs a stateless HMAC token stored in an
 * HttpOnly cookie — no DB, no sessions table, nothing to leak.
 * Token format: `<expiryEpochMs>.<hex(HMAC-SHA256(key=ADMIN_PASSWORD, msg="admin:"+expiry))>`.
 * Valid iff the HMAC matches AND expiry > now. Unset ADMIN_PASSWORD → 503.
 *
 * Brute-force protection: failed attempts are counted in D1 per client IP
 * (fail-open — a missing table/binding or D1 error never blocks a login).
 */
const SESSION_TTL_MS = 7 * 24 * 60 * 60 * 1000;
export const ADMIN_COOKIE = "admin_session";
const MAX_ATTEMPTS = 5;
const LOCKOUT_MS = 15 * 60 * 1000;

/** Constant-time string compare (XOR accumulate) — for HMAC digest compares. */
function constantTimeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}

async function hmacHex(password: string, expiry: string): Promise<string> {
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
  return [...new Uint8Array(sig)]
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

export async function checkAdmin(request: Request, env: { ADMIN_PASSWORD?: string }): Promise<boolean> {
  if (!env.ADMIN_PASSWORD) return false;
  const cookies = request.headers.get("cookie") ?? "";
  const m = cookies.match(new RegExp(`(?:^|;\\s*)${ADMIN_COOKIE}=([^;]*)`));
  if (!m) return false;
  const token = m[1];
  const dot = token.indexOf(".");
  if (dot < 1) return false;
  const expiryStr = token.slice(0, dot);
  const expiry = Number(expiryStr);
  if (!Number.isFinite(expiry) || expiry <= Date.now()) return false;
  const expected = await hmacHex(env.ADMIN_PASSWORD, expiryStr);
  return constantTimeEqual(token.slice(dot + 1), expected);
}

/* ---------- login throttle (fail-open) ---------- */

type ThrottleEnv = { ADMIN_PASSWORD?: string; DB?: D1Database };

function attemptKey(request: Request): string {
  // Cloudflare sets this on every real request; local dev/tests share "unknown".
  return request.headers.get("cf-connecting-ip") ?? "unknown";
}

async function lockedUntil(env: ThrottleEnv, key: string): Promise<number | null> {
  if (!env.DB) return null;
  try {
    const row = await env.DB.prepare(
      "SELECT count, until FROM login_attempts WHERE key = ?1",
    )
      .bind(key)
      .first<{ count: number; until: number }>();
    if (row && row.until > Date.now()) return row.until;
  } catch {
    // D1 down / table missing → fail-open (consistent with the logging rule).
  }
  return null;
}

async function recordFailure(env: ThrottleEnv, key: string): Promise<void> {
  if (!env.DB) return;
  try {
    const row = await env.DB.prepare(
      "SELECT count, until FROM login_attempts WHERE key = ?1",
    )
      .bind(key)
      .first<{ count: number; until: number }>();
    // Stale only if a lock was actually set and has since expired — an
    // in-progress counter (until = 0) must keep accumulating.
    const stale = !row || (row.until > 0 && row.until <= Date.now());
    const count = stale ? 1 : row!.count + 1;
    const until = count >= MAX_ATTEMPTS ? Date.now() + LOCKOUT_MS : 0;
    await env.DB.prepare(
      "INSERT INTO login_attempts (key, count, until) VALUES (?1, ?2, ?3) " +
        "ON CONFLICT(key) DO UPDATE SET count = excluded.count, until = excluded.until",
    )
      .bind(key, count, until)
      .run();
  } catch {
    // fail-open
  }
}

async function clearAttempts(env: ThrottleEnv, key: string): Promise<void> {
  if (!env.DB) return;
  try {
    await env.DB.prepare("DELETE FROM login_attempts WHERE key = ?1")
      .bind(key)
      .run();
  } catch {
    // fail-open
  }
}

export async function handleLogin(
  request: Request,
  env: { ADMIN_PASSWORD?: string },
): Promise<Response> {
  if (!env.ADMIN_PASSWORD) {
    return jsonResponse(
      {
        error: {
          message:
            "Admin console disabled — set the ADMIN_PASSWORD secret: npx wrangler secret put ADMIN_PASSWORD",
        },
      },
      503,
    );
  }
  let body: Record<string, unknown>;
  try {
    body = (await request.json()) as Record<string, unknown>;
  } catch {
    return jsonResponse({ error: { message: "Invalid JSON body" } }, 400);
  }
  const key = attemptKey(request);
  const locked = await lockedUntil(env, key);
  if (locked) {
    return jsonResponse(
      {
        error: {
          message: `Too many failed login attempts — locked until ${new Date(locked).toISOString()}`,
        },
      },
      429,
      { "retry-after": String(Math.max(1, Math.ceil((locked - Date.now()) / 1000))) },
    );
  }
  if (body.password !== env.ADMIN_PASSWORD) {
    await recordFailure(env, key);
    return jsonResponse({ error: { message: "Wrong password" } }, 401);
  }
  await clearAttempts(env, key);
  const expiry = Date.now() + SESSION_TTL_MS;
  const token = `${expiry}.${await hmacHex(env.ADMIN_PASSWORD, String(expiry))}`;
  return new Response(JSON.stringify({ ok: true }), {
    status: 200,
    headers: {
      "content-type": "application/json",
      "set-cookie": `${ADMIN_COOKIE}=${token}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=${Math.floor(SESSION_TTL_MS / 1000)}`,
    },
  });
}

export function handleLogout(): Response {
  return new Response(JSON.stringify({ ok: true }), {
    status: 200,
    headers: {
      "content-type": "application/json",
      "set-cookie": `${ADMIN_COOKIE}=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0`,
    },
  });
}

export async function handleMe(
  request: Request,
  env: { ADMIN_PASSWORD?: string },
): Promise<Response> {
  if (await checkAdmin(request, env)) {
    return jsonResponse({ authenticated: true });
  }
  return jsonResponse({ error: { message: "Unauthorized" } }, 401);
}
