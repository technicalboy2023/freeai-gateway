import type { Env } from "../env";
import { jsonResponse } from "../http";
import {
  complete,
  disconnect,
  listAdapters,
  OAuthError,
  poll,
  start,
  statusOf,
} from "../oauth/engine";
import type { CompleteInput } from "../oauth/engine";
import { MissingKeyMaterialError } from "../oauth/errors";
import { DbMissingError, deletePending, getPending, getTokenStatus } from "../oauth/store";
import type { PendingRow } from "../oauth/store";

/**
 * Admin console OAuth endpoints (Wave B). Every handler funnels engine/store
 * work through oauthGuard so errors land as clean JSON: OAuthError → its own
 * status, typed missing encryption key → 503 (instanceof first; the message
 * regex stays as a safety net for engine-wrapped strings), missing DB
 * binding → 503. Responses carry NO token material — only metadata the UI renders.
 */

async function oauthGuard(work: () => Promise<Response>): Promise<Response> {
  try {
    return await work();
  } catch (err) {
    if (err instanceof MissingKeyMaterialError) {
      return jsonResponse({ error: { message: err.message } }, 503);
    }
    if (err instanceof OAuthError) {
      // Engine paths wrap store errors generically (400); the pinned missing-key
      // message always means 503 regardless of which flow wrapped it.
      const status = /OAUTH_ENCRYPTION_KEY/.test(err.message) ? 503 : err.status;
      return jsonResponse({ error: { message: err.message } }, status);
    }
    if (err instanceof Error && /OAUTH_ENCRYPTION_KEY/.test(err.message)) {
      return jsonResponse(
        { error: { message: "set OAUTH_ENCRYPTION_KEY secret first" } },
        503,
      );
    }
    if (err instanceof DbMissingError) {
      return jsonResponse(
        { error: { message: "DB binding not configured — OAuth console unavailable" } },
        503,
      );
    }
    return jsonResponse(
      { error: { message: `OAuth admin error: ${err instanceof Error ? err.message : "unknown error"}` } },
      500,
    );
  }
}

/** GET /admin/api/oauth — adapter registry + connection state, no secrets. */
export async function handleOauthList(env: Env): Promise<Response> {
  return oauthGuard(async () => {
    const providers: Array<Record<string, unknown>> = [];
    for (const a of listAdapters()) {
      const s = await getTokenStatus(env, a.prefix);
      providers.push({
        prefix: a.prefix,
        flowMode: a.flowMode,
        connected: s?.connected ?? false,
        expiresAt: s?.expiresAt ?? null,
        accountLabel: s?.accountLabel ?? null,
        lastError: s?.lastError ?? null,
        importToken: typeof a.importToken === "function",
        ...(a.instructions ? { instructions: a.instructions } : {}),
      });
    }
    return jsonResponse({ providers });
  });
}

/** POST /admin/api/oauth/:prefix/start — request URL origin feeds redirectUri. */
export function handleOauthStart(request: Request, env: Env, prefix: string): Promise<Response> {
  return oauthGuard(async () => jsonResponse(await start(env, prefix, new URL(request.url))));
}

/** POST /admin/api/oauth/:prefix/complete {code?, token?, blob?}. */
export function handleOauthComplete(request: Request, env: Env, prefix: string): Promise<Response> {
  return oauthGuard(async () => {
    let body: Record<string, unknown>;
    try {
      body = (await request.json()) as Record<string, unknown>;
    } catch {
      return jsonResponse({ error: { message: "Invalid JSON body" } }, 400);
    }
    const input: CompleteInput = {};
    if (typeof body.code === "string") input.code = body.code;
    if (typeof body.token === "string") input.token = body.token;
    if (typeof body.blob === "string") input.blob = body.blob;
    return jsonResponse(await complete(env, prefix, input, new URL(request.url)));
  });
}

/** GET /admin/api/oauth/:prefix/poll — device-flow status check. */
export function handleOauthPoll(env: Env, prefix: string): Promise<Response> {
  return oauthGuard(async () => jsonResponse(await poll(env, prefix)));
}

/** GET /admin/api/oauth/:prefix/status — non-secret connection snapshot. */
export function handleOauthStatus(env: Env, prefix: string): Promise<Response> {
  return oauthGuard(async () => jsonResponse(await statusOf(env, prefix)));
}

/** DELETE /admin/api/oauth/:prefix — forget the connection + in-flight flow. */
export function handleOauthDisconnect(env: Env, prefix: string): Promise<Response> {
  return oauthGuard(async () => {
    await disconnect(env, prefix);
    return jsonResponse({ disconnected: prefix });
  });
}

/* ---------- public state-matched auto-callback (USER DECISION 2026-11-16) ---------- */

/**
 * The admin cookie is SameSite=Strict, so a redirect arriving from the
 * provider carries no cookie — admin-gating this route would 401 in
 * production. The gate here is the encrypted pending row itself: it must
 * exist, be a pkce flow, be unexpired, and its decrypted state must strictly
 * equal the query state. Single-use: the pending row is always consumed in a
 * finally, even when the exchange fails — the user restarts from the console.
 */
function escHtml(s: string): string {
  return s.replace(/[&<>"']/g, (c) => {
    switch (c) {
      case "&": return "&amp;";
      case "<": return "&lt;";
      case ">": return "&gt;";
      case '"': return "&quot;";
      default: return "&#39;";
    }
  });
}

function callbackPage(body: string, status: number): Response {
  return new Response(
    `<!doctype html><html><head><meta charset="utf-8"><title>FreeAI Gateway</title></head><body>${body}</body></html>`,
    { status, headers: { "content-type": "text/html; charset=utf-8" } },
  );
}

export async function handleOauthCallback(request: Request, env: Env, prefix: string): Promise<Response> {
  const url = new URL(request.url);
  const code = url.searchParams.get("code") ?? "";
  const state = url.searchParams.get("state") ?? "";
  const invalid = callbackPage(
    "<p>Invalid or expired login link. Start the login again from the admin console.</p>",
    400,
  );
  let pending: PendingRow | null = null;
  try {
    pending = await getPending(env, prefix);
  } catch {
    pending = null; // DB/key trouble → the same invalid page, never a leak
  }
  if (
    !code ||
    !state ||
    !pending ||
    pending.mode !== "pkce" ||
    pending.state !== state ||
    pending.expiresAt <= Date.now()
  ) {
    return invalid;
  }
  try {
    await complete(env, prefix, { code }, url);
    return callbackPage(`<p>Connected ${escHtml(prefix)}. You can close this tab.</p>`, 200);
  } catch (err) {
    const msg = err instanceof Error ? err.message : "login failed";
    return callbackPage(`<p>Login failed: ${escHtml(msg)}</p>`, 200);
  } finally {
    try {
      await deletePending(env, prefix);
    } catch {
      // row already consumed — nothing to do
    }
  }
}
