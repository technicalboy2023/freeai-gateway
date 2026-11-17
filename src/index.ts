import type { Env } from "./env";
import { jsonResponse, optionsPreflight, withCors } from "./http";
import { checkAuth } from "./auth";
import { handleChat } from "./chat";
import { handleMessages } from "./messages";
import { handleModels } from "./models";
import { handleLogin, handleLogout, handleMe, checkAdmin } from "./admin/auth";
import {
  handleListProviders,
  handleTestProvider,
  handleToggleProvider,
} from "./admin/providers";
import {
  handleGetFallbacks,
  handleLogs,
  handlePruneLogs,
  handlePutFallbacks,
  handleStats,
} from "./admin/ops";
import { handlePlayground } from "./admin/playground";
import {
  handleOauthCallback,
  handleOauthComplete,
  handleOauthDisconnect,
  handleOauthList,
  handleOauthPoll,
  handleOauthStart,
  handleOauthStatus,
} from "./admin/oauth";

/** Returns a 401 Response when the admin session cookie is missing/invalid. */
async function adminGate(request: Request, env: Env): Promise<Response | null> {
  return (await checkAdmin(request, env))
    ? null
    : jsonResponse({ error: { message: "Unauthorized" } }, 401);
}

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    try {
      const { pathname } = new URL(request.url);
      if (request.method === "OPTIONS") {
        return optionsPreflight();
      }
      if (pathname === "/v1/chat/completions" && request.method === "POST") {
        const denied = await checkAuth(request, env);
        if (denied) return withCors(denied);
        return withCors(await handleChat(request, env, ctx));
      }
      if (pathname === "/v1/messages" && request.method === "POST") {
        const denied = await checkAuth(request, env);
        if (denied) return withCors(denied);
        return withCors(await handleMessages(request, env, ctx));
      }
      if (pathname === "/v1/models" && request.method === "GET") {
        return withCors(await handleModels(env));
      }
      if (pathname === "/admin/api/login" && request.method === "POST") {
        return handleLogin(request, env);
      }
      if (pathname === "/admin/api/logout" && request.method === "POST") {
        return handleLogout();
      }
      if (pathname === "/admin/api/me" && request.method === "GET") {
        return handleMe(request, env);
      }
      if (pathname.startsWith("/admin/api/providers")) {
        const denied = await adminGate(request, env);
        if (denied) return denied;
        if (pathname === "/admin/api/providers" && request.method === "GET") {
          return handleListProviders(env);
        }
        const m = pathname.match(/^\/admin\/api\/providers\/([a-z0-9_-]+)\/(toggle|test)$/);
        if (m && request.method === "POST") {
          const [, prefix, action] = m;
          return action === "toggle"
            ? handleToggleProvider(request, env, prefix)
            : handleTestProvider(env, prefix);
        }
        return jsonResponse(
          { error: { message: `No admin route: ${request.method} ${pathname}` } },
          404,
        );
      }
      if (
        pathname === "/admin/api/fallbacks" &&
        (request.method === "GET" || request.method === "PUT")
      ) {
        const denied = await adminGate(request, env);
        if (denied) return denied;
        return request.method === "GET"
          ? handleGetFallbacks(env)
          : handlePutFallbacks(request, env);
      }
      if (pathname === "/admin/api/logs" && request.method === "GET") {
        const denied = await adminGate(request, env);
        if (denied) return denied;
        return handleLogs(request, env);
      }
      if (pathname === "/admin/api/logs/prune" && request.method === "POST") {
        const denied = await adminGate(request, env);
        if (denied) return denied;
        return handlePruneLogs(request, env);
      }
      if (pathname === "/admin/api/stats" && request.method === "GET") {
        const denied = await adminGate(request, env);
        if (denied) return denied;
        return handleStats(env);
      }
      if (pathname === "/admin/api/playground" && request.method === "POST") {
        const denied = await adminGate(request, env);
        if (denied) return denied;
        return handlePlayground(request, env, ctx);
      }
      // PUBLIC state-matched OAuth auto-callback — registered BEFORE the
      // admin-gated API routes and the /admin assets catch-all. The encrypted
      // pending row (mode pkce, unexpired, state match) is its only gate.
      const oauthCb = pathname.match(/^\/admin\/oauth\/([a-z0-9_-]+)\/callback$/);
      if (oauthCb && request.method === "GET") {
        return handleOauthCallback(request, env, oauthCb[1]);
      }
      if (pathname.startsWith("/admin/api/oauth")) {
        const denied = await adminGate(request, env);
        if (denied) return denied;
        if (pathname === "/admin/api/oauth" && request.method === "GET") {
          return handleOauthList(env);
        }
        const m = pathname.match(/^\/admin\/api\/oauth\/([a-z0-9_-]+)(\/(start|complete|poll|status))?$/);
        if (m) {
          const [, prefix, , action] = m;
          if (request.method === "POST" && action === "start") {
            return handleOauthStart(request, env, prefix);
          }
          if (request.method === "POST" && action === "complete") {
            return handleOauthComplete(request, env, prefix);
          }
          if (request.method === "GET" && action === "poll") {
            return handleOauthPoll(env, prefix);
          }
          if (request.method === "GET" && action === "status") {
            return handleOauthStatus(env, prefix);
          }
          if (request.method === "DELETE" && !action) {
            return handleOauthDisconnect(env, prefix);
          }
        }
        return jsonResponse(
          { error: { message: `No admin route: ${request.method} ${pathname}` } },
          404,
        );
      }
      if (pathname.startsWith("/admin") && !pathname.startsWith("/admin/api/")) {
        // Console SPA routing (run_worker_first sends /admin* here first).
        if (request.method !== "GET") {
          return jsonResponse({ error: { message: "Admin assets are GET-only" } }, 404);
        }
        if (!env.ASSETS) {
          return jsonResponse(
            { error: { message: "ASSETS binding not configured — check wrangler.jsonc assets block" } },
            500,
          );
        }
        return env.ASSETS.fetch(request);
      }
      if (pathname === "/") {
        return withCors(jsonResponse({ name: "freeai-gateway", status: "ok" }));
      }
      return withCors(
        jsonResponse(
          { error: { message: `No route for ${request.method} ${pathname}` } },
          404,
        ),
      );
    } catch (err) {
      // Backstop: never leak an opaque HTML error page — always JSON with CORS.
      return withCors(
        jsonResponse(
          {
            error: {
              message: `Gateway error: ${err instanceof Error ? err.message : "unknown error"}`,
            },
          },
          500,
        ),
      );
    }
  },
} satisfies ExportedHandler<Env>;
