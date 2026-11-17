import type { Env } from "./env";
import { jsonResponse } from "./http";

/**
 * Gateway auth: single Bearer GATEWAY_KEY secret.
 * Returns the 401 Response to send, or null when the request may proceed.
 * Fails closed: unconfigured GATEWAY_KEY rejects everything.
 */
export async function checkAuth(request: Request, env: Env): Promise<Response | null> {
  const expected = env.GATEWAY_KEY;
  const provided = request.headers.get("authorization");
  const token = provided?.startsWith("Bearer ") ? provided.slice(7).trim() : "";
  if (!expected || !token || token !== expected) {
    return jsonResponse(
      {
        error: {
          message:
            "Missing or invalid gateway key. Send header: Authorization: Bearer <GATEWAY_KEY>",
        },
      },
      401,
    );
  }
  return null;
}
