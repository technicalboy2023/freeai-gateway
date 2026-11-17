import type { Env } from "../env";
import { jsonResponse } from "../http";
import { resolve } from "../providers";
import { forwardOr400 } from "../forward";
import { fireLog } from "../logging";

/**
 * POST /admin/api/playground — console "Run" button.
 * Auth is the admin session cookie (index gate), NOT GATEWAY_KEY.
 * Direct provider call only (no fallback chains), request logged like any
 * other proxy call (chain/attempt null).
 */
export async function handlePlayground(
  request: Request,
  env: Env,
  ctx?: ExecutionContext,
): Promise<Response> {
  let body: Record<string, unknown>;
  try {
    body = (await request.json()) as Record<string, unknown>;
  } catch {
    return jsonResponse({ error: { message: "Invalid JSON body" } }, 400);
  }
  const model = typeof body.model === "string" ? body.model : "";
  if (!model) {
    return jsonResponse(
      { error: { message: "model is required (format: provider/model)" } },
      400,
    );
  }
  const resolved = resolve(model);
  if (!resolved) {
    return jsonResponse(
      { error: { message: `Unknown provider for model '${model}'` } },
      404,
    );
  }
  const started = Date.now();
  const meta: { error?: string } = {};
  const res = await forwardOr400(
    resolved,
    "/chat/completions",
    { ...body, model: resolved.model },
    env,
    undefined,
    meta,
  );
  fireLog(ctx, env.DB, {
    ts: Date.now(),
    provider: resolved.prefix,
    model: resolved.model,
    status: res.status,
    latencyMs: Date.now() - started,
    stream: body.stream === true,
    chain: null,
    attempt: null,
    error: meta.error ?? null,
  });
  return res;
}
