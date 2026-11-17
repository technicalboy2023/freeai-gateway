import type { Env } from "./env";
import { jsonResponse } from "./http";
import { resolve } from "./providers";
import { forwardOr400 } from "./forward";
import { fireLog } from "./logging";

/**
 * Anthropic-wire endpoint (/v1/messages) — for Claude Code and Anthropic-SDK tools.
 * Routes ONLY to the anthropic provider (OpenAI-format providers don't speak this wire).
 * Model id may come plain ("claude-sonnet-4") or prefixed ("anthropic/claude-sonnet-4").
 */
export async function handleMessages(
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
    return jsonResponse({ error: { message: "model is required" } }, 400);
  }
  const resolved = resolve(model.startsWith("anthropic/") ? model : `anthropic/${model}`);
  if (!resolved || resolved.prefix !== "anthropic") {
    return jsonResponse(
      { error: { message: `Unsupported model '${model}' for /v1/messages` } },
      404,
    );
  }
  const started = Date.now();
  const meta: { error?: string } = {};
  const res = await forwardOr400(
    resolved,
    "/messages",
    { ...body, model: resolved.model },
    env,
    request.headers,
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
