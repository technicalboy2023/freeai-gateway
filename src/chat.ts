import type { Env } from "./env";
import { jsonResponse } from "./http";
import { resolve } from "./providers";
import { forwardOr400 } from "./forward";
import { runChainBody } from "./fallback";
import { fireLog } from "./logging";

export async function handleChat(
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
  if (resolved) {
    const upstreamBody = { ...body, model: resolved.model };
    const started = Date.now();
    const meta: { error?: string } = {};
    const res = await forwardOr400(
      resolved,
      "/chat/completions",
      upstreamBody,
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
  // Not a provider prefix — try a fallback chain named by the prefix.
  return runChainBody(body, env, ctx);
}
