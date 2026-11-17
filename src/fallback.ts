import type { Env } from "./env";
import { jsonResponse } from "./http";
import { getSetting, SETTING_KEYS } from "./config";
import { resolve } from "./providers";
import { forwardToProvider, MissingKeyError, DisabledProviderError } from "./forward";
import { fireLog } from "./logging";

export type Attempt = { provider: string; status: number | string };

/**
 * Fallback chains: D1 config row first (console-edited), then env.
 * `configured` distinguishes "D1 row exists, possibly empty {}" (real console
 * state that must be reflected as-is) from "nothing configured anywhere"
 * (callers may show a built-in default). getSetting's env leg looks up the
 * lowercase setting key, so the real FALLBACK_CHAINS secret (uppercase) is
 * checked explicitly as the seed.
 */
export async function getChains(
  env: Env,
): Promise<{ chains: Record<string, string[]>; configured: boolean } | { error: string }> {
  const raw =
    (await getSetting(env, SETTING_KEYS.FALLBACK_CHAINS)) ??
    (env as unknown as Record<string, string | undefined>).FALLBACK_CHAINS ??
    null;
  if (!raw) return { chains: {}, configured: false };
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw) as unknown;
  } catch {
    return { error: "FALLBACK_CHAINS is not valid JSON — fix the env/secret value." };
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    return {
      error:
        "FALLBACK_CHAINS must be a JSON object like {\"fast\":[\"groq\",\"gemini\"]}.",
    };
  }
  for (const [name, value] of Object.entries(parsed as Record<string, unknown>)) {
    if (
      !Array.isArray(value) ||
      value.some((entry) => typeof entry !== "string")
    ) {
      return {
        error: `FALLBACK_CHAINS: chain '${name}' must be an array of provider prefixes (e.g. ["groq","gemini"]).`,
      };
    }
  }
  return { chains: parsed as Record<string, string[]>, configured: true };
}

export async function runChain(
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
  return runChainBody(body, env, ctx);
}

export async function runChainBody(
  body: Record<string, unknown>,
  env: Env,
  ctx?: ExecutionContext,
): Promise<Response> {
  const model = typeof body.model === "string" ? body.model : "";
  const slash = model.indexOf("/");
  const chainName = slash > 0 ? model.slice(0, slash) : "";
  const bareModel = slash > 0 ? model.slice(slash + 1) : "";
  const config = await getChains(env);
  if ("error" in config) {
    return jsonResponse({ error: { message: config.error } }, 500);
  }
  const chain = chainName ? config.chains[chainName] : undefined;
  if (!chainName || !bareModel || !chain?.length) {
    return jsonResponse(
      {
        error: {
          message: `Unknown model '${model}' — not a provider or fallback chain prefix. Chains come from the admin console Fallbacks tab (D1) or env FALLBACK_CHAINS.`,
        },
      },
      404,
    );
  }

  const attempts: Attempt[] = [];
  let attemptNo = 0;
  for (const prefix of chain) {
    attemptNo++;
    const started = Date.now();
    const resolved = resolve(`${prefix}/${bareModel}`);
    if (!resolved) {
      attempts.push({ provider: prefix, status: "unknown-provider" });
      fireLog(ctx, env.DB, {
        ts: Date.now(),
        provider: prefix,
        model: bareModel,
        status: 0,
        latencyMs: Date.now() - started,
        stream: body.stream === true,
        chain: chainName,
        attempt: attemptNo,
        error: "unknown-provider",
      });
      continue;
    }
    let res: Response;
    try {
      res = await forwardToProvider(
        resolved,
        "/chat/completions",
        { ...body, model: bareModel },
        env,
      );
    } catch (err) {
      if (err instanceof MissingKeyError) {
        const detail = `missing-key:${err.secret}`;
        attempts.push({ provider: prefix, status: detail });
        fireLog(ctx, env.DB, {
          ts: Date.now(),
          provider: prefix,
          model: resolved.model,
          status: 0,
          latencyMs: Date.now() - started,
          stream: body.stream === true,
          chain: chainName,
          attempt: attemptNo,
          error: detail,
        });
      } else if (err instanceof DisabledProviderError) {
        attempts.push({ provider: prefix, status: "disabled" });
        fireLog(ctx, env.DB, {
          ts: Date.now(),
          provider: prefix,
          model: resolved.model,
          status: 0,
          latencyMs: Date.now() - started,
          stream: body.stream === true,
          chain: chainName,
          attempt: attemptNo,
          error: "disabled",
        });
      } else {
        attempts.push({ provider: prefix, status: "network-error" });
        fireLog(ctx, env.DB, {
          ts: Date.now(),
          provider: prefix,
          model: resolved.model,
          status: 0,
          latencyMs: Date.now() - started,
          stream: body.stream === true,
          chain: chainName,
          attempt: attemptNo,
          error: "network-error",
        });
      }
      continue;
    }
    fireLog(ctx, env.DB, {
      ts: Date.now(),
      provider: prefix,
      model: resolved.model,
      status: res.status,
      latencyMs: Date.now() - started,
      stream: body.stream === true,
      chain: chainName,
      attempt: attemptNo,
    });
    if (res.status < 400) return res;
    // Release the failed attempt's body so the connection isn't held open
    // while the chain moves on to the next provider.
    if (res.body) {
      try {
        await res.body.cancel();
      } catch {
        // already closed/errored — nothing to release
      }
    }
    attempts.push({ provider: prefix, status: res.status });
  }

  return jsonResponse(
    { error: { message: "All fallback providers failed", attempts } },
    502,
  );
}
