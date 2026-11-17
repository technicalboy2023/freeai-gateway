import type { Env } from "../env";
import { jsonResponse } from "../http";
import { list } from "../providers";
import { readEnabledMap, readEnabledMapStrict, setSetting, SETTING_KEYS } from "../config";
import { getAdapter } from "../oauth/engine";
import { getTokenStatus } from "../oauth/store";

function envKey(env: Env, secret: string | undefined): string | undefined {
  return secret ? (env as unknown as Record<string, string | undefined>)[secret] : undefined;
}

/**
 * GET /admin/api/providers — registry + console state.
 * Response contains NO key material: keyConfigured is a boolean only.
 */
export async function handleListProviders(env: Env): Promise<Response> {
  const enabled = await readEnabledMap(env);
  const providers = list().map((p) => ({
    prefix: p.prefix,
    enabled: enabled[p.prefix] !== false,
    keyConfigured: !!envKey(env, p.keySecret),
    freeModels: p.freeModels,
  }));
  return jsonResponse({ providers });
}

/**
 * POST /admin/api/providers/:prefix/toggle {enabled:boolean} — persists the
 * merged providers_enabled map to D1. Unknown prefix → 404.
 */
export async function handleToggleProvider(
  request: Request,
  env: Env,
  prefix: string,
): Promise<Response> {
  const provider = list().find((p) => p.prefix === prefix);
  if (!provider) {
    return jsonResponse({ error: { message: `Unknown provider '${prefix}'` } }, 404);
  }
  let body: Record<string, unknown>;
  try {
    body = (await request.json()) as Record<string, unknown>;
  } catch {
    return jsonResponse({ error: { message: "Invalid JSON body" } }, 400);
  }
  if (typeof body.enabled !== "boolean") {
    return jsonResponse(
      { error: { message: "Field 'enabled' (boolean) is required" } },
      400,
    );
  }
  // Strict read (throws on missing DB / D1 error / invalid stored map): a
  // toggle must never proceed on a degraded read — the merge would persist a
  // partial map and silently wipe every other entry.
  let enabled: Record<string, boolean>;
  try {
    enabled = await readEnabledMapStrict(env);
    enabled[prefix] = body.enabled;
    await setSetting(env, SETTING_KEYS.PROVIDERS_ENABLED, JSON.stringify(enabled));
  } catch (err) {
    return jsonResponse(
      {
        error: {
          message: `D1 unavailable — toggle not persisted, no changes written (${(err as Error).message})`,
        },
      },
      503,
    );
  }
  return jsonResponse({ ok: true, prefix, enabled: body.enabled });
}

/**
 * POST /admin/api/providers/:prefix/test — verifies the configured key with a
 * cheap GET <baseURL>/models (no tokens consumed). Returns { ok, status,
 * latencyMs } only — never the key itself.
 */
export async function handleTestProvider(env: Env, prefix: string): Promise<Response> {
  const provider = list().find((p) => p.prefix === prefix);
  if (!provider) {
    const oauthAdapter = getAdapter(prefix);
    if (!oauthAdapter) {
      return jsonResponse({ error: { message: `Unknown provider '${prefix}'` } }, 404);
    }
    const status = await getTokenStatus(env, prefix);
    return status?.connected
      ? jsonResponse({ ok: true, provider: prefix, auth: "oauth" })
      : jsonResponse({ ok: false, reason: "not_connected" });
  }
  const key = envKey(env, provider.keySecret);
  if (!key) {
    return jsonResponse({
      ok: false,
      status: 0,
      error: `missing-key:${provider.keySecret}`,
    });
  }
  const headers: Record<string, string> =
    provider.auth === "anthropic"
      ? { "x-api-key": key, "anthropic-version": "2023-06-01" }
      : { authorization: `Bearer ${key}` };
  const started = Date.now();
  try {
    const res = await fetch(`${provider.baseURL}/models`, { method: "GET", headers });
    return jsonResponse({
      ok: res.status < 400,
      status: res.status,
      latencyMs: Date.now() - started,
    });
  } catch {
    return jsonResponse({
      ok: false,
      status: 0,
      latencyMs: Date.now() - started,
      error: "network-error",
    });
  }
}
