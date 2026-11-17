import type { Env } from "../env";
import { jsonResponse } from "../http";
import { list } from "../providers";
import { setSetting, SETTING_KEYS } from "../config";
import { getChains } from "../fallback";

const SEVEN_DAYS_MS = 7 * 24 * 60 * 60 * 1000;
/** Shown in the console when NO chains are configured anywhere (no D1 row, no env). */
const DEFAULT_CHAINS: Record<string, string[]> = { default: ["groq", "gemini"] };

function chainsToShape(chains: Record<string, string[]>) {
  return Object.entries(chains).map(([name, providers]) => ({ name, providers }));
}

/**
 * GET /admin/api/fallbacks — chain shape [{name, providers}].
 * Precedence: D1 row (even a deliberately-empty "{}" — shown as-is) → env
 * FALLBACK_CHAINS → built-in default (only when nothing is configured).
 */
export async function handleGetFallbacks(env: Env): Promise<Response> {
  const config = await getChains(env);
  if ("error" in config) {
    return jsonResponse({ error: { message: config.error } }, 500);
  }
  const chains = config.configured ? config.chains : DEFAULT_CHAINS;
  return jsonResponse({ chains: chainsToShape(chains) });
}

/**
 * PUT /admin/api/fallbacks {chains:[{name, providers}]} — validates every
 * provider prefix against the registry, persists the map to D1.
 */
export async function handlePutFallbacks(
  request: Request,
  env: Env,
): Promise<Response> {
  if (!env.DB) {
    return jsonResponse(
      { error: { message: "D1 not configured — cannot persist fallback chains" } },
      503,
    );
  }
  let body: { chains?: unknown };
  try {
    body = (await request.json()) as { chains?: unknown };
  } catch {
    return jsonResponse({ error: { message: "Invalid JSON body" } }, 400);
  }
  if (!Array.isArray(body.chains)) {
    return jsonResponse(
      { error: { message: "Field 'chains' (array of {name, providers}) is required" } },
      400,
    );
  }
  const known = new Set(list().map((p) => p.prefix));
  const map: Record<string, string[]> = {};
  const seenNames = new Set<string>();
  for (const entry of body.chains as unknown[]) {
    const e = entry as { name?: unknown; providers?: unknown };
    if (typeof e.name !== "string" || !e.name) {
      return jsonResponse(
        { error: { message: "Each chain needs a non-empty 'name'" } },
        400,
      );
    }
    if (known.has(e.name)) {
      return jsonResponse(
        {
          error: {
            message: `Chain name '${e.name}' collides with a provider prefix — provider prefixes always win, so this chain would be unreachable. Pick another name.`,
          },
        },
        400,
      );
    }
    if (seenNames.has(e.name)) {
      return jsonResponse(
        { error: { message: `Duplicate chain name '${e.name}'` } },
        400,
      );
    }
    seenNames.add(e.name);
    if (
      !Array.isArray(e.providers) ||
      e.providers.length === 0 ||
      e.providers.some((p) => typeof p !== "string")
    ) {
      return jsonResponse(
        {
          error: {
            message: `Chain '${e.name}' needs a non-empty 'providers' array of strings`,
          },
        },
        400,
      );
    }
    for (const p of e.providers as string[]) {
      if (!known.has(p)) {
        return jsonResponse(
          {
            error: {
              message: `Unknown provider prefix '${p}' in chain '${e.name}'`,
            },
          },
          400,
        );
      }
    }
    map[e.name] = e.providers as string[];
  }
  await setSetting(env, SETTING_KEYS.FALLBACK_CHAINS, JSON.stringify(map));
  return jsonResponse({ ok: true, chains: chainsToShape(map) });
}

/** GET /admin/api/logs?limit=N — newest rows first (SQL orders, we just serve). */
export async function handleLogs(request: Request, env: Env): Promise<Response> {
  if (!env.DB) {
    return jsonResponse(
      { error: { message: "D1 not configured — request logs unavailable" } },
      503,
    );
  }
  const limitRaw = new URL(request.url).searchParams.get("limit");
  const limit = Math.min(500, Math.max(1, Number(limitRaw) || 50));
  try {
    const res = await env.DB.prepare(
      "SELECT id, ts, provider, model, status, latency_ms, stream, chain, attempt, error " +
        "FROM request_logs ORDER BY ts DESC LIMIT ?1",
    )
      .bind(limit)
      .all<Record<string, unknown>>();
    return jsonResponse({ logs: res.results });
  } catch {
    return jsonResponse({ error: { message: "D1 unavailable" } }, 503);
  }
}

/**
 * POST /admin/api/logs/prune {olderThanDays} — manual retention: deletes
 * request_logs rows older than N days (free tier has no cron on this plan's
 * budget; the console button keeps growth bounded).
 */
export async function handlePruneLogs(
  request: Request,
  env: Env,
): Promise<Response> {
  if (!env.DB) {
    return jsonResponse(
      { error: { message: "D1 not configured — nothing to prune" } },
      503,
    );
  }
  let body: { olderThanDays?: unknown };
  try {
    body = (await request.json()) as { olderThanDays?: unknown };
  } catch {
    return jsonResponse({ error: { message: "Invalid JSON body" } }, 400);
  }
  const days = body.olderThanDays;
  if (typeof days !== "number" || !Number.isFinite(days) || days < 1) {
    return jsonResponse(
      { error: { message: "Field 'olderThanDays' (number >= 1) is required" } },
      400,
    );
  }
  const cutoff = Date.now() - days * 24 * 60 * 60 * 1000;
  try {
    await env.DB.prepare("DELETE FROM request_logs WHERE ts < ?1")
      .bind(cutoff)
      .run();
  } catch {
    return jsonResponse({ error: { message: "D1 unavailable" } }, 503);
  }
  return jsonResponse({ ok: true, olderThanDays: days });
}

/**
 * GET /admin/api/stats — per-provider {requests, errors, avgLatencyMs} over the
 * last 7 days. status = 0 rows (never reached upstream) count as errors.
 */
export async function handleStats(env: Env): Promise<Response> {
  if (!env.DB) {
    return jsonResponse(
      { error: { message: "D1 not configured — stats unavailable" } },
      503,
    );
  }
  const since = Date.now() - SEVEN_DAYS_MS;
  try {
    const res = await env.DB.prepare(
      "SELECT provider, COUNT(*) AS requests, " +
        "SUM(CASE WHEN status >= 400 OR status = 0 THEN 1 ELSE 0 END) AS errors, " +
        'AVG(latency_ms) AS "avgLatencyMs" ' +
        "FROM request_logs WHERE ts >= ?1 GROUP BY provider ORDER BY requests DESC",
    )
      .bind(since)
      .all<Record<string, unknown>>();
    return jsonResponse({ stats: res.results });
  } catch {
    return jsonResponse({ error: { message: "D1 unavailable" } }, 503);
  }
}
