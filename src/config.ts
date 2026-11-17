import type { Env } from "./env";

export const SETTING_KEYS = {
  PROVIDERS_ENABLED: "providers_enabled",
  FALLBACK_CHAINS: "fallback_chains",
} as const;

/**
 * Read a runtime setting: D1 config table first, env var of the same name as
 * fallback. D1 errors and missing DB binding fall through to env (Global
 * Constraint: D1 must never break proxy traffic).
 */
export async function getSetting(env: Env, key: string): Promise<string | null> {
  try {
    if (env.DB) {
      const row = await env.DB.prepare("SELECT value FROM config WHERE key = ?1")
        .bind(key)
        .first<{ value: string }>();
      if (row && typeof row.value === "string") return row.value;
    }
  } catch {
    // D1 down/misconfigured → env fallback below.
  }
  const envValue = (env as unknown as Record<string, unknown>)[key];
  return typeof envValue === "string" ? envValue : null;
}

/**
 * Whether a D1 config row exists for `key` — even when its value is an empty
 * object like "{}" (the console can persist that, and it is real state).
 * Tolerant like getSetting: missing DB binding or D1 error → false.
 */
export async function hasSettingRow(env: Env, key: string): Promise<boolean> {
  if (!env.DB) return false;
  try {
    const row = await env.DB.prepare("SELECT value FROM config WHERE key = ?1")
      .bind(key)
      .first<{ value: string }>();
    return !!row && typeof row.value === "string";
  } catch {
    return false;
  }
}

export async function setSetting(env: Env, key: string, value: string): Promise<void> {
  if (!env.DB) throw new Error("DB binding not configured");
  await env.DB.prepare(
    "INSERT INTO config (key, value) VALUES (?1, ?2) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
  )
    .bind(key, value)
    .run();
}

/**
 * Parse the providers_enabled map ({prefix: boolean}). Missing/invalid → {}
 * (callers treat unknown as enabled — fail-open).
 */
export async function readEnabledMap(env: Env): Promise<Record<string, boolean>> {
  const raw = await getSetting(env, SETTING_KEYS.PROVIDERS_ENABLED);
  if (!raw) return {};
  try {
    const parsed: unknown = JSON.parse(raw);
    if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
      return parsed as Record<string, boolean>;
    }
  } catch {
    // invalid JSON → no config
  }
  return {};
}

/**
 * Strict read for ADMIN WRITE paths: unlike readEnabledMap, a missing DB
 * binding, a D1 error, or an invalid stored map THROWS. An admin
 * read-modify-write must never proceed on a degraded read — a failed read
 * followed by a successful write would persist a partial map and silently
 * wipe the other entries.
 */
export async function readEnabledMapStrict(
  env: Env,
): Promise<Record<string, boolean>> {
  if (!env.DB) throw new Error("DB binding not configured");
  const row = await env.DB.prepare("SELECT value FROM config WHERE key = ?1")
    .bind(SETTING_KEYS.PROVIDERS_ENABLED)
    .first<{ value: string }>();
  if (!row || typeof row.value !== "string") return {};
  const parsed: unknown = JSON.parse(row.value); // throws on invalid JSON
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error("providers_enabled is not a JSON object");
  }
  return parsed as Record<string, boolean>;
}
