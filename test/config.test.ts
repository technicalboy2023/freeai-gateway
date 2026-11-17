import { describe, expect, it } from "vitest";
import { getSetting, setSetting, SETTING_KEYS } from "../src/config";
import type { Env } from "../src/env";

/** Minimal D1Database stub: captures prepared SQL + bind params, serves rows for SELECTs. */
function stubDb(rows: Record<string, string>, failQuery = false) {
  const runCalls: Array<{ sql: string; params: unknown[] }> = [];
  const db = {
    prepare: (sql: string) => ({
      bind: (...params: unknown[]) => ({
        first: async <T,>() => {
          if (failQuery) throw new Error("d1 unavailable");
          if (!sql.startsWith("SELECT")) return null;
          const key = params[0] as string;
          return key in rows ? ({ value: rows[key] } as T) : null;
        },
        run: async () => {
          runCalls.push({ sql, params });
          return { success: true };
        },
      }),
    }),
  } as unknown as D1Database;
  return { db, runCalls };
}

describe("config store (D1 + env fallback)", () => {
  it("returns the D1 value when the row exists", async () => {
    const { db } = stubDb({ providers_enabled: '{"nvidia":false}' });
    const env = { DB: db } as unknown as Env;
    expect(await getSetting(env, SETTING_KEYS.PROVIDERS_ENABLED)).toBe('{"nvidia":false}');
  });

  it("falls back to env var of the same name when D1 has no row", async () => {
    const { db } = stubDb({});
    const env = { DB: db, fallback_chains: '{"fast":["groq"]}' } as unknown as Env;
    expect(await getSetting(env, SETTING_KEYS.FALLBACK_CHAINS)).toBe('{"fast":["groq"]}');
  });

  it("falls back to env var when the DB binding is absent", async () => {
    const env = { fallback_chains: '{"fast":["groq"]}' } as unknown as Env;
    expect(await getSetting(env, SETTING_KEYS.FALLBACK_CHAINS)).toBe('{"fast":["groq"]}');
  });

  it("returns null when neither D1 nor env has a value", async () => {
    const { db } = stubDb({});
    expect(await getSetting({ DB: db } as unknown as Env, "nothing_here")).toBeNull();
  });

  it("falls back to env when D1 errors (D1 must never break the proxy)", async () => {
    const { db } = stubDb({}, true);
    const env = { DB: db, providers_enabled: '{"groq":true}' } as unknown as Env;
    expect(await getSetting(env, SETTING_KEYS.PROVIDERS_ENABLED)).toBe('{"groq":true}');
  });

  it("setSetting issues an upsert with key and value params", async () => {
    const { db, runCalls } = stubDb({});
    await setSetting({ DB: db } as unknown as Env, SETTING_KEYS.FALLBACK_CHAINS, '{"fast":["gemini"]}');
    expect(runCalls).toHaveLength(1);
    const call = runCalls[0];
    expect(call.sql).toContain("INSERT INTO config");
    expect(call.sql).toContain("ON CONFLICT(key) DO UPDATE");
    expect(call.params).toEqual([SETTING_KEYS.FALLBACK_CHAINS, '{"fast":["gemini"]}']);
  });

  it("SETTING_KEYS exposes the two console settings", () => {
    expect(SETTING_KEYS.PROVIDERS_ENABLED).toBe("providers_enabled");
    expect(SETTING_KEYS.FALLBACK_CHAINS).toBe("fallback_chains");
  });
});
