import { describe, expect, it } from "vitest";
import { getPending, savePending } from "../src/oauth/store";
import { decryptToken, importAesKey } from "../src/oauth/crypto";
import type { Env } from "../src/env";

const KEY = btoa(String.fromCharCode(...new Uint8Array(32).fill(0x41)))
  .replace(/\+/g, "-")
  .replace(/\//g, "_")
  .replace(/=+$/, "");

function stubDb() {
  const pending = new Map<string, Record<string, unknown>>();
  const db = {
    prepare: (sql: string) => ({
      bind: (...params: unknown[]) => ({
        first: async <T,>() => {
          if (!sql.startsWith("SELECT")) return null;
          const row = pending.get(String(params[0]));
          return row ? (row as T) : null;
        },
        all: async <T,>() => ({ results: [] as unknown[] } as unknown as T),
        run: async () => {
          if (sql.startsWith("INSERT INTO oauth_pending")) {
            const [provider, mode, state, codeVerifier, deviceCode, extra, createdAt, expiresAt] =
              params as [string, ...unknown[]];
            pending.set(provider, {
              provider,
              mode,
              state: state ?? null,
              code_verifier: codeVerifier ?? null,
              device_code: deviceCode ?? null,
              extra: extra ?? null,
              created_at: createdAt,
              expires_at: expiresAt,
            });
          }
          if (sql.startsWith("DELETE FROM oauth_pending")) pending.delete(String(params[0]));
          return { success: true };
        },
      }),
    }),
  } as unknown as D1Database;
  return { db, pending };
}

function envWith(db: D1Database): Env {
  return { DB: db, OAUTH_ENCRYPTION_KEY: KEY } as unknown as Env;
}

async function decField(env: Env, stored: unknown): Promise<string | null> {
  if (typeof stored !== "string") return null;
  const key = await importAesKey(env);
  if (!key) throw new Error("test needs a usable OAUTH_ENCRYPTION_KEY");
  const bin = atob(stored.replace(/^enc:v1:/, ""));
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return decryptToken(key, bytes);
}

describe("pending state encryption at rest (RF-1)", () => {
  it("savePending stores NO plaintext sensitive columns — every sensitive TEXT column is enc:v1:", async () => {
    const { db, pending } = stubDb();
    const env = envWith(db);
    await savePending(env, {
      provider: "ghe-copilot",
      mode: "device",
      state: "st-secret-1",
      codeVerifier: "verifier-secret-2",
      deviceCode: "dc-secret-3",
      extra: { gheUrl: "https://ghe.acme.com" },
      ttlSec: 600,
    });
    const row = pending.get("ghe-copilot")!;
    const raw = JSON.stringify(row);
    expect(raw).not.toContain("st-secret-1");
    expect(raw).not.toContain("verifier-secret-2");
    expect(raw).not.toContain("dc-secret-3");
    expect(raw).not.toContain("ghe.acme.com");
    expect(String(row.state)).toMatch(/^enc:v1:/);
    expect(String(row.code_verifier)).toMatch(/^enc:v1:/);
    expect(String(row.device_code)).toMatch(/^enc:v1:/);
    expect(String(row.extra)).toMatch(/^enc:v1:/);
  });

  it("getPending returns the decrypted originals (state/verifier/deviceCode/extra)", async () => {
    const { db } = stubDb();
    const env = envWith(db);
    await savePending(env, {
      provider: "ghe-copilot",
      mode: "device",
      state: "st-1",
      codeVerifier: "vf-1",
      deviceCode: "dc-1",
      extra: { gheUrl: "https://ghe.acme.com" },
      ttlSec: 600,
    });
    const p = (await getPending(env, "ghe-copilot"))!;
    expect(p.state).toBe("st-1");
    expect(p.codeVerifier).toBe("vf-1");
    expect(p.deviceCode).toBe("dc-1");
    expect(p.extra).toEqual({ gheUrl: "https://ghe.acme.com" });
  });

  it("null fields stay null (never enc:v1: of empty)", async () => {
    const { db, pending } = stubDb();
    const env = envWith(db);
    await savePending(env, { provider: "kilocode", mode: "device", deviceCode: "dc-1", ttlSec: 900 });
    const row = pending.get("kilocode")!;
    expect(row.state).toBeNull();
    expect(row.code_verifier).toBeNull();
    expect(row.extra).toBeNull();
    expect(await decField(env, row.state)).toBeNull();
  });

  it("corrupt enc:v1: payload reads that field as null without throwing", async () => {
    const { db, pending } = stubDb();
    const env = envWith(db);
    await savePending(env, { provider: "kilocode", mode: "device", deviceCode: "dc-1", ttlSec: 900 });
    (pending.get("kilocode") as Record<string, unknown>).device_code = "enc:v1:garbage-not-base64!!";
    const p = (await getPending(env, "kilocode"))!;
    expect(p).not.toBeNull();
    expect(p!.deviceCode).toBeNull();
  });

  it("legacy plaintext rows (no enc:v1: prefix) stay readable", async () => {
    const { db, pending } = stubDb();
    const env = envWith(db);
    pending.set("legacy", {
      provider: "legacy",
      mode: "pkce",
      state: "plain-state",
      code_verifier: "plain-verifier",
      device_code: null,
      extra: null,
      created_at: Date.now(),
      expires_at: Date.now() + 60_000,
    });
    const p = (await getPending(env, "legacy"))!;
    expect(p.state).toBe("plain-state");
    expect(p.codeVerifier).toBe("plain-verifier");
  });

  it("upsert ON CONFLICT also updates extra (stale gheUrl/deviceId cannot survive)", async () => {
    const { db } = stubDb();
    const env = envWith(db);
    await savePending(env, {
      provider: "ghe-copilot",
      mode: "device",
      deviceCode: "dc-1",
      extra: { gheUrl: "https://old.acme.com" },
      ttlSec: 900,
    });
    await savePending(env, {
      provider: "ghe-copilot",
      mode: "device",
      deviceCode: "dc-2",
      extra: { gheUrl: "https://new.acme.com" },
      ttlSec: 900,
    });
    const p = (await getPending(env, "ghe-copilot"))!;
    expect(p.deviceCode).toBe("dc-2");
    expect(p.extra).toEqual({ gheUrl: "https://new.acme.com" });
  });
});
