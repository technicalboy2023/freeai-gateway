import { beforeEach, describe, expect, it } from "vitest";
import { complete, poll, registerAdapter, start } from "../src/oauth/engine";
import { ensureFreshToken } from "../src/oauth/refresh";
import { getPending, savePending, saveToken } from "../src/oauth/store";
import { decryptToken, importAesKey } from "../src/oauth/crypto";
import { deriveChallenge } from "../src/oauth/pkce";
import type { Env } from "../src/env";
import type { OAuthAdapter, PollResult, RawTokens } from "../src/oauth/types";

const KEY = btoa(String.fromCharCode(...new Uint8Array(32).fill(0x41)))
  .replace(/\+/g, "-")
  .replace(/\//g, "_")
  .replace(/=+$/, "");

/** Compact D1 stub — same pattern as test/oauth-engine.test.ts, plus the extra column. */
function stubDb() {
  const tokens = new Map<string, Record<string, unknown>>();
  const pending = new Map<string, Record<string, unknown>>();
  const db = {
    prepare: (sql: string) => ({
      bind: (...params: unknown[]) => ({
        first: async <T,>() => {
          if (!sql.startsWith("SELECT")) return null;
          const map = sql.includes("oauth_pending") ? pending : tokens;
          const row = map.get(String(params[0]));
          return row ? (row as T) : null;
        },
        all: async <T,>() => ({ results: [] as unknown[] } as unknown as T),
        run: async () => {
          if (sql.startsWith("INSERT INTO oauth_tokens")) {
            const [provider, access, refresh, expiresAt, label, meta, authKind, connectedAt] =
              params as [string, ...unknown[]];
            tokens.set(provider, {
              provider,
              access_token: access,
              refresh_token: refresh ?? null,
              expires_at: expiresAt ?? null,
              account_label: label ?? null,
              meta: meta ?? null,
              auth_kind: authKind,
              connected_at: connectedAt,
              last_refresh_at: null,
              last_error: null,
            });
          }
          if (sql.startsWith("UPDATE oauth_tokens")) {
            const row = tokens.get(String(params[1]));
            if (row) row.last_error = params[0];
          }
          if (sql.startsWith("DELETE FROM oauth_tokens")) tokens.delete(String(params[0]));
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
  return { db, tokens, pending };
}

function envWith(db: D1Database): Env {
  return { DB: db, OAUTH_ENCRYPTION_KEY: KEY } as unknown as Env;
}

const ORIGIN = "https://gw.test";

/** Decrypt one `enc:v1:` pending TEXT column back to its plaintext. */
async function decPending(env: Env, stored: unknown): Promise<string | null> {
  if (typeof stored !== "string") return null;
  const key = await importAesKey(env);
  if (!key) throw new Error("test needs a usable OAUTH_ENCRYPTION_KEY");
  const bin = atob(stored.replace(/^enc:v1:/, ""));
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return decryptToken(key, bytes);
}

/** Decrypt + JSON.parse a pending `extra` column. */
async function decExtra(env: Env, stored: unknown): Promise<Record<string, unknown> | null> {
  const raw = await decPending(env, stored);
  if (raw == null) return null;
  try {
    const parsed: unknown = JSON.parse(raw);
    return parsed && typeof parsed === "object" && !Array.isArray(parsed)
      ? (parsed as Record<string, unknown>)
      : null;
  } catch {
    return null;
  }
}

const devicePoll: { result: PollResult } = {
  result: { ok: false, data: { error: "authorization_pending" } },
};
const captured: {
  start?: unknown[];
  poll?: unknown[];
  map?: unknown[];
  refresh?: unknown[];
} = {};

function extDeviceFake(overrides: Partial<OAuthAdapter> = {}): OAuthAdapter {
  return {
    prefix: "ext-device",
    flowMode: "device",
    config: { issuer: "up.test" },
    requestDeviceCode: async (config, challenge, startParams) => {
      captured.start = [config, challenge, startParams];
      return {
        device_code: "dc-1",
        user_code: "ABCD-1234",
        verification_uri: "https://up.test/verify",
        expires_in: 300,
        interval: 5,
      };
    },
    pollToken: async (config, deviceCode, verifier, startParams) => {
      captured.poll = [config, deviceCode, verifier, startParams];
      return devicePoll.result;
    },
    mapTokens: (tokens, extra, priorMeta) => {
      captured.map = [tokens, extra, priorMeta];
      return { accessToken: String(tokens.access_token), expiresIn: 300 };
    },
    ...overrides,
  } as OAuthAdapter;
}

function extCodeFake(): OAuthAdapter {
  return {
    prefix: "ext-code",
    flowMode: "paste-code",
    config: { authorizeUrl: "https://up.test/authorize" },
    buildAuthUrl: (config, redirectUri, state, challenge) =>
      `${String(config.authorizeUrl)}?redirect_uri=${encodeURIComponent(redirectUri)}&state=${state}&challenge=${challenge}`,
    exchangeToken: async () => ({
      access_token: "code-at",
      refresh_token: "code-rt",
    }),
    postExchange: async (tokens, startParams) => ({ px: true, from: startParams ?? null }),
    mapTokens: (tokens, extra, priorMeta) => {
      captured.map = [tokens, extra, priorMeta];
      return { accessToken: String(tokens.access_token), expiresIn: 600 };
    },
  } as OAuthAdapter;
}

beforeEach(() => {
  devicePoll.result = { ok: false, data: { error: "authorization_pending" } };
  captured.start = undefined;
  captured.poll = undefined;
  captured.map = undefined;
  captured.refresh = undefined;
});

describe("engine extensions — start/poll threading", () => {
  it("(a) parseStartParams result reaches requestDeviceCode (3rd arg) and pollToken (4th arg)", async () => {
    const { db } = stubDb();
    const env = envWith(db);
    registerAdapter(
      extDeviceFake({
        parseStartParams: (url) => {
          const gheUrl = url.searchParams.get("gheUrl");
          return gheUrl ? { gheUrl } : undefined;
        },
      }),
    );
    await start(env, "ext-device", new URL(`${ORIGIN}/start?gheUrl=https://ghe.acme.com`));
    expect(captured.start![2]).toEqual({ gheUrl: "https://ghe.acme.com" });
    await poll(env, "ext-device");
    expect(captured.poll![3]).toEqual({ gheUrl: "https://ghe.acme.com" });
  });

  it("(b) device start passes an S256 challenge (2nd arg); poll's verifier arg is the pair's twin (RF-4)", async () => {
    const { db } = stubDb();
    const env = envWith(db);
    registerAdapter(extDeviceFake());
    await start(env, "ext-device", new URL(`${ORIGIN}/x`));
    const challenge = String(captured.start![1]);
    expect(challenge).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(captured.start![2]).toBeUndefined();
    await poll(env, "ext-device");
    // The poll arg is the VERIFIER of the same pair — S256(verifier) === challenge.
    const verifier = String(captured.poll![2]);
    expect(await deriveChallenge(verifier)).toBe(challenge);
  });

  it("(c) postExchange result reaches mapTokens as extra on device poll success", async () => {
    const { db } = stubDb();
    const env = envWith(db);
    devicePoll.result = { ok: true, data: { access_token: "at-1" } };
    registerAdapter(
      extDeviceFake({ postExchange: async (tokens, startParams) => ({ px: true, from: startParams ?? null }) }),
    );
    await start(env, "ext-device", new URL(`${ORIGIN}/x`));
    await poll(env, "ext-device");
    expect(captured.map![1]).toEqual({ px: true, from: null });
  });

  it("(c) postExchange result reaches mapTokens as extra on paste-code complete", async () => {
    const { db } = stubDb();
    const env = envWith(db);
    registerAdapter(extCodeFake());
    await start(env, "ext-code", new URL(`${ORIGIN}/x`));
    await complete(env, "ext-code", { code: "abc" }, new URL(`${ORIGIN}/x`));
    expect(captured.map![1]).toEqual({ px: true, from: null });
  });

  it("(c2) pending.extra threads into mapTokens as extra when the adapter has no postExchange", async () => {
    const { db } = stubDb();
    const env = envWith(db);
    devicePoll.result = { ok: true, data: { access_token: "at-1" } };
    registerAdapter(extDeviceFake()); // no postExchange
    await savePending(env, {
      provider: "ext-device",
      mode: "device",
      deviceCode: "dc-1",
      ttlSec: 900,
      extra: { gheUrl: "https://ghe.x" },
    });
    await poll(env, "ext-device");
    expect(captured.map![1]).toEqual({ gheUrl: "https://ghe.x" });
  });

  it("(d) refresh calls adapter.refresh(config, refreshToken, row.meta) and mapTokens(raw, undefined, row.meta)", async () => {
    const { db, tokens } = stubDb();
    const env = envWith(db);
    registerAdapter({
      prefix: "ext-refresh",
      flowMode: "paste",
      config: {},
      refresh: async (config: OAuthAdapter["config"], refreshToken: string, meta?: Record<string, unknown>) => {
        captured.refresh = [config, refreshToken, meta];
        return { access_token: "new-at", refresh_token: "new-rt", expires_in: 3600 };
      },
      mapTokens: (tokens: RawTokens, extra?: Record<string, unknown>, priorMeta?: Record<string, unknown>) => {
        captured.map = [tokens, extra, priorMeta];
        return {
          accessToken: String(tokens.access_token),
          expiresIn: (tokens.expires_in as number) ?? undefined,
          meta: priorMeta ?? undefined,
        };
      },
    } as unknown as OAuthAdapter);
    await saveToken(env, {
      provider: "ext-refresh",
      accessToken: "old-at",
      refreshToken: "rt-1",
      expiresIn: 60, // inside the 300s skew → refresh path
      meta: { keep: "me" },
      authKind: "oauth",
    });
    const at = await ensureFreshToken(env, "ext-refresh");
    expect(at).toBe("new-at");
    expect(captured.refresh![1]).toBe("rt-1");
    expect(captured.refresh![2]).toEqual({ keep: "me" });
    expect(captured.map![1]).toBeUndefined();
    expect(captured.map![2]).toEqual({ keep: "me" });
    // merged row: new tokens, preserved meta
    const stored = tokens.get("ext-refresh")!;
    expect(stored.expires_at).toBeGreaterThan(Date.now() + 300_000);
  });

  it("(e) DeviceCodeResponse.device_id lands in pending extras as deviceId (after startParams)", async () => {
    const { db, pending } = stubDb();
    const env = envWith(db);
    registerAdapter(
      extDeviceFake({
        parseStartParams: () => ({ gheUrl: "https://ghe.acme.com" }),
        requestDeviceCode: async () => ({
          device_code: "dc-1",
          user_code: "ABCD-1234",
          verification_uri: "https://up.test/verify",
          expires_in: 300,
          interval: 5,
          device_id: "dev-1",
        }),
      }),
    );
    await start(env, "ext-device", new URL(`${ORIGIN}/x`));
    const row = pending.get("ext-device")!;
    expect(await decExtra(env, row.extra)).toEqual({
      gheUrl: "https://ghe.acme.com",
      deviceId: "dev-1",
    });
  });

  it("(e2) device pending TTL clamps to the upstream expires_in (min 60, max 1800, default 900)", async () => {
    const { db, pending } = stubDb();
    const env = envWith(db);
    registerAdapter(
      extDeviceFake({
        requestDeviceCode: async () => ({
          device_code: "dc-1",
          user_code: "ABCD-1234",
          verification_uri: "https://up.test/verify",
          expires_in: 1800,
          interval: 5,
        }),
      }),
    );
    await start(env, "ext-device", new URL(`${ORIGIN}/x`));
    let row = pending.get("ext-device")!;
    expect(Number(row.expires_at) - Number(row.created_at)).toBe(1800_000);

    registerAdapter(
      extDeviceFake({
        requestDeviceCode: async () => ({
          device_code: "dc-2",
          user_code: "ABCD-1234",
          verification_uri: "https://up.test/verify",
          expires_in: 0,
          interval: 5,
        }),
      }),
    );
    await start(env, "ext-device", new URL(`${ORIGIN}/x`));
    row = pending.get("ext-device")!;
    expect(Number(row.expires_at) - Number(row.created_at)).toBe(900_000);
  });
});
