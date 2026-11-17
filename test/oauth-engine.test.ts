import { beforeEach, describe, expect, it } from "vitest";
import {
  complete,
  disconnect,
  getAdapter,
  listAdapters,
  OAuthError,
  poll,
  registerAdapter,
  start,
  statusOf,
} from "../src/oauth/engine";
import { getToken } from "../src/oauth/store";
import { decryptToken, importAesKey } from "../src/oauth/crypto";
import type { Env } from "../src/env";
import type { OAuthAdapter, PollResult } from "../src/oauth/types";

const KEY = btoa(String.fromCharCode(...new Uint8Array(32).fill(0x41)))
  .replace(/\+/g, "-")
  .replace(/\//g, "_")
  .replace(/=+$/, "");

/** Compact D1 stub for engine tests (same pattern as test/oauth-store.test.ts). */
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

/** Decrypt one `enc:v1:` pending TEXT column back to its plaintext. */
async function decField(env: Env, stored: unknown): Promise<string | null> {
  if (typeof stored !== "string") return null;
  const key = await importAesKey(env);
  if (!key) throw new Error("test needs a usable OAUTH_ENCRYPTION_KEY");
  if (!stored.startsWith("enc:v1:")) return stored; // legacy plaintext
  const bin = atob(stored.slice("enc:v1:".length));
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return decryptToken(key, bytes);
}

const ORIGIN = "https://gw.test";

/** Mutable holder so each poll test can stage its own upstream outcome. */
const devicePoll: { result: PollResult } = {
  result: { ok: false, data: { error: "authorization_pending" } },
};

function pasteFake(): OAuthAdapter {
  return {
    prefix: "fakepaste",
    flowMode: "paste",
    config: {},
    instructions: "Paste the fake token.",
    importToken: async (raw) => {
      const token = raw.access_token;
      if (typeof token !== "string" || !token.trim()) throw new Error("Token is empty");
      return { access_token: token };
    },
    mapTokens: (tokens) => ({
      accessToken: String(tokens.access_token),
      expiresIn: 120,
      email: "fake@x.com",
      meta: { fake: true },
    }),
  };
}

function codeFake(): OAuthAdapter {
  return {
    prefix: "fakecode",
    flowMode: "paste-code",
    config: { authorizeUrl: "https://up.test/authorize" },
    buildAuthUrl: (config, redirectUri, state, challenge) =>
      `${config.authorizeUrl}?redirect_uri=${encodeURIComponent(redirectUri)}&state=${state}&challenge=${challenge}`,
    exchangeToken: async () => ({
      access_token: "code-at",
      refresh_token: "code-rt",
      email: "code@x.com",
    }),
    mapTokens: (tokens) => ({
      accessToken: String(tokens.access_token),
      refreshToken: (tokens.refresh_token as string) ?? null,
      expiresIn: 600,
      email: (tokens.email as string) ?? null,
    }),
  };
}

function deviceFake(): OAuthAdapter {
  return {
    prefix: "fakedevice",
    flowMode: "device",
    config: {},
    requestDeviceCode: async () => ({
      device_code: "dc-1",
      user_code: "ABCD-1234",
      verification_uri: "https://up.test/verify",
      expires_in: 300,
      interval: 5,
    }),
    pollToken: async () => devicePoll.result,
    mapTokens: (tokens) => ({
      accessToken: String(tokens.access_token),
      expiresIn: 300,
      name: "Fake Device",
    }),
  };
}

beforeEach(() => {
  devicePoll.result = { ok: false, data: { error: "authorization_pending" } };
  registerAdapter(pasteFake());
  registerAdapter(codeFake());
  registerAdapter(deviceFake());
});

describe("engine start", () => {
  it("paste returns instructions", async () => {
    const env = envWith(stubDb().db);
    const res = await start(env, "fakepaste", new URL(`${ORIGIN}/x`));
    expect(res).toEqual({ mode: "paste", instructions: "Paste the fake token." });
  });

  it("paste falls back to default instructions", async () => {
    registerAdapter(pasteFake());
    // adapter without instructions
    const bare = pasteFake();
    delete bare.instructions;
    registerAdapter(bare);
    const env = envWith(stubDb().db);
    const res = await start(env, "fakepaste", new URL(`${ORIGIN}/x`));
    expect(res).toEqual({ mode: "paste", instructions: "Paste the provider token." });
  });

  it("paste-code stores a pkce pending and builds the auth url", async () => {
    const { db, pending } = stubDb();
    const env = envWith(db);
    const res = await start(env, "fakecode", new URL(`${ORIGIN}/x`));
    expect(res.mode).toBe("paste-code");
    if (res.mode !== "paste-code") return;
    expect(res.authUrl).toContain(`redirect_uri=${encodeURIComponent(`${ORIGIN}/admin/oauth/fakecode/callback`)}`);
    expect(res.authUrl).toContain(`state=${res.state}`);
    const row = pending.get("fakecode")!;
    expect(row.mode).toBe("pkce");
    // Pending sensitive columns are encrypted at rest — decrypt to assert.
    expect(await decField(env, row.state)).toBe(res.state);
    const verifier = await decField(env, row.code_verifier);
    expect(verifier).toMatch(/^[A-Za-z0-9_-]+$/);
  });

  it("paste-code without buildAuthUrl/exchangeToken → 400", async () => {
    registerAdapter(codeFake());
    const broken = codeFake();
    delete broken.buildAuthUrl;
    registerAdapter(broken);
    const env = envWith(stubDb().db);
    await expect(start(env, "fakecode", new URL(`${ORIGIN}/x`))).rejects.toThrow(
      /does not support paste-code/,
    );
  });

  it("device stores the device code pending and returns the verify shape", async () => {
    const { db, pending } = stubDb();
    const env = envWith(db);
    const res = await start(env, "fakedevice", new URL(`${ORIGIN}/x`));
    expect(res).toEqual({
      mode: "device",
      user_code: "ABCD-1234",
      verification_uri: "https://up.test/verify",
      verification_uri_complete: "https://up.test/verify",
      expires_in: 300,
      interval: 5,
    });
    expect(await decField(env, pending.get("fakedevice")!.device_code)).toBe("dc-1");
  });

  it("device without requestDeviceCode → 400", async () => {
    registerAdapter(deviceFake());
    const broken = deviceFake();
    delete broken.requestDeviceCode;
    registerAdapter(broken);
    const env = envWith(stubDb().db);
    await expect(start(env, "fakedevice", new URL(`${ORIGIN}/x`))).rejects.toThrow(
      /does not support device/,
    );
  });

  it("unknown prefix → 404 OAuthError on every engine function", async () => {
    const env = envWith(stubDb().db);
    const url = new URL(`${ORIGIN}/x`);
    const errs = await Promise.all([
      start(env, "nope", url).catch((e) => e),
      complete(env, "nope", { token: "t" }).catch((e) => e),
      poll(env, "nope").catch((e) => e),
      statusOf(env, "nope").catch((e) => e),
      disconnect(env, "nope").catch((e) => e),
    ]);
    for (const err of errs) {
      expect(err).toBeInstanceOf(OAuthError);
      expect(err.message).toBe("Unknown OAuth provider: nope");
      expect(err.status).toBe(404);
    }
  });
});

describe("engine complete: paste", () => {
  it("token paste → encrypted row written (authKind paste)", async () => {
    const { db } = stubDb();
    const env = envWith(db);
    const res = await complete(env, "fakepaste", { token: "sk-pasted" });
    expect(res.connected).toBe(true);
    expect(res.accountLabel).toBe("fake@x.com");
    const row = (await getToken(env, "fakepaste"))!;
    expect(row.accessToken).toBe("sk-pasted");
    expect(row.authKind).toBe("paste");
    expect(row.expiresAt).toBeGreaterThan(Date.now());
    expect(row.meta).toEqual({ fake: true });
  });

  it("blob paste decodes and writes the row", async () => {
    const { db } = stubDb();
    const env = envWith(db);
    const blob = blobFor("fakepaste", { access_token: "blob-at" });
    const res = await complete(env, "fakepaste", { blob });
    expect(res.connected).toBe(true);
    expect((await getToken(env, "fakepaste"))!.accessToken).toBe("blob-at");
  });

  it("blob for another provider → 400, no row", async () => {
    const { db } = stubDb();
    const env = envWith(db);
    await expect(complete(env, "fakepaste", { blob: blobFor("other", { access_token: "x" }) })).rejects.toThrow(
      /blob is for other/,
    );
    expect(await getToken(env, "fakepaste")).toBeNull();
  });

  it("importToken throw → 400, no row written", async () => {
    const { db } = stubDb();
    const env = envWith(db);
    await expect(complete(env, "fakepaste", { token: "" })).rejects.toThrow("Token is empty");
    expect(await getToken(env, "fakepaste")).toBeNull();
  });

  it("neither token nor blob → 400 with the pinned message", async () => {
    const { db } = stubDb();
    const env = envWith(db);
    await expect(complete(env, "fakepaste", {})).rejects.toThrow("paste a token or blob");
  });

  it("pasted token is trimmed (header copies carry whitespace/newlines)", async () => {
    const { db } = stubDb();
    const env = envWith(db);
    await complete(env, "fakepaste", { token: "  pad-at\n" });
    expect((await getToken(env, "fakepaste"))!.accessToken).toBe("pad-at");
  });
});

function blobFor(provider: string, tokens: Record<string, unknown>): string {
  return (
    "freeai-cred-v1." +
    btoa(JSON.stringify({ v: 1, provider, tokens }))
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "")
  );
}

describe("engine complete: paste-code", () => {
  it("happy path: row written, pending consumed (single-use)", async () => {
    const { db, pending } = stubDb();
    const env = envWith(db);
    await start(env, "fakecode", new URL(`${ORIGIN}/x`));
    const res = await complete(env, "fakecode", { code: "the-code" }, new URL(`${ORIGIN}/x`));
    expect(res.connected).toBe(true);
    const row = (await getToken(env, "fakecode"))!;
    expect(row.accessToken).toBe("code-at");
    expect(row.refreshToken).toBe("code-rt");
    expect(row.authKind).toBe("oauth");
    expect(pending.has("fakecode")).toBe(false);
  });

  it("no pending → 410 login flow expired", async () => {
    const { db } = stubDb();
    const env = envWith(db);
    await expect(
      complete(env, "fakecode", { code: "c" }, new URL(`${ORIGIN}/x`)),
    ).rejects.toThrow("login flow expired — start again");
  });

  it("expired pending → 410", async () => {
    const { db, pending } = stubDb();
    const env = envWith(db);
    await start(env, "fakecode", new URL(`${ORIGIN}/x`));
    (pending.get("fakecode") as Record<string, unknown>).expires_at = Date.now() - 1;
    await expect(
      complete(env, "fakecode", { code: "c" }, new URL(`${ORIGIN}/x`)),
    ).rejects.toThrow("login flow expired — start again");
  });

  it("exchangeToken throw → 400, pending kept", async () => {
    const { db, pending } = stubDb();
    const env = envWith(db);
    await start(env, "fakecode", new URL(`${ORIGIN}/x`));
    const failing = codeFake();
    failing.exchangeToken = async () => {
      throw new Error("upstream said no");
    };
    registerAdapter(failing);
    await expect(
      complete(env, "fakecode", { code: "c" }, new URL(`${ORIGIN}/x`)),
    ).rejects.toThrow("upstream said no");
    expect(pending.has("fakecode")).toBe(true);
  });
});

describe("engine poll: device", () => {
  it("authorization_pending → {status: pending}", async () => {
    const { db, pending } = stubDb();
    const env = envWith(db);
    await start(env, "fakedevice", new URL(`${ORIGIN}/x`));
    const res = await poll(env, "fakedevice");
    expect(res.status).toBe("pending");
    expect(pending.has("fakedevice")).toBe(true);
  });

  it("slow_down → {status: pending}", async () => {
    const { db } = stubDb();
    const env = envWith(db);
    await start(env, "fakedevice", new URL(`${ORIGIN}/x`));
    devicePoll.result = { ok: false, data: { error: "slow_down" } };
    expect((await poll(env, "fakedevice")).status).toBe("pending");
  });

  it("success → row written (authKind oauth), pending consumed, connected", async () => {
    const { db, pending } = stubDb();
    const env = envWith(db);
    await start(env, "fakedevice", new URL(`${ORIGIN}/x`));
    devicePoll.result = { ok: true, data: { access_token: "dev-at" } };
    const res = await poll(env, "fakedevice");
    expect(res.status).toBe("connected");
    const row = (await getToken(env, "fakedevice"))!;
    expect(row.accessToken).toBe("dev-at");
    expect(row.authKind).toBe("oauth");
    expect(row.accountLabel).toBe("Fake Device");
    expect(pending.has("fakedevice")).toBe(false);
  });

  it("terminal error (access_denied) deletes pending", async () => {
    const { db, pending } = stubDb();
    const env = envWith(db);
    await start(env, "fakedevice", new URL(`${ORIGIN}/x`));
    devicePoll.result = { ok: false, data: { error: "access_denied", error_description: "denied" } };
    const res = await poll(env, "fakedevice");
    expect(res.status).toBe("error");
    expect(res.error).toBe("access_denied");
    expect(pending.has("fakedevice")).toBe(false);
  });

  it("ok without access_token → error path", async () => {
    const { db, pending } = stubDb();
    const env = envWith(db);
    await start(env, "fakedevice", new URL(`${ORIGIN}/x`));
    devicePoll.result = { ok: true, data: {} };
    const res = await poll(env, "fakedevice");
    expect(res.status).toBe("error");
    expect(pending.has("fakedevice")).toBe(true);
  });

  it("adapter throw → {status: error}, pending KEPT (retryable)", async () => {
    const { db, pending } = stubDb();
    const env = envWith(db);
    await start(env, "fakedevice", new URL(`${ORIGIN}/x`));
    const flaky = deviceFake();
    flaky.pollToken = async () => {
      throw new Error("network gone");
    };
    registerAdapter(flaky);
    const res = await poll(env, "fakedevice");
    expect(res.status).toBe("error");
    expect(res.error).toContain("network gone");
    expect(pending.has("fakedevice")).toBe(true);
  });

  it("no pending → {status: error, error: expired}", async () => {
    const { db } = stubDb();
    const env = envWith(db);
    expect(await poll(env, "fakedevice")).toEqual({ status: "error", error: "expired" });
  });
});

describe("engine status + disconnect + registry", () => {
  it("statusOf reflects the store; flowMode from the adapter", async () => {
    const { db } = stubDb();
    const env = envWith(db);
    await complete(env, "fakepaste", { token: "sk-pasted" });
    const s = await statusOf(env, "fakepaste");
    expect(s.connected).toBe(true);
    expect(s.flowMode).toBe("paste");
    expect(s.accountLabel).toBe("fake@x.com");
  });

  it("disconnect clears token + pending", async () => {
    const { db } = stubDb();
    const env = envWith(db);
    await complete(env, "fakepaste", { token: "sk-pasted" });
    await disconnect(env, "fakepaste");
    expect(await getToken(env, "fakepaste")).toBeNull();
  });

  it("getAdapter + listAdapters", () => {
    expect(getAdapter("fakepaste")?.prefix).toBe("fakepaste");
    expect(getAdapter("missing")).toBeNull();
    const prefixes = listAdapters().map((a) => a.prefix);
    expect(prefixes).toContain("fakepaste");
    expect([...prefixes].sort()).toEqual(prefixes);
  });
});
