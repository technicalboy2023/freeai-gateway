import { describe, expect, it } from "vitest";
import {
  deletePending,
  deleteToken,
  getPending,
  getToken,
  getTokenStatus,
  savePending,
  saveToken,
} from "../src/oauth/store";
import type { Env } from "../src/env";

const KEY = btoa(String.fromCharCode(...new Uint8Array(32).fill(0x41)))
  .replace(/\+/g, "-")
  .replace(/\//g, "_")
  .replace(/=+$/, "");

/** Hand-rolled D1 stub for oauth_tokens/oauth_pending (stubDb pattern of admin-ops.test.ts). */
function stubDb() {
  const tokens = new Map<string, Record<string, unknown>>();
  const pending = new Map<string, Record<string, unknown>>();
  const raceNextTokenRead = { provider: null as string | null };
  const db = {
    prepare: (sql: string) => ({
      bind: (...params: unknown[]) => ({
        first: async <T,>() => {
          if (!sql.startsWith("SELECT")) return null;
          const key = String(params[0]);
          const map = sql.includes("oauth_pending") ? pending : tokens;
          const row = map.get(key);
          if (!row) return null;
          const snapshot = { ...row };
          if (!sql.includes("oauth_pending") && raceNextTokenRead.provider === key) {
            raceNextTokenRead.provider = null;
            row.meta = JSON.stringify({ githubLogin: "concurrent-update" });
            row.provider_secrets = null;
          }
          return snapshot as T;
        },
        all: async <T,>() => ({ results: [] as unknown[] } as unknown as T),
        run: async () => {
          if (sql.startsWith("INSERT INTO oauth_tokens")) {
            const [provider, access, refresh, expiresAt, label, meta, ...rest] = params;
            const [authKind, connectedAt, lastRefreshAt, providerSecrets] = rest;
            tokens.set(String(provider), {
              provider,
              access_token: access,
              refresh_token: refresh ?? null,
              expires_at: expiresAt ?? null,
              account_label: label ?? null,
              meta: meta ?? null,
              provider_secrets: providerSecrets ?? null,
              auth_kind: authKind,
              connected_at: connectedAt,
              last_refresh_at: lastRefreshAt ?? null,
              last_error: null,
            });
          }
          if (sql.startsWith("UPDATE oauth_tokens") && sql.includes("SET meta =")) {
            const row = tokens.get(String(params[2]));
            if (
              row &&
              row.meta === params[3] &&
              (row.provider_secrets ?? null) === (params[4] ?? null)
            ) {
              row.meta = params[0];
              if (sql.includes("last_error = ?2")) {
                row.last_error = params[1];
              } else {
                row.provider_secrets = params[1];
              }
            }
          }
          if (sql.startsWith("UPDATE oauth_tokens SET last_error")) {
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
  return { db, tokens, pending, raceNextTokenRead };
}

function envWith(db: D1Database): Env {
  return { DB: db, OAUTH_ENCRYPTION_KEY: KEY } as unknown as Env;
}

describe("oauth token store", () => {
  it("roundtrips save → getToken with decrypted values + parsed meta", async () => {
    const { db } = stubDb();
    const env = envWith(db);
    await saveToken(env, {
      provider: "trae",
      accessToken: "sk-at-1",
      refreshToken: "sk-rt-1",
      expiresIn: 120,
      email: "a@x.com",
      name: "Ankush",
      meta: { webId: "w1", region: "US-East" },
      authKind: "paste",
    });
    const row = await getToken(env, "trae");
    expect(row).not.toBeNull();
    expect(row!.accessToken).toBe("sk-at-1");
    expect(row!.refreshToken).toBe("sk-rt-1");
    expect(row!.authKind).toBe("paste");
    expect(row!.accountLabel).toBe("Ankush");
    expect(row!.meta).toEqual({ webId: "w1", region: "US-East" });
    expect(row!.expiresAt).toBeGreaterThan(Date.now());
    expect(row!.connectedAt).toBeLessThanOrEqual(Date.now());
  });

  it("stored blobs never contain the plaintext", async () => {
    const { db, tokens } = stubDb();
    const env = envWith(db);
    await saveToken(env, { provider: "trae", accessToken: "sk-visible-secret", authKind: "paste" });
    const raw = tokens.get("trae")!;
    expect(String(raw.access_token)).not.toContain("sk-visible-secret");
  });

  it("encrypts provider secrets separately from readable non-secret metadata", async () => {
    const { db, tokens } = stubDb();
    const env = envWith(db);
    const copilotToken = "ghu-copilot-sensitive-value";
    await saveToken(
      env,
      Object.assign(
        {
          provider: "github",
          accessToken: "github-at",
          refreshToken: "github-rt",
          meta: { githubLogin: "octo" },
          authKind: "oauth",
        },
        { secrets: { copilotToken } },
      ),
    );

    const raw = tokens.get("github")!;
    expect(raw.meta).toBe(JSON.stringify({ githubLogin: "octo" }));
    expect(raw.provider_secrets).toBeInstanceOf(Uint8Array);
    expect(JSON.stringify(raw)).not.toContain(copilotToken);
    expect(await getToken(env, "github")).toMatchObject({
      meta: { githubLogin: "octo" },
      secrets: { copilotToken },
    });
  });

  it("scrubs legacy token values from meta on token and status reads", async () => {
    const { db, tokens } = stubDb();
    const env = envWith(db);
    const copilotToken = "legacy-copilot-secret";
    const dcaToken = "dca:legacy-durable";

    await saveToken(env, {
      provider: "legacy-github",
      accessToken: "legacy-gh-at",
      refreshToken: "legacy-gh-rt",
      authKind: "oauth",
      meta: { githubLogin: "legacy-octo" },
    });
    const githubRaw = tokens.get("legacy-github")!;
    githubRaw.meta = JSON.stringify({ githubLogin: "legacy-octo", copilotToken });
    githubRaw.provider_secrets = null;

    await saveToken(env, {
      provider: "legacy-muse",
      accessToken: "legacy-muse-at",
      refreshToken: dcaToken,
      authKind: "oauth",
      meta: { accountName: "Legacy Muse" },
    });
    const museRaw = tokens.get("legacy-muse")!;
    museRaw.meta = JSON.stringify({ accountName: "Legacy Muse", dcaToken });
    museRaw.provider_secrets = null;

    expect(await getToken(env, "legacy-github")).toMatchObject({
      meta: { githubLogin: "legacy-octo" },
      secrets: { copilotToken },
    });
    expect(await getTokenStatus(env, "legacy-muse")).toMatchObject({ connected: true });
    expect(githubRaw.meta).toBe(JSON.stringify({ githubLogin: "legacy-octo" }));
    expect(githubRaw.provider_secrets).toBeInstanceOf(Uint8Array);
    expect(museRaw.meta).toBe(JSON.stringify({ accountName: "Legacy Muse" }));
    expect(JSON.stringify(githubRaw)).not.toContain(copilotToken);
    expect(JSON.stringify(museRaw)).not.toContain(dcaToken);

    await saveToken(env, {
      provider: "legacy-status-github",
      accessToken: "legacy-status-gh-at",
      authKind: "oauth",
      meta: { githubLogin: "status-octo" },
    });
    const statusRaw = tokens.get("legacy-status-github")!;
    statusRaw.meta = JSON.stringify({ githubLogin: "status-octo", copilotToken: "status-copilot" });
    statusRaw.provider_secrets = null;
    expect(await getTokenStatus(env, "legacy-status-github")).toMatchObject({ connected: true });
    expect(statusRaw.meta).toBe(JSON.stringify({ githubLogin: "status-octo" }));
    expect(statusRaw.provider_secrets).toBeInstanceOf(Uint8Array);
    expect(JSON.stringify(statusRaw)).not.toContain("status-copilot");
  });

  it("does not overwrite a concurrent token update while scrubbing legacy meta", async () => {
    const { db, tokens, raceNextTokenRead } = stubDb();
    const env = envWith(db);
    await saveToken(env, {
      provider: "racing-github",
      accessToken: "racing-at",
      refreshToken: "racing-rt",
      authKind: "oauth",
      meta: { githubLogin: "old-login", copilotToken: "legacy-copilot" },
    });
    const raw = tokens.get("racing-github")!;
    raw.provider_secrets = null;
    raceNextTokenRead.provider = "racing-github";

    expect(await getToken(env, "racing-github")).toMatchObject({
      meta: { githubLogin: "old-login" },
      secrets: { copilotToken: "legacy-copilot" },
    });
    expect(raw.meta).toBe(JSON.stringify({ githubLogin: "concurrent-update" }));
    expect(raw.provider_secrets).toBeNull();
  });

  it("treats corrupt provider-secret ciphertext as a reconnect-required row", async () => {
    const { db, tokens } = stubDb();
    const env = envWith(db);
    await saveToken(env, {
      provider: "corrupt-secrets",
      accessToken: "still-encrypted",
      authKind: "oauth",
    });
    tokens.get("corrupt-secrets")!.provider_secrets = new Uint8Array([1, 2, 3]);

    expect(await getToken(env, "corrupt-secrets")).toBeNull();
    expect(tokens.get("corrupt-secrets")!.last_error).toContain("reconnect required");
  });

  it("scrubs legacy Copilot plaintext when existing provider-secret ciphertext is corrupt", async () => {
    const { db, tokens } = stubDb();
    const env = envWith(db);
    await saveToken(env, {
      provider: "legacy-corrupt-copilot",
      accessToken: "legacy-corrupt-at",
      authKind: "oauth",
    });
    const raw = tokens.get("legacy-corrupt-copilot")!;
    raw.meta = JSON.stringify({
      githubLogin: "legacy-login",
      copilotToken: "legacy-plaintext-copilot",
    });
    const corruptCiphertext = new Uint8Array([1, 2, 3]);
    raw.provider_secrets = corruptCiphertext;

    expect(await getToken(env, "legacy-corrupt-copilot")).toBeNull();
    expect(raw.meta).toBe(JSON.stringify({ githubLogin: "legacy-login" }));
    expect(raw.provider_secrets).toBe(corruptCiphertext);
    expect(String(raw.last_error)).toContain("reconnect required");
    expect(JSON.stringify(raw)).not.toContain("legacy-plaintext-copilot");
  });

  it("status reads scrub legacy Copilot plaintext when ciphertext migration fails", async () => {
    const { db, tokens } = stubDb();
    const env = envWith(db);
    await saveToken(env, {
      provider: "legacy-status-corrupt-copilot",
      accessToken: "legacy-status-corrupt-at",
      authKind: "oauth",
    });
    const raw = tokens.get("legacy-status-corrupt-copilot")!;
    raw.meta = JSON.stringify({ copilotToken: "legacy-status-plaintext" });
    const corruptCiphertext = new Uint8Array([4, 5, 6]);
    raw.provider_secrets = corruptCiphertext;

    expect(await getTokenStatus(env, "legacy-status-corrupt-copilot")).toMatchObject({
      connected: true,
      lastError: expect.stringContaining("reconnect required"),
    });
    expect(raw.meta).toBeNull();
    expect(raw.provider_secrets).toBe(corruptCiphertext);
    expect(JSON.stringify(raw)).not.toContain("legacy-status-plaintext");
  });

  it("scrubs legacy Copilot plaintext and marks reconnect when encryption key is missing", async () => {
    const { db, tokens } = stubDb();
    const env = envWith(db);
    await saveToken(env, {
      provider: "legacy-no-key-copilot",
      accessToken: "legacy-no-key-at",
      authKind: "oauth",
    });
    const raw = tokens.get("legacy-no-key-copilot")!;
    raw.meta = JSON.stringify({ copilotToken: "legacy-no-key-plaintext" });
    const noKeyEnv = { DB: db } as unknown as Env;

    await expect(getToken(noKeyEnv, "legacy-no-key-copilot")).rejects.toThrow(/OAUTH_ENCRYPTION_KEY/);
    expect(raw.meta).toBeNull();
    expect(String(raw.last_error)).toContain("reconnect required");
    expect(JSON.stringify(raw)).not.toContain("legacy-no-key-plaintext");
  });

  it("getTokenStatus detects corrupt provider-secret ciphertext without legacy metadata", async () => {
    const { db, tokens } = stubDb();
    const env = envWith(db);
    await saveToken(env, {
      provider: "status-corrupt-secrets",
      accessToken: "status-corrupt-at",
      authKind: "oauth",
      secrets: { copilotToken: "valid-secret-before-corruption" },
      meta: { githubLogin: "status-login" },
    });
    tokens.get("status-corrupt-secrets")!.provider_secrets = new Uint8Array([1, 2, 3]);

    expect(await getTokenStatus(env, "status-corrupt-secrets")).toMatchObject({
      connected: true,
      lastError: expect.stringContaining("reconnect required"),
    });
    expect(String(tokens.get("status-corrupt-secrets")!.last_error)).toContain("reconnect required");
  });

  it("account_label prefers name, falls back to email, else null", async () => {
    const { db } = stubDb();
    const env = envWith(db);
    await saveToken(env, { provider: "p1", accessToken: "a", email: "e@x.com", authKind: "paste" });
    expect((await getToken(env, "p1"))!.accountLabel).toBe("e@x.com");
    await saveToken(env, { provider: "p2", accessToken: "a", authKind: "paste" });
    expect((await getToken(env, "p2"))!.accountLabel).toBeNull();
  });

  it("no expiresIn → expiresAt null; no refreshToken → null", async () => {
    const { db } = stubDb();
    const env = envWith(db);
    await saveToken(env, { provider: "trae", accessToken: "a", authKind: "paste" });
    const row = (await getToken(env, "trae"))!;
    expect(row.expiresAt).toBeNull();
    expect(row.refreshToken).toBeNull();
  });

  it("upsert replaces the row (second save wins)", async () => {
    const { db } = stubDb();
    const env = envWith(db);
    await saveToken(env, { provider: "trae", accessToken: "old", authKind: "paste" });
    await saveToken(env, { provider: "trae", accessToken: "new", authKind: "oauth" });
    const row = (await getToken(env, "trae"))!;
    expect(row.accessToken).toBe("new");
    expect(row.authKind).toBe("oauth");
  });

  it("getTokenStatus exposes non-secret fields only", async () => {
    const { db } = stubDb();
    const env = envWith(db);
    await saveToken(env, {
      provider: "trae",
      accessToken: "a",
      expiresIn: 60,
      name: "N",
      authKind: "paste",
    });
    const s = (await getTokenStatus(env, "trae"))!;
    expect(s.connected).toBe(true);
    expect(s.expiresAt).toBeGreaterThan(Date.now());
    expect(s.accountLabel).toBe("N");
    expect(s.lastError).toBeNull();
    expect(s.authKind).toBe("paste");
    expect(JSON.stringify(s)).not.toContain("accessToken");
  });

  it("getTokenStatus null for unknown provider", async () => {
    const { db } = stubDb();
    expect(await getTokenStatus(envWith(db), "nope")).toBeNull();
  });

  it("deleteToken removes the row", async () => {
    const { db } = stubDb();
    const env = envWith(db);
    await saveToken(env, { provider: "trae", accessToken: "a", authKind: "paste" });
    await deleteToken(env, "trae");
    expect(await getToken(env, "trae")).toBeNull();
    expect(await getTokenStatus(env, "trae")).toBeNull();
  });

  it("corrupt ciphertext → getToken null + last_error recorded", async () => {
    const { db, tokens } = stubDb();
    const env = envWith(db);
    await saveToken(env, { provider: "trae", accessToken: "a", authKind: "paste" });
    (tokens.get("trae") as Record<string, unknown>).access_token = new Uint8Array(30).fill(7);
    expect(await getToken(env, "trae")).toBeNull();
    expect(String((tokens.get("trae") as Record<string, unknown>).last_error)).toMatch(/decrypt/);
  });

  it("missing encryption key → save/get throw honest error", async () => {
    const { db } = stubDb();
    const env = { DB: db } as unknown as Env;
    await expect(
      saveToken(env, { provider: "trae", accessToken: "a", authKind: "paste" }),
    ).rejects.toThrow(/OAUTH_ENCRYPTION_KEY/);
    await expect(getToken(env, "trae")).rejects.toThrow(/OAUTH_ENCRYPTION_KEY/);
  });
});

describe("oauth pending store", () => {
  it("save → get returns the pending flow", async () => {
    const { db } = stubDb();
    const env = envWith(db);
    await savePending(env, {
      provider: "cline",
      mode: "pkce",
      state: "s1",
      codeVerifier: "v1",
      ttlSec: 600,
    });
    const p = (await getPending(env, "cline"))!;
    expect(p.mode).toBe("pkce");
    expect(p.state).toBe("s1");
    expect(p.codeVerifier).toBe("v1");
    expect(p.expiresAt).toBeGreaterThan(Date.now());
  });

  it("expired pending returns null", async () => {
    const { db } = stubDb();
    const env = envWith(db);
    await savePending(env, { provider: "cline", mode: "pkce", state: "s", codeVerifier: "v", ttlSec: 0 });
    expect(await getPending(env, "cline")).toBeNull();
  });

  it("device mode carries device_code; fields null when absent", async () => {
    const { db } = stubDb();
    const env = envWith(db);
    await savePending(env, { provider: "kilocode", mode: "device", deviceCode: "d1", ttlSec: 900 });
    const p = (await getPending(env, "kilocode"))!;
    expect(p.mode).toBe("device");
    expect(p.deviceCode).toBe("d1");
    expect(p.state).toBeNull();
  });

  it("upsert overwrites an in-flight flow (one flow per provider)", async () => {
    const { db } = stubDb();
    const env = envWith(db);
    await savePending(env, { provider: "kilocode", mode: "device", deviceCode: "d1", ttlSec: 900 });
    await savePending(env, { provider: "kilocode", mode: "device", deviceCode: "d2", ttlSec: 900 });
    expect((await getPending(env, "kilocode"))!.deviceCode).toBe("d2");
  });

  it("deletePending removes it", async () => {
    const { db } = stubDb();
    const env = envWith(db);
    await savePending(env, { provider: "kilocode", mode: "device", deviceCode: "d", ttlSec: 900 });
    await deletePending(env, "kilocode");
    expect(await getPending(env, "kilocode")).toBeNull();
  });
});

describe("no DB binding", () => {
  const env = {} as Env;
  const fns: Array<() => Promise<unknown>> = [
    () => saveToken(env, { provider: "x", accessToken: "a", authKind: "paste" }),
    () => getToken(env, "x"),
    () => deleteToken(env, "x"),
    () => getTokenStatus(env, "x"),
    () => savePending(env, { provider: "x", mode: "pkce", ttlSec: 1 }),
    () => getPending(env, "x"),
    () => deletePending(env, "x"),
  ];
  it("every function throws DB binding not configured", async () => {
    for (const fn of fns) {
      await expect(fn()).rejects.toThrow("DB binding not configured");
    }
  });
});
