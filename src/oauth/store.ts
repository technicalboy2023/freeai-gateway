import type { Env } from "../env";
import { MissingKeyMaterialError } from "./errors";
import { decryptToken, encryptToken, importAesKey } from "./crypto";

/**
 * Encrypted D1 store for OAuth tokens and in-flight login flows.
 *
 * Tokens are AES-GCM BLOBs (see ./crypto); only non-secret metadata is stored
 * in the clear (`meta`, `account_label`). Rows never leave this module
 * decrypted except through the typed accessors below, which never log.
 */

export interface TokenRow {
  provider: string;
  accessToken: string;
  refreshToken?: string | null;
  expiresAt?: number | null;
  accountLabel?: string | null;
  meta?: Record<string, unknown>;
  secrets?: Record<string, unknown>;
  authKind: string;
  connectedAt: number;
  lastRefreshAt?: number | null;
  lastError?: string | null;
}

export interface PendingRow {
  provider: string;
  mode: "pkce" | "device";
  state?: string | null;
  codeVerifier?: string | null;
  deviceCode?: string | null;
  /** Provider-specific extras threaded through start → poll → mapTokens. */
  extra?: Record<string, unknown> | null;
  createdAt: number;
  expiresAt: number;
}

export interface SaveTokenInput {
  provider: string;
  accessToken: string;
  refreshToken?: string | null;
  expiresIn?: number | null;
  email?: string | null;
  name?: string | null;
  meta?: Record<string, unknown>;
  secrets?: Record<string, unknown>;
  authKind: string;
  /** Set on token refresh; fresh connects leave it NULL. */
  lastRefreshAt?: number | null;
  /** Preserve the original connect time on refresh re-save; fresh connects leave it unset. */
  connectedAt?: number;
}

interface StoredTokenRow {
  provider: string;
  access_token: Uint8Array;
  refresh_token: Uint8Array | null;
  expires_at: number | null;
  account_label: string | null;
  meta: string | null;
  provider_secrets: Uint8Array | null;
  auth_kind: string;
  connected_at: number;
  last_refresh_at: number | null;
  last_error: string | null;
}

interface StoredPendingRow {
  provider: string;
  mode: string;
  state: string | null;
  code_verifier: string | null;
  device_code: string | null;
  extra: string | null;
  created_at: number;
  expires_at: number;
}

export class DbMissingError extends Error {
  constructor() {
    super("DB binding not configured");
  }
}

function requireDb(env: Env): D1Database {
  if (!env.DB) throw new DbMissingError();
  return env.DB;
}

async function requireKey(env: Env): Promise<CryptoKey> {
  const key = await importAesKey(env);
  if (!key) throw new MissingKeyMaterialError();
  return key;
}

function asBytes(value: unknown): Uint8Array {
  return value instanceof Uint8Array ? value : new Uint8Array(value as ArrayBuffer);
}

function asRecord(value: unknown): Record<string, unknown> | undefined {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : undefined;
}

function parseMeta(raw: string | null): Record<string, unknown> | undefined {
  if (raw == null) return undefined;
  try {
    return asRecord(JSON.parse(raw));
  } catch {
    return undefined;
  }
}

async function decryptProviderSecrets(
  key: CryptoKey,
  stored: Uint8Array | null,
): Promise<Record<string, unknown> | undefined> {
  if (!stored) return undefined;
  const parsed: unknown = JSON.parse(await decryptToken(key, asBytes(stored)));
  const record = asRecord(parsed);
  if (!record) throw new Error("provider secrets are not an object");
  return record;
}

interface LegacyMetaResult {
  meta?: Record<string, unknown>;
  secrets?: Record<string, unknown>;
  migrationFailed?: boolean;
  missingKey?: boolean;
}

/**
 * Scrub pre-provider_secrets credential copies while comparing both source
 * columns so a stale read cannot overwrite a concurrent token save.
 */
async function scrubLegacyMeta(
  env: Env,
  provider: string,
  originalMeta: string | null,
  originalProviderSecrets: Uint8Array | null,
  meta: Record<string, unknown> | undefined,
  secrets: Record<string, unknown> | undefined,
): Promise<LegacyMetaResult> {
  if (
    !meta ||
    (!Object.prototype.hasOwnProperty.call(meta, "copilotToken") &&
      !Object.prototype.hasOwnProperty.call(meta, "dcaToken"))
  ) {
    return { meta, secrets };
  }

  const cleanMeta = { ...meta };
  let cleanSecrets = secrets;
  const legacyCopilotToken = cleanMeta.copilotToken;
  delete cleanMeta.copilotToken;
  delete cleanMeta.dcaToken;

  let migrationError: string | null = null;
  let missingKey = false;
  let newProviderSecrets = originalProviderSecrets;
  if (typeof legacyCopilotToken === "string" && legacyCopilotToken) {
    try {
      const key = await requireKey(env);
      if (cleanSecrets === undefined && originalProviderSecrets) {
        cleanSecrets = await decryptProviderSecrets(key, originalProviderSecrets);
      }
      if (typeof cleanSecrets?.copilotToken !== "string" || !cleanSecrets.copilotToken) {
        cleanSecrets = { ...(cleanSecrets ?? {}), copilotToken: legacyCopilotToken };
      }
      newProviderSecrets =
        cleanSecrets && Object.keys(cleanSecrets).length > 0
          ? await encryptToken(key, JSON.stringify(cleanSecrets))
          : null;
    } catch (error) {
      // Never keep a known credential in plaintext just because its encrypted
      // replacement cannot be read or written. Force a reconnect instead.
      migrationError = "provider secret migration failed — reconnect required";
      missingKey = error instanceof MissingKeyMaterialError;
      cleanSecrets = undefined;
    }
  }

  const db = requireDb(env);
  const cleanMetaJson = Object.keys(cleanMeta).length > 0 ? JSON.stringify(cleanMeta) : null;
  if (migrationError) {
    await db
      .prepare(
        `UPDATE oauth_tokens
         SET meta = ?1, last_error = ?2
         WHERE provider = ?3 AND meta IS ?4 AND provider_secrets IS ?5`,
      )
      .bind(cleanMetaJson, migrationError, provider, originalMeta, originalProviderSecrets)
      .run();
  } else {
    await db
      .prepare(
        `UPDATE oauth_tokens
         SET meta = ?1, provider_secrets = ?2
         WHERE provider = ?3 AND meta IS ?4 AND provider_secrets IS ?5`,
      )
      .bind(
        cleanMetaJson,
        newProviderSecrets,
        provider,
        originalMeta,
        originalProviderSecrets,
      )
      .run();
  }
  return {
    meta: cleanMeta,
    secrets: cleanSecrets,
    migrationFailed: Boolean(migrationError),
    missingKey,
  };
}

/**
 * Pending TEXT codec (RF-1): sensitive pending columns are AES-GCM TEXT
 * prefixed `enc:v1:` + base64(iv‖cipher). Legacy plaintext rows (written
 * before this codec) stay readable; a corrupt payload reads as null for that
 * field only — never a thrown error on read.
 */
const ENC_PREFIX = "enc:v1:";

async function encryptPendingText(key: CryptoKey, plaintext: string): Promise<string> {
  const bytes = await encryptToken(key, plaintext);
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return `${ENC_PREFIX}${btoa(bin)}`;
}

async function decryptPendingText(key: CryptoKey, stored: string | null): Promise<string | null> {
  if (!stored) return null;
  if (!stored.startsWith(ENC_PREFIX)) return stored; // legacy plaintext passthrough
  try {
    const bin = atob(stored.slice(ENC_PREFIX.length));
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return await decryptToken(key, bytes);
  } catch {
    return null; // corrupt field — null, not a crash
  }
}

function parsePendingExtra(raw: string | null): Record<string, unknown> | null {
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

/** Upsert a connection row; a fresh connect clears last_error / last_refresh_at. */
export async function saveToken(env: Env, t: SaveTokenInput): Promise<void> {
  const db = requireDb(env);
  const key = await requireKey(env);
  const access = await encryptToken(key, t.accessToken);
  const refresh = t.refreshToken ? await encryptToken(key, t.refreshToken) : null;
  const secrets =
    t.secrets && Object.keys(t.secrets).length > 0
      ? await encryptToken(key, JSON.stringify(t.secrets))
      : null;
  const expiresAt = t.expiresIn ? Date.now() + t.expiresIn * 1000 : null;
  const label = t.name ?? t.email ?? null;
  const meta = t.meta ? JSON.stringify(t.meta) : null;
  await db
    .prepare(
      `INSERT INTO oauth_tokens
         (provider, access_token, refresh_token, expires_at, account_label, meta, auth_kind, connected_at, last_refresh_at, provider_secrets)
       VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
       ON CONFLICT(provider) DO UPDATE SET
         access_token = excluded.access_token,
         refresh_token = excluded.refresh_token,
         expires_at = excluded.expires_at,
         account_label = excluded.account_label,
         meta = excluded.meta,
         auth_kind = excluded.auth_kind,
         connected_at = excluded.connected_at,
         last_refresh_at = excluded.last_refresh_at,
         provider_secrets = excluded.provider_secrets,
         last_error = NULL`,
    )
    .bind(
      t.provider,
      access,
      refresh,
      expiresAt,
      label,
      meta,
      t.authKind,
      t.connectedAt ?? Date.now(),
      t.lastRefreshAt ?? null,
      secrets,
    )
    .run();
}

/** Decrypt and return the connection row, or null (absent / corrupt). */
export async function getToken(env: Env, provider: string): Promise<TokenRow | null> {
  const db = requireDb(env);
  const stored = await db
    .prepare(
      `SELECT provider, access_token, refresh_token, expires_at, account_label, meta, provider_secrets,
              auth_kind, connected_at, last_refresh_at, last_error
       FROM oauth_tokens WHERE provider = ?1`,
    )
    .bind(provider)
    .first<StoredTokenRow>();
  if (!stored) {
    await requireKey(env);
    return null;
  }

  const migrated = await scrubLegacyMeta(
    env,
    provider,
    stored.meta,
    stored.provider_secrets,
    parseMeta(stored.meta),
    undefined,
  );
  if (migrated.missingKey) throw new MissingKeyMaterialError();
  if (migrated.migrationFailed) return null;

  const key = await requireKey(env);
  let accessToken: string;
  let refreshToken: string | null = null;
  let secrets: Record<string, unknown> | undefined = migrated.secrets;
  try {
    accessToken = await decryptToken(key, asBytes(stored.access_token));
    if (stored.refresh_token) {
      refreshToken = await decryptToken(key, asBytes(stored.refresh_token));
    }
    if (secrets === undefined) {
      secrets = await decryptProviderSecrets(key, stored.provider_secrets);
    }
  } catch {
    // Corrupt row (wrong key after a secret rotation, tampering): never
    // surface garbage — flag it and require a reconnect.
    await db
      .prepare("UPDATE oauth_tokens SET last_error = ?1 WHERE provider = ?2")
      .bind("token decrypt failed — reconnect required", provider)
      .run();
    return null;
  }

  return {
    provider: stored.provider,
    accessToken,
    refreshToken,
    expiresAt: stored.expires_at,
    accountLabel: stored.account_label,
    meta: migrated.meta,
    secrets,
    authKind: stored.auth_kind,
    connectedAt: stored.connected_at,
    lastRefreshAt: stored.last_refresh_at,
    lastError: stored.last_error,
  };
}

export async function deleteToken(env: Env, provider: string): Promise<void> {
  const db = requireDb(env);
  await db.prepare("DELETE FROM oauth_tokens WHERE provider = ?1").bind(provider).run();
}

/** Non-secret status snapshot; legacy plaintext credentials are scrubbed when found. */
export async function getTokenStatus(
  env: Env,
  provider: string,
): Promise<{
  connected: boolean;
  expiresAt: number | null;
  accountLabel: string | null;
  lastError: string | null;
  authKind: string;
} | null> {
  const db = requireDb(env);
  const stored = await db
    .prepare(
      `SELECT expires_at, account_label, last_error, auth_kind, meta, provider_secrets
       FROM oauth_tokens WHERE provider = ?1`,
    )
    .bind(provider)
    .first<
      Pick<
        StoredTokenRow,
        "expires_at" | "account_label" | "last_error" | "auth_kind" | "meta" | "provider_secrets"
      >
    >();
  if (!stored) return null;
  let lastError = stored.last_error;
  try {
    const migrated = await scrubLegacyMeta(
      env,
      provider,
      stored.meta,
      stored.provider_secrets,
      parseMeta(stored.meta),
      undefined,
    );
    if (migrated.missingKey) throw new MissingKeyMaterialError();
    if (migrated.migrationFailed) {
      lastError = "provider secret migration failed — reconnect required";
    } else if (stored.provider_secrets) {
      const key = await requireKey(env);
      await decryptProviderSecrets(key, stored.provider_secrets);
    }
  } catch (error) {
    if (error instanceof MissingKeyMaterialError) throw error;
    lastError = "provider secret decrypt failed — reconnect required";
    await db
      .prepare("UPDATE oauth_tokens SET last_error = ?1 WHERE provider = ?2")
      .bind(lastError, provider)
      .run();
  }
  return {
    connected: true,
    expiresAt: stored.expires_at,
    accountLabel: stored.account_label,
    lastError,
    authKind: stored.auth_kind,
  };
}

export async function savePending(
  env: Env,
  p: {
    provider: string;
    mode: "pkce" | "device";
    state?: string | null;
    codeVerifier?: string | null;
    deviceCode?: string | null;
    extra?: Record<string, unknown> | null;
    ttlSec: number;
  },
): Promise<void> {
  const db = requireDb(env);
  const key = await requireKey(env);
  const now = Date.now();
  const [state, codeVerifier, deviceCode, extra] = await Promise.all([
    p.state ? encryptPendingText(key, p.state) : Promise.resolve(null),
    p.codeVerifier ? encryptPendingText(key, p.codeVerifier) : Promise.resolve(null),
    p.deviceCode ? encryptPendingText(key, p.deviceCode) : Promise.resolve(null),
    p.extra ? encryptPendingText(key, JSON.stringify(p.extra)) : Promise.resolve(null),
  ]);
  await db
    .prepare(
      `INSERT INTO oauth_pending
         (provider, mode, state, code_verifier, device_code, extra, created_at, expires_at)
       VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
       ON CONFLICT(provider) DO UPDATE SET
         mode = excluded.mode,
         state = excluded.state,
         code_verifier = excluded.code_verifier,
         device_code = excluded.device_code,
         extra = excluded.extra,
         created_at = excluded.created_at,
         expires_at = excluded.expires_at`,
    )
    .bind(p.provider, p.mode, state, codeVerifier, deviceCode, extra, now, now + p.ttlSec * 1000)
    .run();
}

/** Expired flows read as absent (Review Focus #1 — no stale-flow reuse). */
export async function getPending(env: Env, provider: string): Promise<PendingRow | null> {
  const db = requireDb(env);
  const stored = await db
    .prepare(
      `SELECT provider, mode, state, code_verifier, device_code, extra, created_at, expires_at
       FROM oauth_pending WHERE provider = ?1`,
    )
    .bind(provider)
    .first<StoredPendingRow>();
  if (!stored || stored.expires_at <= Date.now()) return null;
  const key = await requireKey(env);
  const [state, codeVerifier, deviceCode, extraRaw] = await Promise.all([
    decryptPendingText(key, stored.state),
    decryptPendingText(key, stored.code_verifier),
    decryptPendingText(key, stored.device_code),
    decryptPendingText(key, stored.extra),
  ]);
  return {
    provider: stored.provider,
    mode: stored.mode === "device" ? "device" : "pkce",
    state,
    codeVerifier,
    deviceCode,
    extra: parsePendingExtra(extraRaw),
    createdAt: stored.created_at,
    expiresAt: stored.expires_at,
  };
}

export async function deletePending(env: Env, provider: string): Promise<void> {
  const db = requireDb(env);
  await db.prepare("DELETE FROM oauth_pending WHERE provider = ?1").bind(provider).run();
}
