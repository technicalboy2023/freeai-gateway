import type { DeviceCodeResponse, OAuthAdapter, PollResult, RawTokens } from "../types";
import { decodeJwtPayload } from "./jwt";

/**
 * Cursor's deep-control login is exposed as a device flow so its PKCE
 * verifier remains server-side. Cursor-agent/IDE tokens can also be pasted.
 */

interface CursorConfig extends Record<string, unknown> {
  loginUrl: string;
  pollUrl: string;
  refreshUrl: string;
  clientVersion: string;
  clientType: string;
}

interface CursorClaims extends Record<string, unknown> {
  exp?: unknown;
  email?: unknown;
  sub?: unknown;
}

const CURSOR_CONFIG: CursorConfig = {
  loginUrl: "https://cursor.com/loginDeepControl",
  pollUrl: "https://api2.cursor.sh/auth/poll",
  refreshUrl: "https://api2.cursor.sh/auth/exchange_user_api_key",
  clientVersion: "2026.07.08-0c04a8a",
  clientType: "ide",
};

const DEEP_CONTROL_EXPIRY_FALLBACK_SEC = 3600;
const PASTE_EXPIRY_FALLBACK_SEC = 86_400;
const REFRESH_TIMEOUT_MS = 15_000;
const RETRYABLE_REFRESH_STATUSES = new Set([429, 500, 502, 503, 504]);

function object(value: unknown): Record<string, unknown> | null {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

function nonEmptyString(value: unknown): string | null {
  return typeof value === "string" && value ? value : null;
}

function tokenClaims(token: string): CursorClaims | null {
  return decodeJwtPayload(token) as CursorClaims | null;
}

function tokenIdentity(token: string): {
  email: string | null;
  accountId: string | null;
  claims: CursorClaims | null;
} {
  const claims = tokenClaims(token);
  const rawEmail = nonEmptyString(claims?.email);
  return {
    email: rawEmail?.toLowerCase() ?? null,
    accountId: nonEmptyString(claims?.sub),
    claims,
  };
}

function deepControlExpiry(claims: CursorClaims | null): number {
  if (typeof claims?.exp !== "number" || !Number.isFinite(claims.exp)) {
    return DEEP_CONTROL_EXPIRY_FALLBACK_SEC;
  }
  return Math.floor((claims.exp * 1000 - Date.now() - 300_000) / 1000);
}

function pasteExpiry(
  claims: CursorClaims | null,
  explicit: unknown,
): number {
  if (typeof explicit === "number" && Number.isFinite(explicit)) {
    return Math.max(1, Math.floor(explicit));
  }
  if (typeof claims?.exp === "number" && Number.isFinite(claims.exp)) {
    return Math.max(1, Math.floor(claims.exp - Date.now() / 1000));
  }
  return PASTE_EXPIRY_FALLBACK_SEC;
}

function invalidMachineId(value: unknown): boolean {
  if (value == null || value === "") return false;
  if (typeof value !== "string") return true;
  const machineId = value.trim();
  if (!machineId) return false;
  // Long hex/UUID values are not Cursor machine IDs; accepting them can bind
  // a pasted token to an internal identifier that the CLI never emitted.
  return (
    /^[0-9a-f]{32,}$/i.test(machineId) ||
    /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/i.test(machineId)
  );
}

function parsePaste(raw: RawTokens): RawTokens {
  let input: Record<string, unknown> = raw;
  const rawToken = raw.access_token;
  if (typeof rawToken === "string" && rawToken.trimStart().startsWith("{")) {
    const parsed = object(JSON.parse(rawToken));
    if (!parsed) throw new Error("Invalid token format.");
    input = parsed;
  }

  const accessToken = input.accessToken ?? input.access_token ?? rawToken;
  if (typeof accessToken !== "string" || accessToken.length < 50) {
    throw new Error("Invalid token format. Token appears too short.");
  }
  const machineId = input.machineId ?? input.machine_id ?? null;
  if (invalidMachineId(machineId)) {
    throw new Error("Invalid machine ID format.");
  }
  const refreshToken =
    nonEmptyString(input.refreshToken) ?? nonEmptyString(input.refresh_token);
  const { email, accountId, claims } = tokenIdentity(accessToken);
  const authMethod =
    nonEmptyString(input.authMethod) ??
    (nonEmptyString(machineId) ? "imported" : "cursor-agent");
  return {
    accessToken,
    refreshToken,
    expiresIn: pasteExpiry(claims, input.expiresIn ?? input.expires_in),
    email,
    accountId,
    machineId: nonEmptyString(machineId),
    authMethod,
  };
}

function mapTokens(
  tokens: RawTokens,
  priorMeta?: Record<string, unknown>,
) {
  if (Object.prototype.hasOwnProperty.call(tokens, "access_token")) {
    const accessToken = nonEmptyString(tokens.access_token);
    const refreshToken = nonEmptyString(tokens.refresh_token);
    if (!accessToken || !refreshToken) {
      throw new Error("Cursor auth response missing tokens");
    }
    const { email, accountId, claims } = tokenIdentity(accessToken);
    const machineId = nonEmptyString(priorMeta?.machineId);
    const authMethod = nonEmptyString(priorMeta?.authMethod) ?? "deep_control";
    return {
      accessToken,
      refreshToken,
      expiresIn: deepControlExpiry(claims),
      email,
      name: email ?? accountId,
      meta: {
        accountId: accountId ?? priorMeta?.accountId ?? null,
        authMethod,
        machineId,
      },
    };
  }

  const accessToken = nonEmptyString(tokens.accessToken) ?? "";
  const { email, accountId, claims } = tokenIdentity(accessToken);
  const machineId = nonEmptyString(tokens.machineId);
  if (invalidMachineId(tokens.machineId)) {
    throw new Error("Invalid machine ID format.");
  }
  const authMethod =
    nonEmptyString(tokens.authMethod) ??
    (machineId ? "imported" : "cursor-agent");
  return {
    accessToken,
    refreshToken: nonEmptyString(tokens.refreshToken),
    expiresIn: pasteExpiry(claims, tokens.expiresIn),
    email: nonEmptyString(tokens.email) ?? email,
    name: email ?? accountId,
    meta: {
      accountId: accountId ?? null,
      authMethod,
      machineId,
    },
  };
}

async function wait(ms: number): Promise<void> {
  await new Promise<void>((resolve) => setTimeout(resolve, ms));
}

function retryDelay(attempt: number): number {
  const base = 300 * 2 ** attempt;
  return base * (0.8 + Math.random() * 0.4);
}

async function refreshCursorToken(
  config: CursorConfig,
  refreshToken: string,
): Promise<RawTokens> {
  let lastStatus = "network error";
  for (let attempt = 0; attempt < 3; attempt++) {
    let response: Response;
    try {
      response = await fetch(config.refreshUrl, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${refreshToken}`,
          Accept: "application/json",
          "Content-Type": "application/json",
        },
        body: "{}",
        signal: AbortSignal.timeout(REFRESH_TIMEOUT_MS),
      });
    } catch (err) {
      lastStatus = err instanceof Error ? err.message : "network error";
      if (attempt < 2) {
        await wait(retryDelay(attempt));
        continue;
      }
      break;
    }

    if (response.status === 401 || response.status === 403) {
      const error = new Error(`Cursor token refresh unauthorized (${response.status})`);
      error.name = "CursorRefreshUnauthorized";
      throw error;
    }
    if (RETRYABLE_REFRESH_STATUSES.has(response.status)) {
      lastStatus = String(response.status);
      if (attempt < 2) {
        await wait(retryDelay(attempt));
        continue;
      }
      break;
    }
    if (!response.ok) {
      throw new Error(`Cursor token refresh failed: ${response.status}`);
    }

    let data: Record<string, unknown> | null = null;
    try {
      data = object(await response.json());
    } catch {
      // The provider response is validated below as a missing access token.
    }
    const accessToken = nonEmptyString(data?.accessToken);
    if (!accessToken) {
      throw new Error("Cursor token refresh response missing access token");
    }
    return {
      access_token: accessToken,
      refresh_token: nonEmptyString(data?.refreshToken) ?? refreshToken,
    };
  }
  throw new Error(`Cursor token refresh failed after 3 attempts (last status ${lastStatus})`);
}

export const cursorAdapter: OAuthAdapter = {
  prefix: "cursor",
  flowMode: "device",
  config: CURSOR_CONFIG,
  instructions:
    "Open the verification URL below and confirm the displayed code. Or connect with a Cursor token using the token-paste box.",

  requestDeviceCode: async (cfg, codeChallenge): Promise<DeviceCodeResponse> => {
    const config = cfg as unknown as CursorConfig;
    const uuid = crypto.randomUUID();
    const login = new URL(config.loginUrl);
    login.searchParams.set("challenge", codeChallenge ?? "");
    login.searchParams.set("uuid", uuid);
    login.searchParams.set("mode", "login");
    login.searchParams.set("redirectTarget", "cli");
    const loginUrl = login.toString();
    return {
      device_code: uuid,
      user_code: uuid,
      verification_uri: loginUrl,
      verification_uri_complete: loginUrl,
      expires_in: 900,
      interval: 2,
    };
  },

  pollToken: async (cfg, deviceCode, codeVerifier): Promise<PollResult> => {
    const config = cfg as unknown as CursorConfig;
    const url = new URL(config.pollUrl);
    url.searchParams.set("uuid", deviceCode);
    url.searchParams.set("verifier", codeVerifier ?? "");
    const response = await fetch(url.toString());
    if (response.status === 404) {
      return { ok: false, data: { error: "authorization_pending" } };
    }
    if (!response.ok) {
      return {
        ok: false,
        data: { error: `Cursor auth poll failed: ${response.status}` },
      };
    }
    let data: Record<string, unknown> | null = null;
    try {
      data = object(await response.json());
    } catch {
      // Invalid JSON is treated as a malformed successful response.
    }
    const accessToken = nonEmptyString(data?.accessToken);
    const refreshToken = nonEmptyString(data?.refreshToken);
    if (!accessToken || !refreshToken) {
      return { ok: false, data: { error: "Cursor auth response missing tokens" } };
    }
    return {
      ok: true,
      data: { access_token: accessToken, refresh_token: refreshToken },
    };
  },

  importToken: async (raw): Promise<RawTokens> => {
    try {
      return parsePaste(raw);
    } catch (err) {
      if (err instanceof SyntaxError) throw new Error("Invalid token format.");
      throw err;
    }
  },

  refresh: async (cfg, refreshToken): Promise<RawTokens> => {
    const config = cfg as unknown as CursorConfig;
    return refreshCursorToken(config, refreshToken);
  },

  mapTokens: (tokens, _extra, priorMeta) => mapTokens(tokens, priorMeta),
};
