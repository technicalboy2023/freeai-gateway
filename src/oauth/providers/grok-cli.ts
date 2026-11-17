import type { DeviceCodeResponse, OAuthAdapter, PollResult, RawTokens } from "../types";
import { decodeJwtPayload } from "./jwt";

/**
 * Grok CLI OAuth supports a device-code primary flow and a locally pasted
 * JWT/auth.json fallback. The browser-PKCE flow is intentionally deferred.
 */

interface GrokConfig extends Record<string, unknown> {
  clientId: string;
  issuer: string;
  deviceCodeUrl: string;
  tokenUrl: string;
  deviceScope: string;
  browserScope: string;
  oAuthHeaders: () => Record<string, string>;
}

interface ImportedToken extends Record<string, unknown> {
  accessToken: string;
  refreshToken?: string | null;
  expiresIn: number;
  email: string | null;
  userId: string | null;
  teamId: string | null;
  tier: unknown;
  principalType: string | null;
  principalId: string | null;
  organizationId: string | null;
}

const DEVICE_SCOPE =
  "openid profile email offline_access grok-cli:access api:access conversations:read conversations:write workspaces:read workspaces:write";
const BROWSER_SCOPE = "openid profile email offline_access grok-cli:access";

function oAuthHeaders(): Record<string, string> {
  return {
    Accept: "application/json",
    "Content-Type": "application/x-www-form-urlencoded",
    "x-grok-client-version": "1.0.41",
    "x-grok-client-surface": "ui",
  };
}

const GROK_CONFIG: GrokConfig = {
  clientId: "b1a00492-073a-47ea-816f-4c329264a828",
  issuer: "https://auth.x.ai",
  deviceCodeUrl: "https://auth.x.ai/oauth2/device/code",
  tokenUrl: "https://auth.x.ai/oauth2/token",
  deviceScope: DEVICE_SCOPE,
  browserScope: BROWSER_SCOPE,
  oAuthHeaders,
};

const DEVICE_GRANT = "urn:ietf:params:oauth:grant-type:device_code";
const DEFAULT_EXPIRES_IN = 21_600;

function object(value: unknown): Record<string, unknown> | null {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

function nonEmptyString(value: unknown): string | null {
  return typeof value === "string" && value ? value : null;
}

function parseJsonText(text: string): Record<string, unknown> | null {
  try {
    return object(JSON.parse(text));
  } catch {
    return null;
  }
}

async function readResponse(response: Response): Promise<RawTokens> {
  const body = await response.text();
  return parseJsonText(body) ?? {
    error: "invalid_response",
    error_description: body,
  };
}

function validVerificationUrl(value: unknown): value is string {
  if (typeof value !== "string" || !value || /[\u0000-\u001f\u007f]/.test(value)) return false;
  try {
    const url = new URL(value);
    if (url.username || url.password) return false;
    if (url.protocol === "https:") return true;
    return (
      url.protocol === "http:" &&
      (url.hostname.toLowerCase() === "localhost" || url.hostname === "127.0.0.1")
    );
  } catch {
    return false;
  }
}

function expiresFrom(value: unknown): number {
  if (typeof value !== "number") return DEFAULT_EXPIRES_IN;
  if (!Number.isFinite(value)) return 1;
  return Math.max(1, Math.floor(value));
}

function expiryForImport(
  raw: Record<string, unknown>,
  claims: Record<string, unknown> | null,
): number {
  if (Object.prototype.hasOwnProperty.call(raw, "expires_in")) {
    return expiresFrom(raw.expires_in);
  }
  if (typeof raw.expires_at === "string") {
    const expiresAt = Date.parse(raw.expires_at);
    if (Number.isFinite(expiresAt)) {
      return Math.max(1, Math.floor((expiresAt - Date.now()) / 1000));
    }
  }
  if (typeof claims?.exp === "number" && Number.isFinite(claims.exp)) {
    return Math.max(1, Math.floor(claims.exp - Date.now() / 1000));
  }
  return DEFAULT_EXPIRES_IN;
}

function requireImportedJwtPayload(token: string): Record<string, unknown> {
  const parts = token.split(".");
  if (parts.length !== 3 || parts.some((part) => !part)) {
    throw new Error("Grok token must be a three-part JWT");
  }
  const claims = decodeJwtPayload(token);
  if (!claims) throw new Error("Grok token has an invalid JWT payload");
  return claims;
}

function mapImportedToken(
  accessToken: string,
  raw: Record<string, unknown>,
): ImportedToken {
  const accessClaims = requireImportedJwtPayload(accessToken);
  const idToken = nonEmptyString(raw.id_token);
  const claims = idToken ? decodeJwtPayload(idToken) ?? accessClaims : accessClaims;
  const principalTypeRaw = nonEmptyString(claims?.principal_type);
  const principalType = principalTypeRaw?.toLowerCase() ?? null;
  const principalId = nonEmptyString(claims?.principal_id);
  const subject = nonEmptyString(claims?.sub);
  const email =
    nonEmptyString(claims?.email) ??
    nonEmptyString(claims?.preferred_username);
  const userId =
    principalType === "user"
      ? principalId ?? subject
      : subject ?? principalId;
  const teamId =
    principalType === "team"
      ? principalId
      : nonEmptyString(claims?.team_id);
  const organizationId =
    principalType === "organization"
      ? principalId
      : nonEmptyString(claims?.organization_id);
  return {
    accessToken,
    ...(nonEmptyString(raw.refresh_token)
      ? { refreshToken: nonEmptyString(raw.refresh_token) }
      : {}),
    expiresIn: expiryForImport(raw, claims),
    email,
    userId,
    teamId,
    tier: claims?.tier ?? 1,
    principalType,
    principalId,
    organizationId,
  };
}

function authJsonEntry(value: unknown, preferredKey: string): Record<string, unknown> | null {
  const entries = object(value);
  if (!entries) return null;
  const preferred = object(entries[preferredKey]);
  if (preferred && typeof preferred.key === "string") return preferred;
  for (const entry of Object.values(entries)) {
    const candidate = object(entry);
    if (candidate && typeof candidate.key === "string") return candidate;
  }
  return null;
}

function parseImportedString(value: string, config: GrokConfig): ImportedToken {
  const trimmed = value.trim();
  if (!trimmed) throw new Error("Grok token is empty");
  if (!trimmed.startsWith("{")) return mapImportedToken(trimmed, {});

  const parsed = parseJsonText(trimmed);
  if (!parsed) throw new Error("Grok token JSON is invalid");
  const accessValue = parsed.accessToken ?? parsed.access_token;
  if (typeof accessValue === "string" && accessValue.trim()) {
    return mapImportedToken(accessValue.trim(), parsed);
  }
  const entry = authJsonEntry(accessValue, `${config.issuer}::${config.clientId}`);
  if (entry && typeof entry.key === "string" && entry.key.trim()) {
    return mapImportedToken(entry.key.trim(), entry);
  }
  throw new Error("Grok token JSON is missing accessToken");
}

function mapBrowserTokens(
  tokens: RawTokens,
  config: GrokConfig,
  priorMeta?: Record<string, unknown>,
) {
  const claims =
    typeof tokens.id_token === "string" ? decodeJwtPayload(tokens.id_token) : null;
  const freshEmail =
    nonEmptyString(claims?.email) ??
    nonEmptyString(claims?.preferred_username);
  const email = freshEmail ?? nonEmptyString(priorMeta?.email);
  const freshName = nonEmptyString(claims?.name);
  const name =
    freshName ??
    nonEmptyString(priorMeta?.name) ??
    (priorMeta ? null : email);
  const principalType = nonEmptyString(claims?.principal_type)?.toLowerCase();
  const principalId = nonEmptyString(claims?.principal_id);
  const subject = nonEmptyString(claims?.sub);
  const freshIdentity = {
    userId:
      principalType === "user"
        ? principalId ?? subject
        : subject ?? principalId,
    teamId:
      principalType === "team"
        ? principalId
        : nonEmptyString(claims?.team_id),
    tier: claims?.tier,
    principalType,
    principalId,
    organizationId:
      principalType === "organization"
        ? principalId
        : nonEmptyString(claims?.organization_id),
  };
  const scope =
    nonEmptyString(tokens.scope) ??
    nonEmptyString(priorMeta?.scope) ??
    config.deviceScope;
  const tokenType =
    nonEmptyString(tokens.token_type) ??
    nonEmptyString(priorMeta?.tokenType) ??
    "Bearer";
  const meta: Record<string, unknown> = {
    ...(priorMeta ?? {}),
    scope,
    tokenType,
    autoSync: true,
  };
  if (priorMeta) {
    if (freshEmail) meta.email = freshEmail;
    if (freshName) meta.name = freshName;
    for (const [key, value] of Object.entries(freshIdentity)) {
      if (value !== undefined && value !== null) meta[key] = value;
    }
  }
  const expiresIn =
    tokens.expires_in === undefined || tokens.expires_in === null
      ? DEFAULT_EXPIRES_IN
      : expiresFrom(tokens.expires_in);
  return {
    accessToken: typeof tokens.access_token === "string" ? tokens.access_token : "",
    refreshToken: nonEmptyString(tokens.refresh_token),
    expiresIn,
    email,
    name,
    meta,
  };
}

export const grokCliAdapter: OAuthAdapter = {
  prefix: "grok-cli",
  flowMode: "device",
  config: GROK_CONFIG,
  instructions:
    "Open the verification URL below and confirm the displayed code. Or connect with a Grok CLI token/auth.json using the token-paste box.",

  requestDeviceCode: async (cfg): Promise<DeviceCodeResponse> => {
    const config = cfg as unknown as GrokConfig;
    const response = await fetch(config.deviceCodeUrl, {
      method: "POST",
      headers: config.oAuthHeaders(),
      body: new URLSearchParams({
        client_id: config.clientId,
        scope: config.deviceScope,
        referrer: "grok-build",
      }).toString(),
    });
    const data = await readResponse(response);
    if (!response.ok) {
      const reason =
        nonEmptyString(data.error_description) ??
        nonEmptyString(data.error) ??
        `HTTP ${response.status}`;
      throw new Error(`Grok device authorization failed: ${reason}`);
    }
    const deviceCode = nonEmptyString(data.device_code);
    const userCode = nonEmptyString(data.user_code);
    const verificationUri = data.verification_uri;
    const verificationUriComplete = data.verification_uri_complete ?? verificationUri;
    if (!deviceCode || !userCode || typeof verificationUri !== "string") {
      throw new Error("Grok returned a device authorization response with missing fields");
    }
    if (!/^[A-Za-z0-9-]+$/.test(userCode)) {
      throw new Error("Grok returned an invalid device code");
    }
    if (
      !validVerificationUrl(verificationUri) ||
      !validVerificationUrl(verificationUriComplete)
    ) {
      throw new Error("Grok returned an unsupported verification URL");
    }
    return {
      device_code: deviceCode,
      user_code: userCode,
      verification_uri: verificationUri,
      verification_uri_complete: verificationUriComplete,
      expires_in:
        typeof data.expires_in === "number" && Number.isFinite(data.expires_in) && data.expires_in > 0
          ? data.expires_in
          : 1800,
      interval:
        typeof data.interval === "number" && Number.isFinite(data.interval) && data.interval > 0
          ? data.interval
          : 5,
    };
  },

  pollToken: async (cfg, deviceCode): Promise<PollResult> => {
    const config = cfg as unknown as GrokConfig;
    const response = await fetch(config.tokenUrl, {
      method: "POST",
      headers: config.oAuthHeaders(),
      body: new URLSearchParams({
        client_id: config.clientId,
        device_code: deviceCode,
        grant_type: DEVICE_GRANT,
      }).toString(),
    });
    const data = await readResponse(response);
    if (response.ok && typeof data.access_token === "string" && data.access_token) {
      return { ok: true, data };
    }
    return { ok: false, data };
  },

  importToken: async (raw): Promise<RawTokens> => {
    const config = GROK_CONFIG;
    const token = typeof raw.access_token === "string" ? raw.access_token : "";
    return parseImportedString(token, config);
  },

  mapTokens: (tokens, _extra, priorMeta, _priorSecrets) => {
    const config = GROK_CONFIG;
    if (typeof tokens.access_token === "string") {
      return mapBrowserTokens(tokens, config, priorMeta);
    }
    const email = nonEmptyString(tokens.email) ?? nonEmptyString(priorMeta?.email);
    const fields = {
      userId: nonEmptyString(tokens.userId) ?? nonEmptyString(priorMeta?.userId),
      email,
      teamId: nonEmptyString(tokens.teamId) ?? nonEmptyString(priorMeta?.teamId),
      tier: tokens.tier ?? priorMeta?.tier ?? 1,
      principalType:
        nonEmptyString(tokens.principalType) ?? nonEmptyString(priorMeta?.principalType),
      principalId:
        nonEmptyString(tokens.principalId) ?? nonEmptyString(priorMeta?.principalId),
      organizationId:
        nonEmptyString(tokens.organizationId) ?? nonEmptyString(priorMeta?.organizationId),
    };
    return {
      accessToken: typeof tokens.accessToken === "string" ? tokens.accessToken : "",
      refreshToken: nonEmptyString(tokens.refreshToken),
      expiresIn: expiresFrom(tokens.expiresIn),
      email,
      name: email,
      meta: {
        ...(priorMeta ?? {}),
        ...fields,
        autoSync: true,
      },
    };
  },
};
