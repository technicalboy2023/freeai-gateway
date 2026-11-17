import type { OAuthAdapter, RawTokens } from "../types";

/**
 * Recon (OmniRoute release/v3.8.54, CLINE_CONFIG): paste-code flow. The Cline
 * console hands out an auth code that is EITHER an embedded base64 token
 * envelope or a real authorization code — try the embedded decode first, then
 * fall back to the token endpoint. No redirectUri: the code arrives pasted,
 * so the engine default `${origin}/admin` is only recorded for parity.
 * Refresh uses the WorkOS extension grant.
 */

interface ClineConfig extends Record<string, unknown> {
  authorizeUrl: string;
  tokenExchangeUrl: string;
  refreshUrl: string;
}

const CLINE_CONFIG: ClineConfig = {
  authorizeUrl: "https://api.cline.bot/api/v1/auth/authorize",
  tokenExchangeUrl: "https://api.cline.bot/api/v1/auth/token",
  refreshUrl: "https://api.cline.bot/api/v1/auth/refresh",
};

/** Base64(URI-encoded) JSON envelope — any failure means "try the POST". */
function tryEmbeddedDecode(code: string): RawTokens | null {
  try {
    let s = code;
    try {
      s = decodeURIComponent(code);
    } catch {
      // tolerate non-URI-encoded input
    }
    const padded = s + "=".repeat((4 - (s.length % 4)) % 4);
    const decoded = atob(padded);
    const json = decoded.slice(0, decoded.lastIndexOf("}") + 1);
    const parsed = JSON.parse(json) as Record<string, unknown>;
    const accessToken = parsed.accessToken;
    if (typeof accessToken !== "string" || !accessToken) throw new Error("no accessToken in envelope");
    return {
      access_token: accessToken,
      refresh_token: (parsed.refreshToken as string) ?? null,
      email: (parsed.email as string) ?? "",
      firstName: (parsed.firstName as string) ?? "",
      lastName: (parsed.lastName as string) ?? "",
      expires_at: (parsed.expiresAt as string) ?? undefined,
    };
  } catch {
    return null;
  }
}

async function fallbackExchange(
  config: ClineConfig,
  code: string,
  redirectUri: string,
): Promise<RawTokens> {
  const res = await fetch(config.tokenExchangeUrl, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      grant_type: "authorization_code",
      code,
      client_type: "extension",
      redirect_uri: redirectUri,
    }),
  });
  if (!res.ok) throw new Error(`Cline token exchange failed: ${await res.text()}`);
  const data = (await res.json()) as Record<string, unknown>;
  const nested = (data.data ?? {}) as Record<string, unknown>;
  const userInfo = (nested.userInfo ?? {}) as Record<string, unknown>;
  return {
    access_token: (nested.accessToken as string) ?? (data.accessToken as string) ?? "",
    refresh_token: (nested.refreshToken as string) ?? (data.refreshToken as string) ?? null,
    email: (userInfo.email as string) ?? "",
    expires_at: (nested.expiresAt as string) ?? (data.expiresAt as string) ?? undefined,
  };
}

function object(value: unknown): Record<string, unknown> | null {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

function nonEmptyString(value: unknown): string | null {
  return typeof value === "string" && value ? value : null;
}

export const clineAdapter: OAuthAdapter = {
  prefix: "cline",
  flowMode: "paste-code",
  config: CLINE_CONFIG,
  buildAuthUrl: (cfg, redirectUri) => {
    const c = cfg as unknown as ClineConfig;
    const params = new URLSearchParams({
      client_type: "extension",
      callback_url: redirectUri,
      redirect_uri: redirectUri,
    });
    return `${c.authorizeUrl}?${params}`;
  },
  exchangeToken: async (cfg, code, redirectUri) => {
    const c = cfg as unknown as ClineConfig;
    const embedded = tryEmbeddedDecode(code);
    if (embedded) return embedded;
    return fallbackExchange(c, code, redirectUri);
  },
  refresh: async (cfg, refreshToken) => {
    const c = cfg as unknown as ClineConfig;
    if (!c.refreshUrl) throw new Error("Cline refresh URL is not configured");
    const response = await fetch(c.refreshUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json", Accept: "application/json" },
      body: JSON.stringify({
        refreshToken,
        grantType: "refresh_token",
        clientType: "extension",
      }),
    });
    let payload: Record<string, unknown> | null = null;
    try {
      payload = object(await response.json());
    } catch {
      // The malformed body is handled like a missing refresh result below.
    }
    const data = object(payload?.data) ?? payload ?? {};
    const errorText =
      nonEmptyString(data.error) ??
      nonEmptyString(data.message) ??
      nonEmptyString(payload?.error) ??
      nonEmptyString(payload?.message);
    const lowerError = errorText?.toLowerCase() ?? "";
    const terminalCode = ["invalid_grant", "invalid_request"].find((code) =>
      lowerError.includes(code),
    );
    if (terminalCode) throw new Error(`cline refresh rejected: ${terminalCode}`);
    if (!response.ok) throw new Error(`Cline refresh failed (${response.status})`);
    const accessToken =
      nonEmptyString(data.accessToken) ?? nonEmptyString(payload?.accessToken);
    if (!accessToken) throw new Error("Cline token refresh returned no token");
    const nextRefreshToken =
      nonEmptyString(data.refreshToken) ?? nonEmptyString(payload?.refreshToken) ?? refreshToken;
    const expiresAt =
      nonEmptyString(data.expiresAt) ?? nonEmptyString(payload?.expiresAt) ?? undefined;
    return {
      access_token: accessToken,
      refresh_token: nextRefreshToken,
      ...(expiresAt ? { expires_at: expiresAt } : {}),
    };
  },
  mapTokens: (tokens, _extra, priorMeta) => {
    const freshFirstName = nonEmptyString(tokens.firstName);
    const freshLastName = nonEmptyString(tokens.lastName);
    const freshEmail = nonEmptyString(tokens.email);
    const firstName =
      freshFirstName ?? nonEmptyString(priorMeta?.firstName) ?? "";
    const lastName =
      freshLastName ?? nonEmptyString(priorMeta?.lastName) ?? "";
    const fullName = [firstName, lastName].filter(Boolean).join(" ").trim();
    const email = freshEmail ?? nonEmptyString(priorMeta?.email);
    const hasFreshIdentity = Boolean(freshFirstName || freshLastName || freshEmail);
    const expRaw = tokens.expires_at;
    const derived = expRaw
      ? Math.floor((new Date(String(expRaw)).getTime() - Date.now()) / 1000)
      : 3600;
    return {
      accessToken: String(tokens.access_token ?? ""),
      refreshToken: (tokens.refresh_token as string) ?? null,
      expiresIn: Number.isFinite(derived) ? derived : 3600,
      name: hasFreshIdentity ? fullName || email : null,
      email,
      meta: {
        ...(priorMeta ?? {}),
        firstName,
        lastName,
        ...(priorMeta && freshEmail ? { email: freshEmail } : {}),
      },
    };
  },
};
