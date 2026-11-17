import type { DeviceCodeResponse, OAuthAdapter, PollResult, RawTokens } from "../types";

/**
 * Muse Code uses a durable DCA token that is minted into a non-expiring API
 * key for forwarding. Reminting happens on refresh; the DCA remains the
 * refresh grant and is never replaced by the short API key.
 */

interface MuseCodeConfig extends Record<string, unknown> {
  clientId: string;
  deviceCodeUrl: string;
  tokenUrl: string;
  mintUrl: string;
}

interface MuseMint {
  apiKey?: string;
  baseUrl?: string;
  email?: string;
  name?: string;
  subsTierName?: unknown;
  subsTierId?: unknown;
  isSubsActive?: unknown;
  hasPaymentMethod?: unknown;
  requirePayment?: unknown;
  canSubscribe?: unknown;
}

const MUSE_CODE_CONFIG: MuseCodeConfig = {
  clientId: "1031625952748946",
  deviceCodeUrl: "https://auth.meta.com/oidc/device/authorization/",
  tokenUrl: "https://auth.meta.com/oidc/device/token/",
  mintUrl: "https://api.meta.ai/muse-code/key",
};

const USER_AGENT = "muse-code/1.0.2";
const TIMEOUT_MS = 20_000;
const DEVICE_GRANT = "urn:ietf:params:oauth:grant-type:device_code";

const POLL_ERROR_DESCRIPTIONS: Record<string, string> = {
  authorization_pending: "Authorization pending.",
  slow_down: "Authorization pending.",
  access_denied: "Authorization denied.",
  expired_token: "Device code expired.",
  invalid_grant: "Authorization failed.",
};

function object(value: unknown): RawTokens | null {
  return value && typeof value === "object" && !Array.isArray(value) ? (value as RawTokens) : null;
}

function text(value: unknown): string | undefined {
  return typeof value === "string" && value.trim() ? value.trim() : undefined;
}

function asFiniteNumber(value: unknown): number | undefined {
  return typeof value === "number" && Number.isFinite(value) ? value : undefined;
}

/** Common Muse request headers; per-request values override the defaults. */
export function museHeaders(extra: Record<string, string> = {}): Record<string, string> {
  return {
    Accept: "application/json",
    "User-Agent": USER_AGENT,
    ...extra,
  };
}

export function isDcaToken(value: unknown): value is string {
  return typeof value === "string" && value.startsWith("dca:");
}

function formHeaders(): Record<string, string> {
  return museHeaders({ "Content-Type": "application/x-www-form-urlencoded" });
}

function timeoutSignal(): AbortSignal {
  return AbortSignal.timeout(TIMEOUT_MS);
}

async function readJsonOnce(response: Response): Promise<RawTokens> {
  const body = await response.text();
  try {
    const parsed: unknown = JSON.parse(body);
    return object(parsed) ?? { error: "invalid_response", error_description: body };
  } catch {
    return { error: "invalid_response", error_description: body };
  }
}

function normalizePollError(data: RawTokens): PollResult {
  const upstreamError = typeof data.error === "string" ? data.error : "";
  const description = POLL_ERROR_DESCRIPTIONS[upstreamError];
  if (description) {
    return {
      ok: false,
      data: { error: upstreamError, error_description: description },
    };
  }
  return {
    ok: false,
    data: {
      error: "invalid_response",
      ...(typeof data.error_description === "string"
        ? { error_description: data.error_description }
        : {}),
    },
  };
}

function normalizeMint(data: RawTokens): MuseMint | null {
  const apiKey = text(data.api_key) ?? text(data.apiKey);
  if (!apiKey) return null;
  return {
    apiKey,
    baseUrl: text(data.base_url) ?? text(data.baseUrl),
    email: text(data.user_email) ?? text(data.email),
    name: text(data.user_full_name) ?? text(data.name),
    subsTierName: data.subs_tier_name ?? data.subsTierName,
    subsTierId: data.subs_tier_id ?? data.subsTierId,
    isSubsActive: data.is_subs_active ?? data.isSubsActive,
    hasPaymentMethod: data.has_payment_method ?? data.hasPaymentMethod,
    requirePayment: data.require_payment ?? data.requirePayment,
    canSubscribe: data.can_subscribe ?? data.canSubscribe,
  };
}

function toDcaExpiry(tokens: RawTokens, priorMeta?: Record<string, unknown>): string | undefined {
  const expiresAt = tokens.expires_at;
  if (typeof expiresAt === "string" || typeof expiresAt === "number") {
    const parsed = typeof expiresAt === "number" ? expiresAt : Date.parse(expiresAt);
    if (Number.isFinite(parsed)) return new Date(parsed).toISOString();
  }
  const expiresIn = asFiniteNumber(tokens.expires_in);
  if (expiresIn !== undefined && expiresIn > 0) {
    return new Date(Date.now() + expiresIn * 1000).toISOString();
  }
  return typeof priorMeta?.dcaExpiresAt === "string" ? priorMeta.dcaExpiresAt : undefined;
}

class MuseCodeMintError extends Error {
  status: number;

  constructor(status: number) {
    super(`Muse Code key mint failed (HTTP ${status}).`);
    this.name = "MuseCodeMintError";
    this.status = status;
  }
}

async function fetchMint(
  config: MuseCodeConfig,
  dcaToken: string,
): Promise<MuseMint> {
  const response = await fetch(config.mintUrl, {
    method: "POST",
    headers: museHeaders({
      Authorization: `Bearer ${dcaToken}`,
      "Content-Type": "application/json",
    }),
    body: JSON.stringify({ dca_token: dcaToken }),
    redirect: "error",
    signal: timeoutSignal(),
  });
  if (!response.ok) {
    if (response.status === 401 || response.status === 403) {
      throw new MuseCodeMintError(response.status);
    }
    throw new Error(`Muse Code key mint failed (HTTP ${response.status}).`);
  }
  const data = await readJsonOnce(response);
  const minted = normalizeMint(data);
  if (!minted) throw new Error("Muse Code key mint response missing api_key.");
  return minted;
}

function isMissingApiKeyError(error: unknown): boolean {
  return error instanceof Error && error.message === "Muse Code key mint response missing api_key.";
}

export const museCodeAdapter: OAuthAdapter = {
  prefix: "muse-code",
  flowMode: "device",
  config: MUSE_CODE_CONFIG,
  instructions:
    "Open the verification URL below and confirm the displayed code. The console checks for approval automatically.",

  requestDeviceCode: async (cfg): Promise<DeviceCodeResponse> => {
    const config = cfg as unknown as MuseCodeConfig;
    let response: Response;
    try {
      response = await fetch(config.deviceCodeUrl, {
        method: "POST",
        headers: formHeaders(),
        body: new URLSearchParams({ client_id: config.clientId }).toString(),
        redirect: "error",
        signal: timeoutSignal(),
      });
    } catch {
      throw new Error("Muse Code device authorization network error.");
    }
    if (!response.ok) {
      throw new Error(`Muse Code device authorization failed (HTTP ${response.status}).`);
    }
    const data = await readJsonOnce(response);
    const deviceCode = text(data.device_code);
    const userCode = text(data.user_code);
    if (!deviceCode) throw new Error("Muse Code returned a missing device_code.");
    if (!userCode) throw new Error("Muse Code returned a missing user_code.");

    const verify = (value: unknown): string | undefined => {
      const candidate = text(value);
      if (!candidate) return undefined;
      try {
        const url = new URL(candidate);
        if (url.origin !== "https://auth.meta.com" || url.username || url.password) return undefined;
        return candidate;
      } catch {
        return undefined;
      }
    };
    const verificationUri = verify(data.verification_uri);
    const verificationUriComplete =
      data.verification_uri_complete == null
        ? verificationUri
        : verify(data.verification_uri_complete);
    if (!verificationUri || !verificationUriComplete) {
      throw new Error("Muse Code returned an invalid authorization URL.");
    }

    const expiresIn = asFiniteNumber(data.expires_in);
    if (expiresIn === undefined || expiresIn <= 0 || expiresIn > 86_400) {
      throw new Error("Muse Code returned an invalid device code expiry.");
    }
    const interval = asFiniteNumber(data.interval);
    return {
      device_code: deviceCode,
      user_code: userCode,
      verification_uri: verificationUri,
      verification_uri_complete: verificationUriComplete,
      expires_in: expiresIn,
      interval: interval !== undefined && interval > 0 ? interval : 5,
    };
  },

  pollToken: async (cfg, deviceCode): Promise<PollResult> => {
    const config = cfg as unknown as MuseCodeConfig;
    let response: Response;
    try {
      response = await fetch(config.tokenUrl, {
        method: "POST",
        headers: formHeaders(),
        body: new URLSearchParams({
          client_id: config.clientId,
          device_code: deviceCode,
          grant_type: DEVICE_GRANT,
        }).toString(),
        redirect: "error",
        signal: timeoutSignal(),
      });
    } catch {
      return { ok: false, data: { error: "network_error" } };
    }
    const data = await readJsonOnce(response);
    const accessToken = text(data.access_token);
    if (response.ok && accessToken) {
      return {
        ok: true,
        data: {
          access_token: accessToken,
          ...(text(data.refresh_token) ? { refresh_token: text(data.refresh_token) } : {}),
          ...(asFiniteNumber(data.expires_in) !== undefined
            ? { expires_in: asFiniteNumber(data.expires_in) }
            : {}),
          ...(text(data.token_type) ? { token_type: text(data.token_type) } : {}),
        },
      };
    }
    if (response.ok && !data.error) {
      return {
        ok: false,
        data: { error: "Muse Code device flow completed without an access token." },
      };
    }
    return normalizePollError(data);
  },

  postExchange: async (tokens, _startParams): Promise<RawTokens> => {
    const config = MUSE_CODE_CONFIG;
    const access = text(tokens.access_token);
    const refresh = isDcaToken(tokens.refresh_token) ? tokens.refresh_token : undefined;
    const dcaToken = (access && isDcaToken(access) ? access : undefined) ?? refresh;
    if (!dcaToken) return {};
    try {
      const minted = await fetchMint(config, dcaToken);
      return { dcaToken, minted };
    } catch (error) {
      // A valid device grant is still useful without a minted API key; save
      // the DCA-only row and let refresh-on-use retry the mint later.
      if (isMissingApiKeyError(error)) throw error;
      return { dcaToken };
    }
  },

  refresh: async (_cfg, refreshToken, meta) => {
    const dcaToken = isDcaToken(meta?.dcaToken)
      ? meta.dcaToken
      : isDcaToken(refreshToken)
        ? refreshToken
        : undefined;
    if (!dcaToken) throw new Error("Muse Code refresh is missing its DCA token.");
    const minted = await fetchMint(MUSE_CODE_CONFIG, dcaToken);
    return {
      access_token: minted.apiKey,
      refresh_token: dcaToken,
      muse_mint: minted,
    };
  },

  mapTokens: (tokens, extra, priorMeta) => {
    const extraMint = object(extra?.minted);
    const tokenMint = object(tokens.muse_mint);
    const rawMint = extraMint ?? tokenMint;
    const minted = rawMint ? normalizeMint(rawMint) : null;
    const access = text(tokens.access_token) ?? "";
    const extraDca = text(extra?.dcaToken);
    const dcaToken = isDcaToken(tokens.refresh_token)
      ? tokens.refresh_token
      : isDcaToken(extraDca)
        ? extraDca
        : isDcaToken(priorMeta?.dcaToken)
          ? priorMeta.dcaToken
          : isDcaToken(access)
            ? access
            : undefined;
    const accessToken = minted?.apiKey || (isDcaToken(access) ? "" : access) || dcaToken || "";
    if (!accessToken) {
      throw new Error("Muse Code device flow completed without an access token.");
    }
    const email = minted?.email ?? text(priorMeta?.email);
    const name = minted?.name ?? text(priorMeta?.name);
    const dcaExpiresAt = toDcaExpiry(tokens, priorMeta);
    const meta: Record<string, unknown> = {
      ...(priorMeta ?? {}),
      authKind: "oauth",
      lastRefresh: new Date().toISOString(),
    };
    delete meta.dcaToken;
    if (minted) {
      for (const key of [
        "baseUrl",
        "email",
        "name",
        "subsTierName",
        "subsTierId",
        "isSubsActive",
        "hasPaymentMethod",
        "requirePayment",
        "canSubscribe",
      ] as const) {
        if (minted[key] !== undefined) meta[key] = minted[key];
      }
    }
    if (email) meta.email = email;
    if (name) meta.name = name;
    if (dcaExpiresAt) meta.dcaExpiresAt = dcaExpiresAt;
    return {
      accessToken,
      refreshToken: dcaToken ?? null,
      expiresIn: minted ? undefined : asFiniteNumber(tokens.expires_in),
      email: email ?? null,
      name: name ?? email ?? null,
      meta,
    };
  },
};
