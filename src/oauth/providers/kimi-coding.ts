import type { DeviceCodeResponse, OAuthAdapter, PollResult, RawTokens } from "../types";

/**
 * Kimi Code device OAuth. Kimi binds rotating refresh-token families to the
 * client/device identity, so the UUID minted at connect is persisted in
 * token meta and reused on poll + every refresh.
 */

interface KimiConfig extends Record<string, unknown> {
  clientId: string;
  deviceCodeUrl: string;
  tokenUrl: string;
}

const KIMI_CONFIG: KimiConfig = {
  clientId: "17e5f671-d194-4dfb-9706-5516cb48c098",
  deviceCodeUrl: "https://auth.kimi.com/api/oauth/device_authorization",
  tokenUrl: "https://auth.kimi.com/api/oauth/token",
};

const DEVICE_NAME = "freeai-gateway";
const DEVICE_MODEL = "cloudflare-worker";
const OS_VERSION = "workers";
const KNOWN_ERRORS = new Set([
  "authorization_pending",
  "slow_down",
  "expired_token",
  "access_denied",
  "invalid_grant",
  "invalid_request",
]);

function deviceId(meta?: Record<string, unknown>): string {
  const existing = meta?.deviceId;
  return typeof existing === "string" && existing.trim() ? existing.trim() : crypto.randomUUID();
}

/** Stable identity headers shared by the device start, poll, and refresh. */
export function kimiIdentityHeaders(meta?: Record<string, unknown>): Record<string, string> {
  return {
    "X-Msh-Platform": "kimi_code_cli",
    "X-Msh-Version": "2.1.1",
    "X-Msh-Device-Name": DEVICE_NAME,
    "X-Msh-Device-Model": DEVICE_MODEL,
    "X-Msh-Os-Version": OS_VERSION,
    "X-Msh-Device-Id": deviceId(meta),
  };
}

function headers(meta?: Record<string, unknown>): Record<string, string> {
  return {
    Accept: "application/json",
    "Content-Type": "application/x-www-form-urlencoded",
    ...kimiIdentityHeaders(meta),
  };
}

async function readJsonOnce(response: Response): Promise<RawTokens> {
  const text = await response.text();
  try {
    const parsed: unknown = JSON.parse(text);
    if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) return parsed as RawTokens;
  } catch {
    // Body already consumed; use a stable error shape below.
  }
  return { error: "invalid_response", error_description: text };
}

function normalizePollError(data: RawTokens): PollResult {
  const upstreamError = typeof data.error === "string" ? data.error : "";
  const error = KNOWN_ERRORS.has(upstreamError) ? upstreamError : "invalid_response";
  const description =
    typeof data.error_description === "string"
      ? data.error_description
      : upstreamError && error === "invalid_response"
        ? upstreamError
        : undefined;
  return {
    ok: false,
    data: {
      error,
      ...(description ? { error_description: description } : {}),
    },
  };
}

function isText(value: unknown): value is string {
  return typeof value === "string" && value.trim().length > 0;
}

export const kimiCodingAdapter: OAuthAdapter = {
  prefix: "kimi-coding",
  flowMode: "device",
  config: KIMI_CONFIG,
  instructions:
    "Open the verification URL below and confirm the displayed code. The console checks for approval automatically.",

  requestDeviceCode: async (cfg): Promise<DeviceCodeResponse> => {
    const config = cfg as unknown as KimiConfig;
    // Mint exactly once; engine persists this device_id as encrypted pending
    // extra and later passes it back to pollToken/mapTokens.
    const id = deviceId();
    const response = await fetch(config.deviceCodeUrl, {
      method: "POST",
      headers: headers({ deviceId: id }),
      body: new URLSearchParams({ client_id: config.clientId }).toString(),
    });
    if (!response.ok) {
      throw new Error(`Kimi device authorization request failed (${response.status})`);
    }
    const data = await readJsonOnce(response);
    for (const field of ["device_code", "user_code", "verification_uri_complete"] as const) {
      if (!isText(data[field])) {
        throw new Error(`Device authorization response missing ${field}`);
      }
    }
    return {
      device_code: (data.device_code as string).trim(),
      user_code: (data.user_code as string).trim(),
      verification_uri: typeof data.verification_uri === "string" ? data.verification_uri : "",
      verification_uri_complete: (data.verification_uri_complete as string).trim(),
      expires_in: typeof data.expires_in === "number" ? data.expires_in : 900,
      interval:
        typeof data.interval === "number" && Number.isFinite(data.interval) && data.interval > 0
          ? data.interval
          : 5,
      device_id: id,
    };
  },

  pollToken: async (cfg, deviceCode, _codeVerifier, startParams): Promise<PollResult> => {
    const config = cfg as unknown as KimiConfig;
    const identity = { deviceId: startParams?.deviceId };
    const response = await fetch(config.tokenUrl, {
      method: "POST",
      headers: headers(identity),
      body: new URLSearchParams({
        client_id: config.clientId,
        device_code: deviceCode,
        grant_type: "urn:ietf:params:oauth:grant-type:device_code",
      }).toString(),
    });
    const data = await readJsonOnce(response);
    if (isText(data.access_token)) return { ok: true, data };
    return normalizePollError(data);
  },

  refresh: async (cfg, refreshToken, meta) => {
    const config = cfg as unknown as KimiConfig;
    if (!isText(meta?.deviceId)) {
      throw new Error("Kimi device identity missing — reconnect required");
    }
    const response = await fetch(config.tokenUrl, {
      method: "POST",
      headers: headers(meta),
      body: new URLSearchParams({
        grant_type: "refresh_token",
        refresh_token: refreshToken,
        client_id: config.clientId,
      }).toString(),
    });
    const data = await readJsonOnce(response);
    if (typeof data.error === "string" && ["invalid_grant", "invalid_request"].includes(data.error)) {
      throw new Error(data.error);
    }
    if (!response.ok || !isText(data.access_token)) {
      const reason =
        typeof data.error_description === "string"
          ? data.error_description
          : typeof data.error === "string"
            ? data.error
            : `HTTP ${response.status}`;
      throw new Error(`Kimi token refresh failed: ${reason}`);
    }
    return {
      access_token: data.access_token.trim(),
      refresh_token: isText(data.refresh_token) ? data.refresh_token.trim() : refreshToken,
      ...(typeof data.expires_in === "number" ? { expires_in: data.expires_in } : {}),
    };
  },

  mapTokens: (tokens, extra, priorMeta) => {
    const priorId = typeof priorMeta?.deviceId === "string" ? priorMeta.deviceId : undefined;
    const extraId = typeof extra?.deviceId === "string" ? extra.deviceId : undefined;
    const id = extraId ?? priorId ?? deviceId();
    return {
      accessToken: isText(tokens.access_token) ? tokens.access_token.trim() : "",
      refreshToken: isText(tokens.refresh_token) ? tokens.refresh_token.trim() : null,
      expiresIn: typeof tokens.expires_in === "number" ? tokens.expires_in : null,
      meta: {
        ...(priorMeta ?? {}),
        deviceId: id,
        deviceName: DEVICE_NAME,
        deviceModel: DEVICE_MODEL,
        osVersion: OS_VERSION,
      },
    };
  },
};
