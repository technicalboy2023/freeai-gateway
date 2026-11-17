import type { DeviceCodeResponse, OAuthAdapter, PollResult, RawTokens } from "../types";

/**
 * WorkBuddy plugin OAuth. Its state endpoint returns an opaque state used as
 * a one-shot poll credential; successful poll returns a normal long-lived
 * access/refresh token pair.
 */

interface WorkBuddyConfig extends Record<string, unknown> {
  stateUrl: string;
  tokenUrl: string;
  refreshUrl: string;
  platform: string;
  pollIntervalMs: number;
}

const WORKBUDDY_CONFIG: WorkBuddyConfig = {
  stateUrl: "https://www.workbuddy.ai/v2/plugin/auth/state",
  tokenUrl: "https://www.workbuddy.ai/v2/plugin/auth/token",
  refreshUrl: "https://www.workbuddy.ai/v2/plugin/auth/token/refresh",
  platform: "CLI",
  pollIntervalMs: 5000,
};

const DEVICE_TTL_SEC = 600;
const REFRESH_HEADERS = {
  "Content-Type": "application/json",
  Accept: "application/json",
  "X-Product": "SaaS",
  "X-Domain": "www.workbuddy.ai",
  "User-Agent": "WorkBuddy/5.5.6",
};

function object(value: unknown): RawTokens | null {
  return value && typeof value === "object" && !Array.isArray(value) ? (value as RawTokens) : null;
}

async function readJsonOnce(response: Response): Promise<RawTokens> {
  const body = await response.text();
  try {
    const parsed: unknown = JSON.parse(body);
    return object(parsed) ?? {};
  } catch {
    return {};
  }
}

function message(data: RawTokens): string {
  return typeof data.msg === "string" && data.msg ? data.msg : "unknown error";
}

function errorFromPoll(data: RawTokens): PollResult {
  if (data.code === 11217) {
    return { ok: false, data: { error: "authorization_pending" } };
  }
  return {
    ok: false,
    data: {
      ...(typeof data.code === "number" ? { code: data.code } : {}),
      ...(typeof data.msg === "string" ? { msg: data.msg } : {}),
    },
  };
}

export const workbuddyAdapter: OAuthAdapter = {
  prefix: "workbuddy",
  flowMode: "device",
  config: WORKBUDDY_CONFIG,
  instructions:
    "Open the verification URL below and confirm the displayed code. The console checks for approval automatically.",

  requestDeviceCode: async (cfg): Promise<DeviceCodeResponse> => {
    const config = cfg as unknown as WorkBuddyConfig;
    let response: Response;
    try {
      response = await fetch(`${config.stateUrl}?platform=${encodeURIComponent(config.platform)}`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Accept: "application/json",
          "X-Product": "SaaS",
        },
        body: JSON.stringify({ platform: config.platform }),
      });
    } catch {
      throw new Error("WorkBuddy state error: the state endpoint is unreachable");
    }
    const result = await readJsonOnce(response);
    const data = object(result.data);
    const state = typeof data?.state === "string" ? data.state.trim() : "";
    const authUrl =
      (typeof data?.authUrl === "string" && data.authUrl) ||
      (typeof data?.url === "string" && data.url) ||
      "";
    if (!response.ok || result.code !== 0 || !state) {
      throw new Error(`WorkBuddy state error: ${message(result)}`);
    }
    return {
      device_code: state,
      user_code: state,
      verification_uri: authUrl,
      verification_uri_complete: authUrl,
      expires_in: DEVICE_TTL_SEC,
      interval: Math.max(1, Math.floor(config.pollIntervalMs / 1000)),
    };
  },

  pollToken: async (cfg, state): Promise<PollResult> => {
    const config = cfg as unknown as WorkBuddyConfig;
    let response: Response;
    try {
      response = await fetch(`${config.tokenUrl}?state=${encodeURIComponent(state)}`, {
        method: "GET",
        headers: { Accept: "application/json", "X-Product": "SaaS" },
      });
    } catch {
      return { ok: false, data: { code: 0, msg: "WorkBuddy token endpoint is unreachable" } };
    }
    const result = await readJsonOnce(response);
    const data = object(result.data);
    if (
      response.ok &&
      result.code === 0 &&
      typeof data?.accessToken === "string" &&
      data.accessToken
    ) {
      return {
        ok: true,
        data: {
          access_token: data.accessToken,
          refresh_token:
            typeof data.refreshToken === "string" && data.refreshToken ? data.refreshToken : "",
          token_type: typeof data.tokenType === "string" && data.tokenType ? data.tokenType : "Bearer",
          ...(typeof data.expiresIn === "number" ? { expires_in: data.expiresIn } : {}),
        },
      };
    }
    return errorFromPoll(result);
  },

  refresh: async (cfg, refreshToken): Promise<RawTokens> => {
    const config = cfg as unknown as WorkBuddyConfig;
    let response: Response;
    try {
      response = await fetch(config.refreshUrl, {
        method: "POST",
        headers: {
          ...REFRESH_HEADERS,
          "X-Refresh-Token": refreshToken,
        },
        body: "{}",
      });
    } catch {
      throw new Error("Failed to refresh WorkBuddy token (network error)");
    }
    const result = await readJsonOnce(response);
    const data = object(result.data);
    if (!response.ok) {
      throw new Error(`Failed to refresh WorkBuddy token (${response.status})`);
    }
    if (result.code !== 0 || typeof data?.accessToken !== "string" || !data.accessToken) {
      throw new Error("WorkBuddy token refresh returned no token");
    }
    return {
      access_token: data.accessToken,
      refresh_token:
        typeof data.refreshToken === "string" && data.refreshToken
          ? data.refreshToken
          : refreshToken,
      ...(typeof data.expiresIn === "number" ? { expires_in: data.expiresIn } : {}),
    };
  },

  mapTokens: (tokens) => ({
    accessToken: typeof tokens.access_token === "string" ? tokens.access_token : "",
    refreshToken: typeof tokens.refresh_token === "string" && tokens.refresh_token ? tokens.refresh_token : null,
    expiresIn:
      typeof tokens.expires_in === "number" && tokens.expires_in
        ? tokens.expires_in
        : 31_104_000,
    meta: {},
  }),
};
