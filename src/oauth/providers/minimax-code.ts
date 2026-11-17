import type { DeviceCodeResponse, OAuthAdapter, PollResult, RawTokens } from "../types";

/**
 * MiniMax Code device OAuth. Unlike most device grants, this flow binds the
 * PKCE challenge to the device-code request and requires its verifier again
 * when polling for the token.
 */

interface MinimaxConfig extends Record<string, unknown> {
  clientId: string;
  scope: string;
  audience: string;
  accountBase: string;
  deviceCodeUrl: string;
  tokenUrl: string;
  userAgent: string;
}

const MINIMAX_CONFIG: MinimaxConfig = {
  clientId: "mcode-public",
  scope: "agent.default",
  audience: "agent-backend",
  accountBase: "https://account.minimax.io",
  deviceCodeUrl: "https://account.minimax.io/oauth2/device/code",
  tokenUrl: "https://account.minimax.io/oauth2/token",
  userAgent: "minimax-code-cli",
};

const DEVICE_GRANT = "urn:ietf:params:oauth:grant-type:device_code";
const TIMEOUT_MS = 20_000;

function formHeaders(config: MinimaxConfig): Record<string, string> {
  return {
    Accept: "application/json",
    "Content-Type": "application/x-www-form-urlencoded",
    "User-Agent": config.userAgent,
  };
}

function object(value: unknown): RawTokens | null {
  return value && typeof value === "object" && !Array.isArray(value) ? (value as RawTokens) : null;
}

function text(value: unknown): string | undefined {
  return typeof value === "string" && value.trim() ? value.trim() : undefined;
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

function deviceError(data: RawTokens): string {
  return (
    text(data.error_description) ??
    text(data.error) ??
    "unknown error"
  );
}

function normalizePollError(response: Response, data: RawTokens): PollResult {
  if (typeof data.error === "string" && data.error) {
    return {
      ok: false,
      data: {
        error: data.error,
        ...(typeof data.error_description === "string"
          ? { error_description: data.error_description }
          : {}),
      },
    };
  }
  if (!response.ok) {
    return {
      ok: false,
      data: {
        error: "poll_failed",
        error_description: `Poll failed: ${response.status}`,
      },
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

export const minimaxCodeAdapter: OAuthAdapter = {
  prefix: "minimax-code",
  flowMode: "device",
  config: MINIMAX_CONFIG,
  instructions:
    "Open the verification URL below and confirm the displayed code. The console checks for approval automatically.",

  requestDeviceCode: async (cfg, codeChallenge): Promise<DeviceCodeResponse> => {
    const config = cfg as unknown as MinimaxConfig;
    let response: Response;
    try {
      response = await fetch(config.deviceCodeUrl, {
        method: "POST",
        headers: formHeaders(config),
        body: new URLSearchParams({
          client_id: config.clientId,
          scope: config.scope,
          audience: config.audience,
          code_challenge: codeChallenge ?? "",
          code_challenge_method: "S256",
        }).toString(),
        redirect: "error",
        signal: AbortSignal.timeout(TIMEOUT_MS),
      });
    } catch {
      throw new Error("MiniMax Code device authorization failed: the account endpoint is unreachable");
    }
    const data = await readJsonOnce(response);
    if (!response.ok) {
      throw new Error(`MiniMax Code device authorization failed: ${deviceError(data)}`);
    }
    const deviceCode = text(data.device_code);
    const userCode = text(data.user_code);
    if (!deviceCode || !userCode) {
      throw new Error(`MiniMax Code device authorization failed: ${deviceError(data)}`);
    }
    return {
      device_code: deviceCode,
      user_code: userCode,
      verification_uri: text(data.verification_uri) ?? "",
      verification_uri_complete:
        text(data.verification_uri_complete) ?? text(data.verification_uri) ?? "",
      expires_in:
        typeof data.expires_in === "number" && Number.isFinite(data.expires_in) && data.expires_in > 0
          ? data.expires_in
          : 300,
      interval:
        typeof data.interval === "number" && Number.isFinite(data.interval) && data.interval > 0
          ? data.interval
          : 5,
    };
  },

  pollToken: async (cfg, deviceCode, codeVerifier): Promise<PollResult> => {
    const config = cfg as unknown as MinimaxConfig;
    let response: Response;
    try {
      response = await fetch(config.tokenUrl, {
        method: "POST",
        headers: formHeaders(config),
        body: new URLSearchParams({
          grant_type: DEVICE_GRANT,
          device_code: deviceCode,
          client_id: config.clientId,
          code_verifier: codeVerifier ?? "",
        }).toString(),
        redirect: "error",
        signal: AbortSignal.timeout(TIMEOUT_MS),
      });
    } catch {
      return { ok: false, data: { error: "network_error" } };
    }
    const data = await readJsonOnce(response);
    const accessToken = text(data.access_token);
    if (accessToken) {
      return {
        ok: true,
        data: {
          access_token: accessToken,
          ...(text(data.refresh_token) ? { refresh_token: text(data.refresh_token) } : {}),
          ...(typeof data.expires_in === "number" ? { expires_in: data.expires_in } : {}),
        },
      };
    }
    return normalizePollError(response, data);
  },

  refresh: async (cfg, refreshToken, meta) => {
    const config = cfg as unknown as MinimaxConfig;
    const accountBase =
      typeof meta?.accountBase === "string" && meta.accountBase
        ? meta.accountBase.replace(/\/+$/, "")
        : config.accountBase;
    let response: Response;
    try {
      response = await fetch(`${accountBase}/oauth2/token`, {
        method: "POST",
        headers: formHeaders(config),
        body: new URLSearchParams({
          grant_type: "refresh_token",
          refresh_token: refreshToken,
          client_id: config.clientId,
          scope: config.scope,
          audience: config.audience,
        }).toString(),
        redirect: "error",
        signal: AbortSignal.timeout(TIMEOUT_MS),
      });
    } catch {
      throw new Error("MiniMax Code token refresh failed: the account endpoint is unreachable");
    }
    const data = await readJsonOnce(response);
    if (!response.ok || !text(data.access_token)) {
      throw new Error(
        `MiniMax Code token refresh failed: ${text(data.error_description) ?? text(data.error) ?? `HTTP ${response.status}`}`,
      );
    }
    return {
      access_token: text(data.access_token),
      refresh_token: text(data.refresh_token) ?? refreshToken,
      ...(typeof data.expires_in === "number" ? { expires_in: data.expires_in } : {}),
    };
  },

  mapTokens: (tokens, _extra, priorMeta) => {
    const config = MINIMAX_CONFIG;
    return {
      accessToken: text(tokens.access_token) ?? "",
      refreshToken: text(tokens.refresh_token) ?? null,
      expiresIn: typeof tokens.expires_in === "number" ? tokens.expires_in : null,
      name: "MiniMax Code account",
      meta: {
        ...(priorMeta ?? {}),
        authKind: "oauth",
        accountBase:
          typeof priorMeta?.accountBase === "string" && priorMeta.accountBase
            ? priorMeta.accountBase
            : config.accountBase,
      },
    };
  },
};
