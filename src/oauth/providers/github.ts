import type { DeviceCodeResponse, OAuthAdapter, PollResult, RawTokens } from "../types";

/**
 * GitHub device login + Copilot enrichment. The Copilot token is short-lived
 * and is refreshed by forwarding separately; the durable OAuth grant uses
 * GitHub's standard refresh endpoint when available.
 */

interface GithubConfig extends Record<string, unknown> {
  clientId: string;
  deviceCodeUrl: string;
  tokenUrl: string;
  userInfoUrl: string;
  scopes: string;
  apiVersion: string;
  copilotTokenUrl: string;
  userAgent: string;
}

const GITHUB_CONFIG: GithubConfig = {
  clientId: "Iv1.b507a08c87ecfe98",
  deviceCodeUrl: "https://github.com/login/device/code",
  tokenUrl: "https://github.com/login/oauth/access_token",
  userInfoUrl: "https://api.github.com/user",
  scopes: "read:user",
  apiVersion: "2026-08-01",
  copilotTokenUrl: "https://api.github.com/copilot_internal/v2/token",
  userAgent: "GitHubCopilotChat/1.0.91",
};

const DEVICE_GRANT = "urn:ietf:params:oauth:grant-type:device_code";

function formHeaders(): Record<string, string> {
  return {
    Accept: "application/json",
    "Content-Type": "application/x-www-form-urlencoded",
  };
}

async function jsonOrInvalidResponse(response: Response): Promise<RawTokens> {
  const text = await response.text();
  try {
    const parsed: unknown = JSON.parse(text);
    if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
      return parsed as RawTokens;
    }
  } catch {
    // Return a provider-shaped error below; the body was consumed only once.
  }
  return { error: "invalid_response", error_description: text };
}

async function bestEffortJson(response: Response): Promise<RawTokens | null> {
  if (!response.ok) return null;
  try {
    const data: unknown = await response.json();
    return data && typeof data === "object" && !Array.isArray(data) ? (data as RawTokens) : null;
  } catch {
    return null;
  }
}

export const githubAdapter: OAuthAdapter = {
  prefix: "github",
  flowMode: "device",
  config: GITHUB_CONFIG,
  instructions:
    "Open the verification URL below and confirm the displayed code. The console checks for approval automatically.",

  requestDeviceCode: async (cfg): Promise<DeviceCodeResponse> => {
    const c = cfg as unknown as GithubConfig;
    const response = await fetch(c.deviceCodeUrl, {
      method: "POST",
      headers: formHeaders(),
      body: new URLSearchParams({
        client_id: c.clientId,
        scope: c.scopes,
      }).toString(),
    });
    if (!response.ok) {
      const text = await response.text();
      throw new Error(`GitHub device code request failed (${response.status}): ${text}`);
    }
    const data = await jsonOrInvalidResponse(response);
    const verificationUri =
      typeof data.verification_uri === "string" ? data.verification_uri : "";
    return {
      device_code: typeof data.device_code === "string" ? data.device_code : "",
      user_code: typeof data.user_code === "string" ? data.user_code : "",
      verification_uri: verificationUri,
      verification_uri_complete:
        typeof data.verification_uri_complete === "string"
          ? data.verification_uri_complete
          : verificationUri,
      expires_in: typeof data.expires_in === "number" ? data.expires_in : 900,
      interval: typeof data.interval === "number" ? data.interval : 5,
    };
  },

  pollToken: async (cfg, deviceCode): Promise<PollResult> => {
    const c = cfg as unknown as GithubConfig;
    const response = await fetch(c.tokenUrl, {
      method: "POST",
      headers: formHeaders(),
      body: new URLSearchParams({
        client_id: c.clientId,
        device_code: deviceCode,
        grant_type: DEVICE_GRANT,
      }).toString(),
    });
    const data = await jsonOrInvalidResponse(response);
    if (typeof data.access_token === "string" && data.access_token) {
      return { ok: true, data };
    }
    return { ok: false, data };
  },

  postExchange: async (tokens): Promise<RawTokens> => {
    const c = GITHUB_CONFIG;
    const accessToken = typeof tokens.access_token === "string" ? tokens.access_token : "";
    const headers = {
      Authorization: `Bearer ${accessToken}`,
      Accept: "application/json",
      "X-GitHub-Api-Version": c.apiVersion,
      "User-Agent": c.userAgent,
    };

    let copilot: RawTokens | null = null;
    try {
      copilot = await bestEffortJson(
        await fetch(c.copilotTokenUrl, { method: "GET", headers }),
      );
    } catch {
      // Copilot subscription is optional; OAuth connection still succeeds.
    }

    let user: RawTokens | null = null;
    try {
      user = await bestEffortJson(await fetch(c.userInfoUrl, { method: "GET", headers }));
    } catch {
      // Profile lookup is also best-effort.
    }

    return {
      copilotToken: typeof copilot?.token === "string" ? copilot.token : undefined,
      copilotTokenExpiresAt: copilot?.expires_at,
      githubUserId: user?.id,
      githubLogin: typeof user?.login === "string" ? user.login : undefined,
      githubName: typeof user?.name === "string" ? user.name : undefined,
      githubEmail: typeof user?.email === "string" ? user.email : undefined,
      autoSync: true,
    };
  },

  mapTokens: (tokens, extra, priorMeta, priorSecrets) => {
    const details: Record<string, unknown> = { ...(priorMeta ?? {}) };
    for (const [key, value] of Object.entries(extra ?? {})) {
      if (value !== undefined && value !== null) details[key] = value;
    }
    const login = typeof details.githubLogin === "string" ? details.githubLogin : undefined;
    const name = typeof details.githubName === "string" ? details.githubName : undefined;
    const email = typeof details.githubEmail === "string" ? details.githubEmail : undefined;
    const meta: Record<string, unknown> = { ...details, autoSync: details.autoSync === true };
    delete meta.copilotToken;
    return {
      accessToken: typeof tokens.access_token === "string" ? tokens.access_token : "",
      refreshToken: typeof tokens.refresh_token === "string" ? tokens.refresh_token : null,
      expiresIn: typeof tokens.expires_in === "number" ? tokens.expires_in : null,
      name: login ?? name ?? null,
      email: email ?? null,
      secrets: {
        ...(priorSecrets ?? {}),
        ...(typeof details.copilotToken === "string"
          ? { copilotToken: details.copilotToken }
          : {}),
      },
      meta,
    };
  },
};
