import type { DeviceCodeResponse, OAuthAdapter, PollResult, RawTokens } from "../types";

/**
 * GitHub Enterprise Server Copilot device OAuth. The host is deliberately
 * per-connection (and encrypted in oauth_pending while a flow is in flight),
 * rather than being stored in global adapter config.
 */

interface GheCopilotConfig extends Record<string, unknown> {
  clientId: string;
  scopes: string;
  apiVersion: string;
  userAgent: string;
}

interface GheDetails extends Record<string, unknown> {
  gheUrl: string;
  copilotApiUrl?: string;
  copilotProxyUrl?: string;
  copilotToken?: string;
  copilotTokenExpiresAt?: unknown;
  githubUserId?: unknown;
  githubLogin?: string;
  githubName?: string;
  githubEmail?: string;
  autoSync?: boolean;
}

const GHE_COPILOT_CONFIG: GheCopilotConfig = {
  clientId: "Iv1.b507a08c87ecfe98",
  scopes: "read:user",
  apiVersion: "2026-08-01",
  userAgent: "GitHubCopilotChat/1.0.91",
};

const KNOWN_ERRORS = new Set([
  "authorization_pending",
  "slow_down",
  "expired_token",
  "access_denied",
  "incorrect_device_code",
  "incorrect_client_credentials",
  "device_flow_disabled",
  "unsupported_grant_type",
]);

const INSTRUCTIONS =
  "GitHub Enterprise Server only. Start via API: POST /admin/api/oauth/ghe-copilot/start?gheUrl=https://<ghe-host> (admin auth), then open the returned verification URL and confirm its code. github.com Copilot uses the github card, not this one.";

function normalizeGheUrl(value: unknown): string | undefined {
  if (typeof value !== "string") return undefined;
  const trimmed = value.trim();
  if (!trimmed) return undefined;
  try {
    const parsed = new URL(trimmed);
    if (parsed.protocol !== "https:" || parsed.username || parsed.password) return undefined;
  } catch {
    return undefined;
  }
  const normalized = trimmed.replace(/\/+$/, "");
  return normalized || undefined;
}

function requireGheUrl(value: unknown): string {
  const url = normalizeGheUrl(value);
  if (!url) throw new Error("gheUrl is required for GHE Copilot OAuth");
  return url;
}

function formHeaders(): Record<string, string> {
  return {
    Accept: "application/json",
    "Content-Type": "application/x-www-form-urlencoded",
  };
}

async function readJsonOnce(response: Response): Promise<RawTokens> {
  const text = await response.text();
  try {
    const value: unknown = JSON.parse(text);
    if (value && typeof value === "object" && !Array.isArray(value)) return value as RawTokens;
  } catch {
    // The body has been consumed exactly once; turn malformed JSON into a
    // stable provider error rather than leaking an HTML response downstream.
  }
  return { error: "invalid_response", error_description: text };
}

function object(value: unknown): RawTokens | null {
  return value && typeof value === "object" && !Array.isArray(value) ? (value as RawTokens) : null;
}

function errorResult(data: RawTokens): PollResult {
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

async function bestEffortJson(response: Response): Promise<RawTokens | null> {
  if (!response.ok) return null;
  try {
    return object(await response.json());
  } catch {
    return null;
  }
}

function apiHeaders(config: GheCopilotConfig, accessToken: string): Record<string, string> {
  return {
    Authorization: `Bearer ${accessToken}`,
    Accept: "application/json",
    "X-GitHub-Api-Version": config.apiVersion,
    "User-Agent": config.userAgent,
  };
}

export const gheCopilotAdapter: OAuthAdapter = {
  prefix: "ghe-copilot",
  flowMode: "device",
  config: GHE_COPILOT_CONFIG,
  instructions: INSTRUCTIONS,

  parseStartParams: (requestUrl) => {
    const gheUrl = normalizeGheUrl(requestUrl.searchParams.get("gheUrl"));
    return gheUrl ? { gheUrl } : undefined;
  },

  requestDeviceCode: async (cfg, _codeChallenge, startParams): Promise<DeviceCodeResponse> => {
    const config = cfg as unknown as GheCopilotConfig;
    const gheUrl = requireGheUrl(startParams?.gheUrl);
    const response = await fetch(`${gheUrl}/login/device/code`, {
      method: "POST",
      headers: formHeaders(),
      body: new URLSearchParams({
        client_id: config.clientId,
        scope: config.scopes,
      }).toString(),
    });
    if (!response.ok) {
      throw new Error(`Device code request failed (HTTP ${response.status})`);
    }
    const data = await readJsonOnce(response);
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

  pollToken: async (cfg, deviceCode, _codeVerifier, startParams): Promise<PollResult> => {
    const config = cfg as unknown as GheCopilotConfig;
    const gheUrl = requireGheUrl(startParams?.gheUrl);
    const response = await fetch(`${gheUrl}/login/oauth/access_token`, {
      method: "POST",
      headers: formHeaders(),
      body: new URLSearchParams({
        client_id: config.clientId,
        device_code: deviceCode,
        grant_type: "urn:ietf:params:oauth:grant-type:device_code",
      }).toString(),
    });
    const data = await readJsonOnce(response);
    if (typeof data.access_token === "string" && data.access_token) {
      return { ok: true, data };
    }
    return errorResult(data);
  },

  postExchange: async (tokens, startParams): Promise<GheDetails> => {
    const config = GHE_COPILOT_CONFIG;
    const gheUrl = requireGheUrl(startParams?.gheUrl);
    const accessToken = typeof tokens.access_token === "string" ? tokens.access_token : "";
    const headers = apiHeaders(config, accessToken);

    let copilot: RawTokens | null = null;
    try {
      copilot = await bestEffortJson(
        await fetch(`${gheUrl}/api/v3/copilot_internal/v2/token`, { method: "GET", headers }),
      );
    } catch {
      // Copilot subscription is optional; OAuth connection still succeeds.
    }

    let user: RawTokens | null = null;
    try {
      user = await bestEffortJson(await fetch(`${gheUrl}/api/v3/user`, { method: "GET", headers }));
    } catch {
      // Profile lookup is also best-effort.
    }

    const endpoints = object(copilot?.endpoints);
    return {
      gheUrl,
      copilotApiUrl: typeof endpoints?.api === "string" ? endpoints.api : undefined,
      copilotProxyUrl: typeof endpoints?.proxy === "string" ? endpoints.proxy : undefined,
      copilotToken: typeof copilot?.token === "string" ? copilot.token : undefined,
      copilotTokenExpiresAt: copilot?.expires_at,
      githubUserId: user?.id,
      githubLogin: typeof user?.login === "string" ? user.login : undefined,
      githubName: typeof user?.name === "string" ? user.name : undefined,
      githubEmail: typeof user?.email === "string" ? user.email : undefined,
      autoSync: true,
    };
  },

  refresh: async (cfg, refreshToken, meta) => {
    const config = cfg as unknown as GheCopilotConfig;
    const gheUrl = normalizeGheUrl(meta?.gheUrl);
    if (!gheUrl) throw new Error("no gheUrl in connection meta");
    const response = await fetch(`${gheUrl}/login/oauth/access_token`, {
      method: "POST",
      headers: formHeaders(),
      body: new URLSearchParams({
        grant_type: "refresh_token",
        client_id: config.clientId,
        refresh_token: refreshToken,
      }).toString(),
    });
    const data = await readJsonOnce(response);
    if (
      !response.ok ||
      typeof data.access_token !== "string" ||
      !data.access_token
    ) {
      const reason =
        typeof data.error_description === "string"
          ? data.error_description
          : typeof data.error === "string"
            ? data.error
            : `HTTP ${response.status}`;
      throw new Error(`GHE Copilot token refresh failed: ${reason}`);
    }
    return {
      access_token: data.access_token,
      refresh_token:
        typeof data.refresh_token === "string" && data.refresh_token
          ? data.refresh_token
          : refreshToken,
      ...(typeof data.expires_in === "number" ? { expires_in: data.expires_in } : {}),
    };
  },

  mapTokens: (tokens, extra, priorMeta, priorSecrets) => {
    const details = {
      ...(priorMeta ?? {}),
      ...(extra ?? {}),
    } as Partial<GheDetails>;
    const login = typeof details.githubLogin === "string" ? details.githubLogin : undefined;
    const name = typeof details.githubName === "string" ? details.githubName : undefined;
    const email = typeof details.githubEmail === "string" ? details.githubEmail : undefined;
    const meta = { ...details, autoSync: true };
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
