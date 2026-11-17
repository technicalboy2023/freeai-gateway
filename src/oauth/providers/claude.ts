import type { OAuthAdapter, RawTokens } from "../types";

/**
 * Claude Code's browser OAuth and setup-token import. Browser grants are
 * enriched with Claude CLI bootstrap account data; setup tokens are live
 * validated and intentionally have no refresh grant.
 */

interface ClaudeConfig extends Record<string, unknown> {
  clientId: string;
  authorizeUrl: string;
  tokenUrl: string;
  redirectUri: string;
  scopes: string;
  bootstrapUrl: string;
  bootstrapUserAgent: string;
  beta: string;
  setupTokenPrefix: string;
  validationModel: string;
}

const CLAUDE_CONFIG: ClaudeConfig = {
  clientId: "9d1c250a-e61b-44d9-88ed-5944d1962f5e",
  authorizeUrl: "https://claude.ai/oauth/authorize",
  tokenUrl: "https://api.anthropic.com/v1/oauth/token",
  redirectUri: "https://platform.claude.com/oauth/code/callback",
  scopes: "org:create_api_key user:profile user:inference user:sessions:claude_code user:mcp_servers",
  bootstrapUrl: "https://api.anthropic.com/api/claude_cli/bootstrap",
  bootstrapUserAgent: "claude-cli/2.1.7 (external, cli)",
  beta: "oauth-2025-04-20",
  setupTokenPrefix: "sk-ant-oat",
  validationModel: "claude-haiku-4-5-20251001",
};

const SETUP_TOKEN_TTL_SEC = 31_536_000;

function object(value: unknown): RawTokens | null {
  return value && typeof value === "object" && !Array.isArray(value) ? (value as RawTokens) : null;
}

function cliUserId(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

async function responseJson(response: Response): Promise<RawTokens> {
  const text = await response.text();
  try {
    return object(JSON.parse(text)) ?? {};
  } catch {
    return {};
  }
}

function tokenError(data: RawTokens, status: number): Error {
  const detail =
    (typeof data.error_description === "string" && data.error_description) ||
    (typeof data.error === "string" && data.error) ||
    `HTTP ${status}`;
  return new Error(`Claude token request failed: ${detail}`);
}

function accountField(
  key: "account_uuid" | "email" | "organizationName" | "organizationRole",
  extra?: Record<string, unknown>,
  priorMeta?: Record<string, unknown>,
): unknown {
  return extra?.[key] ?? priorMeta?.[key];
}

export const claudeAdapter: OAuthAdapter = {
  prefix: "claude",
  flowMode: "paste-code",
  config: CLAUDE_CONFIG,
  redirectUri: CLAUDE_CONFIG.redirectUri,
  instructions:
    "Open the authorization URL, sign in, then copy the code from the callback URL (it may look like code#state) and paste it here. Or use the token-paste box with a Claude setup token starting with sk-ant-oat…",

  buildAuthUrl: (cfg, _redirectUri, state, codeChallenge) => {
    const config = cfg as unknown as ClaudeConfig;
    const params = new URLSearchParams({
      response_type: "code",
      client_id: config.clientId,
      redirect_uri: config.redirectUri,
      scope: config.scopes,
      code_challenge: codeChallenge,
      code_challenge_method: "S256",
      code: "true",
      prompt: "login",
      state,
    });
    return `${config.authorizeUrl}?${params.toString()}`;
  },

  exchangeToken: async (cfg, code, redirectUri, codeVerifier): Promise<RawTokens> => {
    const config = cfg as unknown as ClaudeConfig;
    const response = await fetch(config.tokenUrl, {
      method: "POST",
      headers: {
        Accept: "application/json",
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        client_id: config.clientId,
        code: code.split("#", 1)[0],
        redirect_uri: redirectUri || config.redirectUri,
        code_verifier: codeVerifier,
      }).toString(),
    });
    const data = await responseJson(response);
    if (!response.ok) throw tokenError(data, response.status);
    return data;
  },

  postExchange: async (tokens, _startParams): Promise<RawTokens> => {
    const config = CLAUDE_CONFIG;
    const accessToken = typeof tokens.access_token === "string" ? tokens.access_token : "";
    try {
      const response = await fetch(config.bootstrapUrl, {
        method: "GET",
        headers: {
          Authorization: `Bearer ${accessToken}`,
          Accept: "application/json",
          "User-Agent": config.bootstrapUserAgent,
          "anthropic-beta": config.beta,
        },
        signal: AbortSignal.timeout(10_000),
      });
      if (!response.ok) return {};
      const data = await responseJson(response);
      return {
        account_uuid: data.account_uuid,
        email: data.email,
        organizationName: data.organizationName,
        organizationRole: data.organizationRole,
      };
    } catch {
      // Bootstrap is best-effort. OAuth credentials are still usable without
      // organization/profile enrichment.
      return {};
    }
  },

  importToken: async (raw): Promise<RawTokens> => {
    const config = CLAUDE_CONFIG;
    const accessToken = typeof raw.access_token === "string" ? raw.access_token.trim() : "";
    if (!accessToken.startsWith(config.setupTokenPrefix)) {
      throw new Error(`paste a setup token starting with ${config.setupTokenPrefix}`);
    }
    const response = await fetch("https://api.anthropic.com/v1/messages", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${accessToken}`,
        "anthropic-version": "2023-06-01",
        "anthropic-beta": config.beta,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        model: config.validationModel,
        max_tokens: 1,
        messages: [{ role: "user", content: "test" }],
      }),
    });
    if (response.status === 401 || response.status === 403) {
      throw new Error("Invalid OAuth token");
    }
    if (response.status >= 500) {
      throw new Error(`Provider unavailable (${response.status})`);
    }
    if (!response.ok) {
      throw new Error(`Claude setup-token validation failed (HTTP ${response.status})`);
    }
    return { access_token: accessToken, tokenKind: "setup" };
  },

  refresh: async (cfg, refreshToken, meta): Promise<RawTokens> => {
    const config = cfg as unknown as ClaudeConfig;
    if (meta?.tokenKind === "setup") {
      throw new Error("no refresh grant for setup tokens");
    }
    const response = await fetch(config.tokenUrl, {
      method: "POST",
      headers: {
        Accept: "application/json",
        "Content-Type": "application/x-www-form-urlencoded",
        "anthropic-beta": config.beta,
      },
      body: new URLSearchParams({
        grant_type: "refresh_token",
        refresh_token: refreshToken,
        client_id: config.clientId,
      }).toString(),
    });
    const data = await responseJson(response);
    if (!response.ok || typeof data.access_token !== "string" || !data.access_token) {
      throw tokenError(data, response.status);
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

  mapTokens: (tokens, extra, priorMeta) => {
    const accountUuid = accountField("account_uuid", extra, priorMeta);
    const email = accountField("email", extra, priorMeta);
    const organizationName = accountField("organizationName", extra, priorMeta);
    const organizationRole = accountField("organizationRole", extra, priorMeta);
    const inheritedCliId =
      typeof priorMeta?.cliUserID === "string" && priorMeta.cliUserID
        ? priorMeta.cliUserID
        : undefined;
    const tokenKind =
      tokens.tokenKind === "setup" || priorMeta?.tokenKind === "setup"
        ? "setup"
        : priorMeta?.tokenKind === "oauth"
          ? "oauth"
          : "oauth";
    const setupToken = tokenKind === "setup";
    const meta: Record<string, unknown> = {
      ...(priorMeta ?? {}),
      ...(extra ?? {}),
      cliUserID: inheritedCliId ?? cliUserId(),
      tokenKind,
    };
    for (const [key, value] of Object.entries({
      account_uuid: accountUuid,
      email,
      organizationName,
      organizationRole,
    })) {
      if (value !== undefined && value !== null) meta[key] = value;
    }
    return {
      accessToken: typeof tokens.access_token === "string" ? tokens.access_token : "",
      refreshToken: setupToken
        ? null
        : typeof tokens.refresh_token === "string"
          ? tokens.refresh_token
          : null,
      expiresIn:
        typeof tokens.expires_in === "number"
          ? tokens.expires_in
          : setupToken
            ? SETUP_TOKEN_TTL_SEC
            : null,
      email: typeof email === "string" ? email : null,
      name:
        typeof email === "string"
          ? email
          : typeof accountUuid === "string"
            ? accountUuid
            : null,
      meta,
    };
  },
};
