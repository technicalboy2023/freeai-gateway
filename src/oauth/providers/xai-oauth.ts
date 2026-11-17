import type { OAuthAdapter, RawTokens } from "../types";
import { decodeJwtPayload } from "./jwt";

/** xAI's native CLI OAuth client uses a loopback redirect and longer PKCE verifier. */

interface XaiConfig extends Record<string, unknown> {
  clientId: string;
  authorizeUrl: string;
  tokenUrl: string;
  redirectUri: string;
  scope: string;
}

const XAI_CONFIG: XaiConfig = {
  clientId: "b1a00492-073a-47ea-816f-4c329264a828",
  authorizeUrl: "https://auth.x.ai/oauth2/authorize",
  tokenUrl: "https://auth.x.ai/oauth2/token",
  redirectUri: "http://127.0.0.1:56121/callback",
  scope: "openid profile email offline_access grok-cli:access api:access",
};

function nonce(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function nonEmptyString(value: unknown): string | null {
  return typeof value === "string" && value ? value : null;
}

function object(value: unknown): RawTokens | null {
  return value && typeof value === "object" && !Array.isArray(value) ? (value as RawTokens) : null;
}

async function responseJson(response: Response): Promise<RawTokens> {
  const text = await response.text();
  try {
    return object(JSON.parse(text)) ?? {};
  } catch {
    return {};
  }
}

export const xaiOAuthAdapter: OAuthAdapter = {
  prefix: "xai-oauth",
  flowMode: "paste-code",
  config: XAI_CONFIG,
  redirectUri: XAI_CONFIG.redirectUri,
  pkceVerifierBytes: 96,
  instructions:
    "Open the authorization URL, sign in, then copy the code from the loopback callback address bar and paste it here.",

  buildAuthUrl: (cfg, _redirectUri, state, codeChallenge) => {
    const config = cfg as unknown as XaiConfig;
    const params = new URLSearchParams({
      response_type: "code",
      client_id: config.clientId,
      redirect_uri: config.redirectUri,
      scope: config.scope,
      code_challenge: codeChallenge,
      code_challenge_method: "S256",
      state,
      nonce: nonce(),
      plan: "generic",
      referrer: "cli-proxy-api",
    });
    return `${config.authorizeUrl}?${params.toString()}`;
  },

  exchangeToken: async (cfg, code, redirectUri, codeVerifier): Promise<RawTokens> => {
    const config = cfg as unknown as XaiConfig;
    const response = await fetch(config.tokenUrl, {
      method: "POST",
      headers: {
        Accept: "application/json",
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        client_id: config.clientId,
        code,
        redirect_uri: redirectUri,
        code_verifier: codeVerifier,
      }).toString(),
    });
    const data = await responseJson(response);
    if (!response.ok) {
      const detail =
        (typeof data.error_description === "string" && data.error_description) ||
        (typeof data.error === "string" && data.error) ||
        `HTTP ${response.status}`;
      throw new Error(`xAI token exchange failed: ${detail}`);
    }
    return data;
  },

  mapTokens: (tokens) => {
    const idToken = typeof tokens.id_token === "string" ? tokens.id_token : "";
    const payload = idToken ? decodeJwtPayload(idToken) : null;
    const email =
      nonEmptyString(payload?.email) ??
      nonEmptyString(payload?.preferred_username);
    const name = nonEmptyString(payload?.name) ?? email;
    const config = XAI_CONFIG;
    return {
      accessToken: typeof tokens.access_token === "string" ? tokens.access_token : "",
      refreshToken: typeof tokens.refresh_token === "string" ? tokens.refresh_token : null,
      expiresIn: typeof tokens.expires_in === "number" ? tokens.expires_in : null,
      email,
      name,
      meta: {
        scope: nonEmptyString(tokens.scope) ?? config.scope,
        tokenType: nonEmptyString(tokens.token_type) ?? "Bearer",
      },
    };
  },
};
