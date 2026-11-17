import type { OAuthAdapter, RawTokens } from "../types";
import { decodeJwtPayload } from "./jwt";

/** Openference authorization-code OAuth with best-effort OIDC userinfo. */

interface OpenferenceConfig extends Record<string, unknown> {
  clientId: string;
  authorizeUrl: string;
  tokenUrl: string;
  userinfoUrl: string;
  redirectUri: string;
  scope: string;
}

const OPENFERENCE_CONFIG: OpenferenceConfig = {
  clientId: "omniroute",
  authorizeUrl: "https://openference.com/app/oauth/authorize",
  tokenUrl: "https://openference.com/oauth/token",
  userinfoUrl: "https://openference.com/oauth/userinfo",
  redirectUri: "http://127.0.0.1:56123/callback",
  scope: "openid profile email model:invoke offline_access",
};

function object(value: unknown): RawTokens | null {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as RawTokens)
    : null;
}

function nonEmptyString(value: unknown): string | null {
  return typeof value === "string" && value ? value : null;
}

async function responseJson(response: Response): Promise<RawTokens> {
  const text = await response.text();
  try {
    return object(JSON.parse(text)) ?? {};
  } catch {
    return {};
  }
}

export const openferenceAdapter: OAuthAdapter = {
  prefix: "openference",
  flowMode: "paste-code",
  config: OPENFERENCE_CONFIG,
  redirectUri: OPENFERENCE_CONFIG.redirectUri,
  instructions:
    "Open the authorization URL, sign in, then copy the code from the loopback callback address bar and paste it here.",

  buildAuthUrl: (cfg, _redirectUri, state, codeChallenge) => {
    const config = cfg as unknown as OpenferenceConfig;
    const params = new URLSearchParams({
      response_type: "code",
      client_id: config.clientId,
      redirect_uri: config.redirectUri,
      scope: config.scope,
      code_challenge: codeChallenge,
      code_challenge_method: "S256",
      state,
    });
    return `${config.authorizeUrl}?${params.toString()}`;
  },

  exchangeToken: async (cfg, code, redirectUri, codeVerifier): Promise<RawTokens> => {
    const config = cfg as unknown as OpenferenceConfig;
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
        redirect_uri: redirectUri || config.redirectUri,
        code_verifier: codeVerifier,
      }).toString(),
    });
    const data = await responseJson(response);
    if (!response.ok) {
      const detail =
        nonEmptyString(data.error_description) ??
        nonEmptyString(data.error) ??
        `HTTP ${response.status}`;
      throw new Error(`Openference token exchange failed: ${detail}`);
    }
    return data;
  },

  postExchange: async (tokens): Promise<RawTokens> => {
    const accessToken = nonEmptyString(tokens.access_token);
    if (!accessToken) return {};
    try {
      const response = await fetch(OPENFERENCE_CONFIG.userinfoUrl, {
        method: "GET",
        headers: {
          Authorization: `Bearer ${accessToken}`,
          Accept: "application/json",
        },
      });
      if (!response.ok) return {};
      return await responseJson(response);
    } catch {
      return {};
    }
  },

  mapTokens: (tokens, extra) => {
    const idToken = nonEmptyString(tokens.id_token);
    const claims = idToken ? decodeJwtPayload(idToken) : null;
    const userinfo = extra ?? {};
    const idEmail =
      nonEmptyString(claims?.email) ??
      nonEmptyString(claims?.preferred_username);
    const userinfoEmail =
      nonEmptyString(userinfo.email) ??
      nonEmptyString(userinfo.preferred_username);
    const email = idEmail ?? userinfoEmail;
    const name =
      nonEmptyString(claims?.name) ??
      nonEmptyString(userinfo.name) ??
      nonEmptyString(userinfo.email) ??
      nonEmptyString(userinfo.preferred_username) ??
      email;
    return {
      accessToken: nonEmptyString(tokens.access_token) ?? "",
      refreshToken: nonEmptyString(tokens.refresh_token),
      expiresIn: typeof tokens.expires_in === "number" ? tokens.expires_in : null,
      email,
      name,
      meta: {
        scope: nonEmptyString(tokens.scope) ?? OPENFERENCE_CONFIG.scope,
        tokenType: nonEmptyString(tokens.token_type) ?? "Bearer",
      },
    };
  },
};
