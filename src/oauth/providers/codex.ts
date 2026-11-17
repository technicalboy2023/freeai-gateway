import type { OAuthAdapter, RawTokens } from "../types";
import { decodeJwtPayload } from "./jwt";

/**
 * OpenAI Codex OAuth. Unlike the other paste-code providers, the provider
 * redirects back to this gateway so its callback can complete the flow.
 */

interface CodexConfig extends Record<string, unknown> {
  clientId: string;
  authorizeUrl: string;
  tokenUrl: string;
  scope: string;
}

interface Organization extends Record<string, unknown> {
  id?: unknown;
  is_default?: unknown;
  role?: unknown;
  title?: unknown;
}

const OPENAI_AUTH = "https://api.openai.com/auth";
const CODEX_CONFIG: CodexConfig = {
  clientId: "app_EMoamEEZ73f0CkXaXp7hrann",
  authorizeUrl: "https://auth.openai.com/oauth/authorize",
  tokenUrl: "https://auth.openai.com/oauth/token",
  scope: "openid profile email offline_access",
};

function object(value: unknown): Record<string, unknown> | null {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

function nonEmptyString(value: unknown): string | null {
  return typeof value === "string" && value ? value : null;
}

function organizationsFrom(value: unknown): Organization[] | null {
  if (!Array.isArray(value)) return null;
  return value.filter((item): item is Organization => object(item) !== null);
}

function selectWorkspace(authInfo: Record<string, unknown> | null): {
  workspaceId: unknown;
  workspacePlanType: unknown;
  chatgptUserId: unknown;
  organizations: Organization[] | null;
} {
  if (!authInfo) {
    return {
      workspaceId: null,
      workspacePlanType: null,
      chatgptUserId: null,
      organizations: null,
    };
  }
  const accountId = authInfo.chatgpt_account_id ?? null;
  const rawPlanType = nonEmptyString(authInfo.chatgpt_plan_type);
  const planType = rawPlanType?.toLowerCase() ?? null;
  const organizations = organizationsFrom(authInfo.organizations);

  if ((planType === "team" || planType === "chatgptteam") && accountId) {
    return {
      workspaceId: accountId,
      workspacePlanType: rawPlanType,
      chatgptUserId: authInfo.chatgpt_user_id ?? null,
      organizations,
    };
  }

  const selectedOrg = organizations?.find((org) => {
    if (org.is_default === true) return false;
    const title = typeof org.title === "string" ? org.title.toLowerCase() : "";
    const role = typeof org.role === "string" ? org.role.toLowerCase() : "";
    return (
      /(team|business|workspace|org)/.test(title) ||
      role === "admin" ||
      role === "member"
    );
  });
  if (selectedOrg?.id) {
    return {
      workspaceId: selectedOrg.id,
      workspacePlanType: "team",
      chatgptUserId: authInfo.chatgpt_user_id ?? null,
      organizations,
    };
  }
  return {
    workspaceId: accountId,
    workspacePlanType: rawPlanType,
    chatgptUserId: authInfo.chatgpt_user_id ?? null,
    organizations,
  };
}

async function responseJson(response: Response): Promise<RawTokens> {
  const text = await response.text();
  try {
    return object(JSON.parse(text)) ?? {};
  } catch {
    return {};
  }
}

export const codexAdapter: OAuthAdapter = {
  prefix: "codex",
  flowMode: "paste-code",
  config: CODEX_CONFIG,
  instructions:
    "Open the login URL and sign in. The provider redirects back to this gateway and the state-matched callback completes login automatically; no code paste is needed.",

  buildAuthUrl: (cfg, redirectUri, state, codeChallenge) => {
    const config = cfg as unknown as CodexConfig;
    const params = new URLSearchParams({
      response_type: "code",
      client_id: config.clientId,
      redirect_uri: redirectUri,
      scope: config.scope,
      code_challenge: codeChallenge,
      code_challenge_method: "S256",
      id_token_add_organizations: "true",
      codex_cli_simplified_flow: "true",
      originator: "codex_cli_rs",
      prompt: "login",
      state,
    });
    return `${config.authorizeUrl}?${params.toString()}`;
  },

  exchangeToken: async (cfg, code, redirectUri, codeVerifier): Promise<RawTokens> => {
    const config = cfg as unknown as CodexConfig;
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
      throw new Error(`Codex token exchange failed: ${detail}`);
    }
    return data;
  },

  postExchange: async (tokens): Promise<RawTokens> => {
    const idToken = typeof tokens.id_token === "string" ? tokens.id_token : "";
    const payload = idToken ? decodeJwtPayload(idToken) : null;
    const authInfo = object(payload?.[OPENAI_AUTH]);
    return {
      email: nonEmptyString(payload?.email),
      authInfo,
    };
  },

  mapTokens: (tokens, extra, priorMeta) => {
    const authInfo = object(extra?.authInfo);
    const selected = selectWorkspace(authInfo);
    const prior = priorMeta ?? {};
    const workspaceId = authInfo ? selected.workspaceId : (prior.workspaceId ?? null);
    const workspacePlanType = authInfo
      ? selected.workspacePlanType
      : (prior.workspacePlanType ?? null);
    const chatgptUserId = authInfo ? selected.chatgptUserId : (prior.chatgptUserId ?? null);
    const organizations = authInfo
      ? selected.organizations
      : (prior.organizations ?? null);
    const email =
      nonEmptyString(extra?.email) ??
      (typeof prior.email === "string" ? prior.email : null);
    return {
      accessToken: typeof tokens.access_token === "string" ? tokens.access_token : "",
      refreshToken: typeof tokens.refresh_token === "string" ? tokens.refresh_token : null,
      expiresIn: typeof tokens.expires_in === "number" ? tokens.expires_in : null,
      email,
      name: email,
      meta: {
        ...prior,
        workspaceId,
        workspacePlanType,
        chatgptUserId,
        organizations,
      },
    };
  },
};
