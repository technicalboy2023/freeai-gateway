import type { DeviceCodeResponse, OAuthAdapter, PollResult, RawTokens } from "../types";

/**
 * Recon (OmniRoute release/v3.8.54, CODEBUDDY_CN/INTL_CONFIGS): Tencent's
 * CodeBuddy plugin device auth. One shared flow, two deployments:
 * cn = CLI flavor on copilot.tencent.com, intl = IDE flavor on
 * www.codebuddy.ai. Envelopes are {code, data, msg}; code===0 means ok.
 * User-Agent pins come verbatim from open-sse/config/providerHeaderProfiles.ts
 * — a mismatched version string across auth vs chat calls is exactly the
 * internally-inconsistent fingerprint Tencent's WAF flags (#12702), so both
 * numbers must stay identical to the chat path's pin.
 * Refresh uses the shared CodeBuddy plugin endpoint contract for both
 * deployments while preserving their distinct UA/domain fingerprints.
 */

interface CodeBuddyConfig extends Record<string, unknown> {
  stateUrl: string;
  tokenUrl: string;
  refreshUrl: string;
  platform: string;
  domain: string;
  userAgent: string;
  pollIntervalMs: number;
}

const CN_CONFIG: CodeBuddyConfig = {
  stateUrl: "https://copilot.tencent.com/v2/plugin/auth/state",
  tokenUrl: "https://copilot.tencent.com/v2/plugin/auth/token",
  refreshUrl: "https://copilot.tencent.com/v2/plugin/auth/token/refresh",
  platform: "CLI",
  domain: "copilot.tencent.com",
  userAgent: "CLI/2.108.1 CodeBuddy/2.108.1",
  pollIntervalMs: 5000,
};

const INTL_CONFIG: CodeBuddyConfig = {
  stateUrl: "https://www.codebuddy.ai/v2/plugin/auth/state",
  tokenUrl: "https://www.codebuddy.ai/v2/plugin/auth/token",
  refreshUrl: "https://www.codebuddy.ai/v2/plugin/auth/token/refresh",
  platform: "ide",
  domain: "www.codebuddy.ai",
  userAgent: "IDE/2.108.1 CodeBuddy/2.108.1",
  pollIntervalMs: 5000,
};

function baseHeaders(c: CodeBuddyConfig): Record<string, string> {
  return {
    "content-type": "application/json",
    accept: "application/json",
    "user-agent": c.userAgent,
    "x-requested-with": "XMLHttpRequest",
    "x-domain": c.domain,
    "x-no-authorization": "true",
    "x-no-user-id": "true",
    "x-product": "SaaS",
  };
}

function object(value: unknown): Record<string, unknown> | null {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

async function refreshCodeBuddy(
  config: CodeBuddyConfig,
  refreshToken: string,
): Promise<RawTokens> {
  const response = await fetch(config.refreshUrl, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Accept: "application/json",
      "User-Agent": config.userAgent,
      "X-Requested-With": "XMLHttpRequest",
      "X-Domain": config.domain,
      "X-Refresh-Token": refreshToken,
      "X-Auth-Refresh-Source": "plugin",
      "X-Product": "SaaS",
    },
    body: "{}",
  });
  if (!response.ok) {
    throw new Error(`Failed to refresh CodeBuddy token (${response.status})`);
  }
  let envelope: Record<string, unknown> | null = null;
  try {
    envelope = object(await response.json());
  } catch {
    // Invalid JSON becomes the pinned missing-token error below.
  }
  const data = object(envelope?.data);
  const accessToken =
    typeof data?.accessToken === "string" && data.accessToken ? data.accessToken : "";
  if (envelope?.code !== 0 || !accessToken) {
    throw new Error("CodeBuddy token refresh returned no token");
  }
  return {
    access_token: accessToken,
    refresh_token:
      typeof data?.refreshToken === "string" && data.refreshToken
        ? data.refreshToken
        : refreshToken,
    ...(typeof data?.expiresIn === "number" ? { expires_in: data.expiresIn } : {}),
  };
}

function codeBuddyAdapter(c: CodeBuddyConfig, prefix: string): OAuthAdapter {
  return {
    prefix,
    flowMode: "device",
    config: c,
    requestDeviceCode: async (): Promise<DeviceCodeResponse> => {
      const res = await fetch(`${c.stateUrl}?platform=${encodeURIComponent(c.platform)}`, {
        method: "POST",
        headers: baseHeaders(c),
        body: JSON.stringify({ platform: c.platform }),
      });
      if (!res.ok) throw new Error(`CodeBuddy state request failed (${res.status})`);
      const env = (await res.json().catch(() => null)) as {
        code?: unknown;
        msg?: unknown;
        data?: Record<string, unknown>;
      } | null;
      const state = typeof env?.data?.state === "string" ? env.data.state : null;
      const authUrlRaw = env?.data?.authUrl ?? env?.data?.url;
      const authUrl = typeof authUrlRaw === "string" ? authUrlRaw : null;
      if (env?.code !== 0 || !state || !authUrl) {
        const msg = typeof env?.msg === "string" ? env.msg : "";
        throw new Error(`CodeBuddy state error: ${msg || "no state in response"}`);
      }
      return {
        device_code: state,
        user_code: state,
        verification_uri: authUrl,
        verification_uri_complete: authUrl,
        expires_in: 600,
        interval: Math.max(1, Math.floor(c.pollIntervalMs / 1000)),
      };
    },
    pollToken: async (_config, deviceCode): Promise<PollResult> => {
      const res = await fetch(`${c.tokenUrl}?state=${encodeURIComponent(deviceCode)}`, {
        method: "GET",
        headers: { ...baseHeaders(c), "x-no-enterprise-id": "true", "x-no-department-info": "true" },
      });
      if (!res.ok) return { ok: false, data: { error: "request_failed" } };
      const env = (await res.json().catch(() => null)) as {
        code?: unknown;
        msg?: unknown;
        data?: Record<string, unknown>;
      } | null;
      if (env?.code === 0 && typeof env.data?.accessToken === "string" && env.data.accessToken) {
        const d = env.data;
        const out: RawTokens = { access_token: d.accessToken };
        out.refresh_token = typeof d.refreshToken === "string" ? d.refreshToken : "";
        out.token_type = typeof d.tokenType === "string" ? d.tokenType : "Bearer";
        out.expires_in = d.expiresIn;
        return { ok: true, data: out };
      }
      return {
        ok: false,
        data: {
          code: env?.code as number,
          msg: typeof env?.msg === "string" ? env.msg : "",
        },
      };
    },
    refresh: async (_config, refreshToken) => refreshCodeBuddy(c, refreshToken),
    mapTokens: (tokens) => ({
      accessToken: String(tokens.access_token ?? ""),
      refreshToken: (tokens.refresh_token as string) || null,
      expiresIn: (tokens.expires_in as number) ?? 86400,
    }),
  };
}

export const codebuddyCnAdapter: OAuthAdapter = codeBuddyAdapter(CN_CONFIG, "codebuddy-cn");
export const codebuddyIntlAdapter: OAuthAdapter = codeBuddyAdapter(INTL_CONFIG, "codebuddy-intl");
