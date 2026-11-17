import type { DeviceCodeResponse, OAuthAdapter, PollResult, RawTokens } from "../types";

/**
 * Recon (OmniRoute release/v3.8.54, KILOCODE_CONFIG): device flow on
 * api.kilo.ai. The device "code" doubles as the user code (shown in the
 * console); polls answer 202 pending / 403 denied / 410 expired and a 200
 * approved envelope. Refresh: none (tokens are long-lived, no grant).
 */

interface KilocodeConfig extends Record<string, unknown> {
  initiateUrl: string;
  pollUrlBase: string;
}

const KILOCODE_CONFIG: KilocodeConfig = {
  initiateUrl: "https://api.kilo.ai/api/device-auth/codes",
  pollUrlBase: "https://api.kilo.ai/api/device-auth/codes",
};

export const kilocodeAdapter: OAuthAdapter = {
  prefix: "kilocode",
  flowMode: "device",
  config: KILOCODE_CONFIG,
  requestDeviceCode: async (cfg): Promise<DeviceCodeResponse> => {
    const c = cfg as unknown as KilocodeConfig;
    const res = await fetch(c.initiateUrl, {
      method: "POST",
      headers: { "content-type": "application/json" },
    });
    if (!res.ok) {
      if (res.status === 429) {
        throw new Error("Too many pending authorization requests. Please try again later.");
      }
      throw new Error(`Device auth initiation failed: ${await res.text()}`);
    }
    const payload = (await res.json().catch(() => null)) as
      | { data?: { code?: unknown; link?: unknown; expiresIn?: unknown } | null }
      | null;
    const code = typeof payload?.data?.code === "string" ? payload.data.code.trim() : "";
    if (!code) {
      throw new Error("Kilocode device auth response is missing code");
    }
    const verificationUrl = typeof payload?.data?.link === "string" ? payload.data.link.trim() : "";
    if (!verificationUrl) {
      throw new Error("Kilocode device auth response is missing link");
    }
    return {
      device_code: code,
      user_code: code,
      verification_uri: verificationUrl,
      verification_uri_complete: verificationUrl,
      expires_in: typeof payload?.data?.expiresIn === "number" ? payload.data.expiresIn : 300,
      interval: 3,
    };
  },
  pollToken: async (cfg, deviceCode): Promise<PollResult> => {
    const c = cfg as unknown as KilocodeConfig;
    const res = await fetch(`${c.pollUrlBase}/${deviceCode}`, { method: "GET" });
    if (res.status === 202) return { ok: false, data: { error: "authorization_pending" } };
    if (res.status === 403) {
      return { ok: false, data: { error: "access_denied", error_description: "Authorization denied by user" } };
    }
    if (res.status === 410) {
      return { ok: false, data: { error: "expired_token", error_description: "Authorization code expired" } };
    }
    if (!res.ok) {
      return { ok: false, data: { error: "poll_failed", error_description: `Poll failed: ${res.status}` } };
    }
    const data = (await res.json().catch(() => null)) as {
      status?: unknown;
      token?: unknown;
      userEmail?: unknown;
    } | null;
    if (data && typeof data.token === "string" && data.token) {
      const out: RawTokens = { access_token: data.token };
      if (typeof data.userEmail === "string") out._userEmail = data.userEmail;
      return { ok: true, data: out };
    }
    return { ok: false, data: { error: "authorization_pending" } };
  },
  mapTokens: (tokens) => ({
    accessToken: String(tokens.access_token ?? ""),
    refreshToken: null,
    expiresIn: null,
    email: (tokens._userEmail as string) ?? null,
  }),
};
