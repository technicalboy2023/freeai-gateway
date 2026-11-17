import type { DeviceCodeResponse, OAuthAdapter, PollResult, RawTokens } from "../types";

/**
 * Recon (OmniRoute release/v3.8.54, FREEBUFF_CONFIG): CodeBuddy-style CLI
 * device login on freebuff.com. The "device code" is a self-contained
 * base64url blob {fingerprintId, fingerprintHash, expiresAt} — the adapter
 * re-decodes it on every poll instead of relying on server-side state.
 * No refresh grant: tokens are long-lived, reconnect when expired.
 */

interface FreebuffConfig extends Record<string, unknown> {
  codeUrl: string;
  statusUrl: string;
}

const FREEBUFF_CONFIG: FreebuffConfig = {
  codeUrl: "https://freebuff.com/api/auth/cli/code",
  statusUrl: "https://freebuff.com/api/auth/cli/status",
};

const FINGERPRINT_PREFIX = "codebuff-cli-";
const POLL_INTERVAL_SEC = 5;

export function toBase64Url(s: string): string {
  return s.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function fromBase64Url(s: string): string {
  const std = s.replace(/-/g, "+").replace(/_/g, "/");
  return atob(std + "=".repeat((4 - (std.length % 4)) % 4));
}

function newFingerprintId(): string {
  const bytes = new Uint8Array(6); // 6 bytes → exactly 8 base64url chars
  crypto.getRandomValues(bytes);
  return FINGERPRINT_PREFIX + toBase64Url(btoa(String.fromCharCode(...bytes)));
}

/** ISO date or epoch-ms digits → epoch ms, else null. */
function parseExpiry(raw: unknown): number | null {
  if (typeof raw === "number" && Number.isFinite(raw)) return raw;
  if (typeof raw !== "string" || !raw) return null;
  if (/^\d+$/.test(raw)) {
    const n = Number(raw);
    return Number.isFinite(n) ? n : null;
  }
  const t = new Date(raw).getTime();
  return Number.isFinite(t) ? t : null;
}

interface FreebuffState {
  fingerprintId: string;
  fingerprintHash: string;
  expiresAt: string;
}

function decodeState(deviceCode: string): FreebuffState | null {
  try {
    const state = JSON.parse(fromBase64Url(deviceCode)) as FreebuffState;
    if (typeof state?.fingerprintId !== "string" || typeof state?.fingerprintHash !== "string") {
      return null;
    }
    return state;
  } catch {
    return null;
  }
}

export const freebuffAdapter: OAuthAdapter = {
  prefix: "freebuff",
  flowMode: "device",
  config: FREEBUFF_CONFIG,
  requestDeviceCode: async (cfg): Promise<DeviceCodeResponse> => {
    const c = cfg as unknown as FreebuffConfig;
    const fingerprintId = newFingerprintId();
    const res = await fetch(c.codeUrl, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ fingerprintId }),
    });
    if (!res.ok) throw new Error(`Freebuff login URL request failed (${res.status})`);
    const data = (await res.json().catch(() => null)) as Record<string, unknown> | null;
    const loginUrl = typeof data?.loginUrl === "string" ? data.loginUrl : null;
    const fingerprintHash = typeof data?.fingerprintHash === "string" ? data.fingerprintHash : null;
    const expiresAtMs = parseExpiry(data?.expiresAt);
    if (!loginUrl || !fingerprintHash || expiresAtMs === null) {
      throw new Error("Freebuff login URL response is missing required fields");
    }
    const expiresAt = String(data!.expiresAt);
    return {
      device_code: toBase64Url(btoa(JSON.stringify({ fingerprintId, fingerprintHash, expiresAt }))),
      user_code: fingerprintId.slice(FINGERPRINT_PREFIX.length),
      verification_uri: loginUrl,
      verification_uri_complete: loginUrl,
      expires_in: Math.max(1, Math.floor((expiresAtMs - Date.now()) / 1000)),
      interval: POLL_INTERVAL_SEC,
    };
  },
  pollToken: async (cfg, deviceCode): Promise<PollResult> => {
    const c = cfg as unknown as FreebuffConfig;
    const state = decodeState(deviceCode);
    if (!state) {
      return { ok: false, data: { error: "invalid_request", error_description: "Malformed Freebuff login state" } };
    }
    const expiresAtMs = parseExpiry(state.expiresAt) ?? 0;
    const expired = expiresAtMs <= Date.now();
    const expiredResult: PollResult = {
      ok: false,
      data: { error: "expired_token", error_description: "Freebuff login expired" },
    };

    const res = await fetch(
      `${c.statusUrl}?fingerprintId=${encodeURIComponent(state.fingerprintId)}` +
        `&fingerprintHash=${encodeURIComponent(state.fingerprintHash)}` +
        `&expiresAt=${encodeURIComponent(state.expiresAt)}`,
      { method: "GET" },
    );
    if (!res.ok) {
      if (expired) return expiredResult;
      if (res.status === 429 || res.status >= 500) return { ok: false, data: { error: "slow_down" } };
      return { ok: false, data: { error: "authorization_pending" } };
    }

    let data: Record<string, unknown> | null = null;
    try {
      data = JSON.parse(await res.text()) as Record<string, unknown>;
    } catch {
      data = null;
    }
    const user = (data?.user ?? {}) as Record<string, unknown>;
    if (typeof user.authToken === "string" && user.authToken) {
      const out: RawTokens = { access_token: user.authToken, _fingerprintId: state.fingerprintId };
      if (typeof user.id === "string") out._userId = user.id;
      if (typeof user.email === "string") out._userEmail = user.email;
      if (typeof user.name === "string") out._userName = user.name;
      return { ok: true, data: out };
    }
    return expired ? expiredResult : { ok: false, data: { error: "authorization_pending" } };
  },
  mapTokens: (tokens) => {
    const meta: Record<string, unknown> = {};
    if (typeof tokens._userId === "string") meta.userId = tokens._userId;
    if (typeof tokens._fingerprintId === "string") meta.fingerprintId = tokens._fingerprintId;
    return {
      accessToken: String(tokens.access_token ?? ""),
      refreshToken: null,
      expiresIn: null,
      email: (tokens._userEmail as string) ?? null,
      name: (tokens._userName as string) ?? null,
      ...(Object.keys(meta).length ? { meta } : {}),
    };
  },
};
