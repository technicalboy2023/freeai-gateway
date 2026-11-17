import type { OAuthAdapter } from "../types";

/**
 * Recon (OmniRoute release/v3.8.54, TRAE_CONFIG): paste-only Cloud-IDE-JWT.
 * The JWT expires in ~14 days and carries no refresh grant — reconnect when
 * the console shows it expired. Fields the JWT envelope may carry are copied
 * into meta (camelCase wins over snake_case); missing optional fields fall
 * back to the OmniRoute defaults or "".
 */

const TRAE_LIFETIME_SEC = 14 * 86400;

function pick(tokens: Record<string, unknown>, ...keys: string[]): string {
  for (const k of keys) {
    const v = tokens[k];
    if (typeof v === "string" && v) return v;
    if (typeof v === "number") return String(v);
  }
  return "";
}

export const traeAdapter: OAuthAdapter = {
  prefix: "trae",
  flowMode: "paste",
  config: {},
  instructions:
    "Authorize via trae.ai in the popup, or sign in to solo.trae.ai and paste the Cloud-IDE-JWT from the Authorization header (~14-day lifetime).",
  importToken: async (raw) => {
    // The instructions point at the Authorization header, so a naive copy
    // arrives as "Bearer eyJ…" (often with a trailing newline). Storing that
    // verbatim breaks every forward call — normalize before saving.
    const token = (typeof raw.access_token === "string" ? raw.access_token : "")
      .trim()
      .replace(/^bearer\b\s*/i, "");
    if (!token) throw new Error("Token looks empty after trimming the pasted Authorization header");
    return { access_token: token };
  },
  mapTokens: (tokens) => ({
    accessToken: (tokens.accessToken as string) ?? (tokens.access_token as string) ?? "",
    refreshToken: (tokens.refreshToken as string) ?? null,
    expiresIn: (tokens.expiresIn as number) ?? TRAE_LIFETIME_SEC,
    meta: {
      webId: pick(tokens, "webId", "web_id"),
      bizUserId: pick(tokens, "bizUserId", "biz_user_id"),
      userUniqueId: pick(tokens, "userUniqueId", "user_unique_id"),
      scope: "marscode-us",
      tenant: "marscode",
      region: "US-East",
      aiRegion: pick(tokens, "aiRegion", "ai_region", "region"),
      appLanguage: pick(tokens, "appLanguage", "app_language") || "en",
      appVersion: pick(tokens, "appVersion", "app_version") || "1.0.0.1229",
      userRegion: pick(tokens, "userRegion", "user_region") || "US",
      userTimezone: pick(tokens, "userTimezone", "user_timezone"),
      userIdentity: pick(tokens, "userIdentity", "user_identity") || "Free",
      authMethod: "imported",
    },
  }),
};
