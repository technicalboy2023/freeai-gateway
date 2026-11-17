import type { OAuthAdapter } from "../types";

/**
 * Recon (OmniRoute release/v3.8.54, DEVIN_DESKTOP_CONFIG): Devin session
 * tokens are signed in via browser and must carry the exact
 * `devin-session-token$` prefix — normalize to exactly one. The browser-PKCE
 * variant is deferred to Wave B Plan 2 (ledger).
 */

const TOKEN_PREFIX = "devin-session-token$";

export const devinDesktopAdapter: OAuthAdapter = {
  prefix: "devin-desktop",
  flowMode: "paste",
  config: {},
  instructions: "Paste the Devin session token from an authenticated Devin session (browser sign-in).",
  importToken: async (raw) => {
    const token = typeof raw.access_token === "string" ? raw.access_token.trim() : "";
    if (!token) throw new Error("Token is empty");
    if (token.length < 16) throw new Error("Token is too short");
    const normalized = token.startsWith(TOKEN_PREFIX) ? token : `${TOKEN_PREFIX}${token}`;
    return { access_token: normalized };
  },
  mapTokens: (tokens) => ({
    accessToken: String(tokens.access_token ?? ""),
    refreshToken: null,
    expiresIn: null,
  }),
};
