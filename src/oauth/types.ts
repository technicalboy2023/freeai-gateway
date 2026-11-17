/**
 * OAuth adapter contract — one module per provider, ported from OmniRoute's
 * provider modules. Everything here is web-standard; adapters must never
 * import node APIs.
 */

export type FlowMode = "paste" | "paste-code" | "device";

export interface DeviceCodeResponse {
  device_code: string;
  user_code: string;
  verification_uri: string;
  verification_uri_complete?: string;
  expires_in: number;
  interval: number;
  /** Provider-specific upstream identity (e.g. kimi deviceId) — engine threads it into pending extras. */
  device_id?: string;
}

/** Loose upstream token payload — adapters read the fields their flow returns. */
export interface RawTokens {
  [k: string]: unknown;
}

export interface PollResult {
  ok: boolean;
  data: RawTokens;
}

/** Normalized token payload an adapter produces from a raw one. */
export interface MappedTokens {
  accessToken: string;
  refreshToken?: string | null;
  expiresIn?: number | null;
  email?: string | null;
  name?: string | null;
  meta?: Record<string, unknown>;
  secrets?: Record<string, unknown>;
}

export interface OAuthAdapter {
  prefix: string;
  flowMode: FlowMode;
  config: Record<string, unknown>;
  /** PKCE verifier entropy for paste-code providers (defaults to 32 bytes). */
  pkceVerifierBytes?: number;
  /** paste mode help text shown in the console. */
  instructions?: string;
  /** Static redirect URI override (e.g. a provider-hosted callback). */
  redirectUri?: string;
  /** Extract provider-specific start params from the start request URL (e.g. ?gheUrl=). */
  parseStartParams?(requestUrl: URL): Record<string, unknown> | undefined;
  buildAuthUrl?(
    config: OAuthAdapter["config"],
    redirectUri: string,
    state: string,
    codeChallenge: string,
  ): string;
  exchangeToken?(
    config: OAuthAdapter["config"],
    code: string,
    redirectUri: string,
    codeVerifier: string,
    state: string,
  ): Promise<RawTokens>;
  /**
   * Start a device flow. `codeChallenge` is the S256 challenge of the pending
   * row's verifier (poll receives the verifier twin); `startParams` carries
   * parseStartParams output when the adapter opts in.
   */
  requestDeviceCode?(
    config: OAuthAdapter["config"],
    codeChallenge?: string,
    startParams?: Record<string, unknown>,
  ): Promise<DeviceCodeResponse>;
  pollToken?(
    config: OAuthAdapter["config"],
    deviceCode: string,
    codeVerifier?: string,
    startParams?: Record<string, unknown>,
  ): Promise<PollResult>;
  /** Post-exchange enrichment (e.g. a second token mint) — result feeds mapTokens as extra. */
  postExchange?(tokens: RawTokens, startParams?: Record<string, unknown>): Promise<RawTokens>;
  /** Validate/normalize a pasted token (or decoded blob tokens). */
  importToken?(raw: RawTokens): Promise<RawTokens>;
  /**
   * Non-standard refresh grant; default is a form-encoded refresh_token POST.
   * `meta` is the saved row's meta (device identity etc.) — never regenerated here.
   */
  refresh?(
    config: OAuthAdapter["config"],
    refreshToken: string,
    meta?: Record<string, unknown>,
  ): Promise<RawTokens>;
  mapTokens(
    tokens: RawTokens,
    extra?: Record<string, unknown>,
    priorMeta?: Record<string, unknown>,
    priorSecrets?: Record<string, unknown>,
  ): MappedTokens;
}
