/**
 * Paste-safe credential blob codec — port of OmniRoute credentialBlob.ts.
 *
 * When a provider's OAuth redirect cannot reach this worker (loopback-only
 * clients on a remote deployment), a login performed elsewhere produces a raw
 * token response; this codec wraps it in one copy-paste-safe line:
 * `freeai-cred-v1.<base64url(JSON)>`. No `+`, `/`, `=` or whitespace, so it
 * survives terminals, notes and URL bars.
 */

export const CREDENTIAL_BLOB_PREFIX = "freeai-cred-v1.";
const CREDENTIAL_BLOB_VERSION = 1;
const MAX_BODY_CHARS = 16384;

export interface CredentialBlob {
  provider: string;
  tokens: Record<string, unknown>;
}

function toBase64Url(json: string): string {
  const bytes = new TextEncoder().encode(json);
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function fromBase64Url(body: string): string {
  const normalized = body.replace(/-/g, "+").replace(/_/g, "/");
  const padded = normalized + "=".repeat((4 - (normalized.length % 4)) % 4);
  const bin = atob(padded);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return new TextDecoder().decode(bytes);
}

/** Encode a provider + raw token response into one paste-safe line. */
export function encodeCredentialBlob(input: CredentialBlob): string {
  if (!input || typeof input.provider !== "string" || !input.provider.trim()) {
    throw new Error("encodeCredentialBlob: a non-empty provider is required");
  }
  if (!input.tokens || typeof input.tokens !== "object") {
    throw new Error("encodeCredentialBlob: tokens object is required");
  }
  if (typeof input.tokens.access_token !== "string" || !input.tokens.access_token) {
    throw new Error("encodeCredentialBlob: tokens.access_token is required");
  }
  const json = JSON.stringify({
    v: CREDENTIAL_BLOB_VERSION,
    provider: input.provider.trim(),
    tokens: input.tokens,
  });
  return `${CREDENTIAL_BLOB_PREFIX}${toBase64Url(json)}`;
}

/** Decode a paste-blob; throws a descriptive error on malformed/tampered input. */
export function decodeCredentialBlob(blob: string): CredentialBlob {
  if (typeof blob !== "string" || !blob.startsWith(CREDENTIAL_BLOB_PREFIX)) {
    throw new Error(`decodeCredentialBlob: invalid format — must start with "${CREDENTIAL_BLOB_PREFIX}"`);
  }
  const body = blob.slice(CREDENTIAL_BLOB_PREFIX.length).trim();
  if (body.length > MAX_BODY_CHARS) {
    throw new Error(`decodeCredentialBlob: payload too large (>${MAX_BODY_CHARS} chars)`);
  }
  if (!/^[A-Za-z0-9_-]+$/.test(body)) {
    throw new Error("decodeCredentialBlob: invalid payload — not base64url");
  }

  let parsed: { v?: unknown; provider?: unknown; tokens?: unknown };
  try {
    parsed = JSON.parse(fromBase64Url(body));
  } catch {
    throw new Error("decodeCredentialBlob: invalid payload — could not parse JSON");
  }

  if (parsed.v !== CREDENTIAL_BLOB_VERSION) {
    throw new Error(`decodeCredentialBlob: unsupported blob version ${String(parsed.v)} (expected ${CREDENTIAL_BLOB_VERSION})`);
  }
  if (typeof parsed.provider !== "string" || !parsed.provider.trim()) {
    throw new Error("decodeCredentialBlob: invalid payload — missing provider");
  }
  const tokens = parsed.tokens;
  if (!tokens || typeof tokens !== "object" || Array.isArray(tokens)) {
    throw new Error("decodeCredentialBlob: invalid payload — missing tokens");
  }
  const rec = tokens as Record<string, unknown>;
  if (typeof rec.access_token !== "string" || !rec.access_token) {
    throw new Error("decodeCredentialBlob: invalid payload — missing access_token");
  }

  return { provider: parsed.provider.trim(), tokens: rec };
}
