/**
 * PKCE (RFC 7636) + OAuth state generation via Web Crypto.
 * Verifier/state are base64url (URL-safe, no padding) so they survive URLs
 * and form bodies unencoded.
 */

function toBase64Url(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** SHA-256 of a verifier, base64url — the S256 code_challenge (RFC 7636 §4.2). */
export async function deriveChallenge(verifier: string): Promise<string> {
  const digest = new Uint8Array(
    await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier) as BufferSource),
  );
  return toBase64Url(digest);
}

export interface Pkce {
  codeVerifier: string;
  codeChallenge: string;
  state: string;
}

/** Random verifier (default 32 bytes → 43 base64url chars) + S256 challenge + state. */
export async function generatePkce(verifierBytes = 32): Promise<Pkce> {
  const verifierBytesArr = crypto.getRandomValues(new Uint8Array(verifierBytes));
  const codeVerifier = toBase64Url(verifierBytesArr);
  const codeChallenge = await deriveChallenge(codeVerifier);
  const state = toBase64Url(crypto.getRandomValues(new Uint8Array(16)));
  return { codeVerifier, codeChallenge, state };
}
