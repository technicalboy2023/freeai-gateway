import type { Env } from "../env";

/**
 * AES-GCM encryption for OAuth tokens at rest in D1.
 *
 * Key material comes from the OAUTH_ENCRYPTION_KEY secret: base64url of
 * exactly 32 decoded bytes. Ciphertext format: `<12-byte random IV>‖<AES-GCM
 * ciphertext>` — a fresh IV per call, so identical tokens never produce
 * identical BLOBs.
 */

const IV_BYTES = 12;
const KEY_BYTES = 32;

function base64UrlDecode(value: string): Uint8Array | null {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = normalized + "=".repeat((4 - (normalized.length % 4)) % 4);
  try {
    const bin = atob(padded);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  } catch {
    return null;
  }
}

/** Import the configured secret as an AES-GCM key, or null when unusable. */
export async function importAesKey(env: Env): Promise<CryptoKey | null> {
  const secret = env.OAUTH_ENCRYPTION_KEY;
  if (typeof secret !== "string" || !secret.trim()) return null;
  const raw = base64UrlDecode(secret);
  if (!raw || raw.length !== KEY_BYTES) return null;
  return crypto.subtle.importKey("raw", raw as BufferSource, { name: "AES-GCM" }, false, [
    "encrypt",
    "decrypt",
  ]);
}

/** Encrypt plaintext; returns `iv ‖ ciphertext`. */
export async function encryptToken(key: CryptoKey, plaintext: string): Promise<Uint8Array> {
  const iv = crypto.getRandomValues(new Uint8Array(IV_BYTES));
  const params = { name: "AES-GCM", iv: iv as BufferSource };
  const cipher = new Uint8Array(
    await crypto.subtle.encrypt(params, key, new TextEncoder().encode(plaintext) as BufferSource),
  );
  const out = new Uint8Array(IV_BYTES + cipher.length);
  out.set(iv, 0);
  out.set(cipher, IV_BYTES);
  return out;
}

/** Decrypt `iv ‖ ciphertext`; throws on wrong key, tamper, or bad shape. */
export async function decryptToken(key: CryptoKey, blob: Uint8Array): Promise<string> {
  if (blob.length <= IV_BYTES) throw new Error("ciphertext too short");
  const iv = blob.slice(0, IV_BYTES);
  const cipher = blob.slice(IV_BYTES);
  const plain = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: iv as BufferSource },
    key,
    cipher as BufferSource,
  );
  return new TextDecoder().decode(plain);
}
