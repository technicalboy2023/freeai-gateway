import { describe, expect, it } from "vitest";
import { decryptToken, encryptToken, importAesKey } from "../src/oauth/crypto";
import type { Env } from "../src/env";

/** base64url of raw bytes (test helper). */
function b64urlOfBytes(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

const KEY = b64urlOfBytes(new Uint8Array(32).fill(0x41)); // 32×0x41
const OTHER_KEY = b64urlOfBytes(new Uint8Array(32).fill(0x42));

describe("oauth token crypto", () => {
  it("roundtrips encrypt/decrypt", async () => {
    const key = await importAesKey({ OAUTH_ENCRYPTION_KEY: KEY } as Env);
    expect(key).not.toBeNull();
    const blob = await encryptToken(key!, "sk-secret-token");
    expect(await decryptToken(key!, blob)).toBe("sk-secret-token");
  });

  it("produces a fresh IV per call", async () => {
    const key = (await importAesKey({ OAUTH_ENCRYPTION_KEY: KEY } as Env))!;
    const a = await encryptToken(key, "t");
    const b = await encryptToken(key, "t");
    expect(Array.from(a.slice(0, 12))).not.toEqual(Array.from(b.slice(0, 12)));
    expect(a.length).toBe(b.length);
  });

  it("wrong key fails to decrypt (does not throw a plaintext leak)", async () => {
    const k1 = (await importAesKey({ OAUTH_ENCRYPTION_KEY: KEY } as Env))!;
    const blob = await encryptToken(k1, "sk-secret");
    const k2 = (await importAesKey({ OAUTH_ENCRYPTION_KEY: OTHER_KEY } as Env))!;
    await expect(decryptToken(k2, blob)).rejects.toThrow();
  });

  it("missing / wrong-length secret returns null key", async () => {
    expect(await importAesKey({} as Env)).toBeNull();
    expect(
      await importAesKey({ OAUTH_ENCRYPTION_KEY: b64urlOfBytes(new Uint8Array(16).fill(0x41)) } as Env),
    ).toBeNull();
  });

  it("ciphertext does not contain the plaintext", async () => {
    const key = (await importAesKey({ OAUTH_ENCRYPTION_KEY: KEY } as Env))!;
    const blob = await encryptToken(key, "sk-plain-visible-token");
    const text = new TextDecoder().decode(blob);
    expect(text.includes("sk-plain-visible-token")).toBe(false);
  });
});
