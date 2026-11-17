import { describe, expect, it } from "vitest";
import { deriveChallenge, generatePkce } from "../src/oauth/pkce";

describe("oauth pkce", () => {
  it("matches the RFC 7636 S256 vector", async () => {
    const codeChallenge = await deriveChallenge(
      "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
    );
    expect(codeChallenge).toBe("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
  });

  it("generates url-safe verifier/state of expected lengths", async () => {
    const p = await generatePkce(32);
    expect(p.codeVerifier).toMatch(/^[A-Za-z0-9_-]{43}$/); // 32 bytes → 43 base64url chars
    expect(p.state.length).toBeGreaterThanOrEqual(16);
    expect(p.codeChallenge).toMatch(/^[A-Za-z0-9_-]+$/);
  });

  it("challenge derives from the generated verifier itself", async () => {
    const p = await generatePkce(32);
    const again = await deriveChallenge(p.codeVerifier);
    expect(again).toBe(p.codeChallenge);
  });

  it("supports larger verifiers (96 bytes, devin-style)", async () => {
    const p = await generatePkce(96);
    expect(p.codeVerifier).toMatch(/^[A-Za-z0-9_-]{128}$/);
  });

  it("generates a distinct verifier per call", async () => {
    const a = await generatePkce(32);
    const b = await generatePkce(32);
    expect(a.codeVerifier).not.toBe(b.codeVerifier);
    expect(a.state).not.toBe(b.state);
  });
});
