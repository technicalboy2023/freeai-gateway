import { describe, expect, it } from "vitest";
import { decodeCredentialBlob, encodeCredentialBlob } from "../src/oauth/blob";

const TOKENS = {
  access_token: "sk-at-123",
  refresh_token: "sk-rt-456",
  expires_in: 3600,
};

function oversizedBlob(): string {
  // >16384-char base64url body with a valid access_token payload
  const tokens: Record<string, unknown> = { access_token: "x" };
  tokens.pad = "y".repeat(20000);
  return encodeCredentialBlob({ provider: "trae", tokens });
}

describe("paste-blob codec", () => {
  it("roundtrips encode/decode", () => {
    const blob = encodeCredentialBlob({ provider: "trae", tokens: TOKENS });
    expect(blob.startsWith("freeai-cred-v1.")).toBe(true);
    const decoded = decodeCredentialBlob(blob);
    expect(decoded.provider).toBe("trae");
    expect(decoded.tokens).toEqual(TOKENS);
  });

  it("rejects a wrong prefix", () => {
    expect(() => decodeCredentialBlob("omniroute-cred-v1.abc")).toThrow();
    expect(() => decodeCredentialBlob("freeai-cred-v2.abc")).toThrow();
    expect(() => decodeCredentialBlob("")).toThrow();
  });

  it("rejects a non-base64url body", () => {
    expect(() => decodeCredentialBlob("freeai-cred-v1.!!!")).toThrow();
    expect(() => decodeCredentialBlob("freeai-cred-v1.not base64 url")).toThrow();
  });

  it("rejects malformed JSON payload", () => {
    // base64url of "not json"
    const body = btoa("not json").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    expect(() => decodeCredentialBlob(`freeai-cred-v1.${body}`)).toThrow();
  });

  it("rejects a wrong version", () => {
    const body = btoa(JSON.stringify({ v: 2, provider: "trae", tokens: TOKENS }))
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");
    expect(() => decodeCredentialBlob(`freeai-cred-v1.${body}`)).toThrow(/version/);
  });

  it("rejects a missing provider", () => {
    expect(() => encodeCredentialBlob({ provider: "  ", tokens: TOKENS })).toThrow();
    const body = btoa(JSON.stringify({ v: 1, tokens: TOKENS }))
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");
    expect(() => decodeCredentialBlob(`freeai-cred-v1.${body}`)).toThrow();
  });

  it("rejects tokens without an access_token", () => {
    expect(() => encodeCredentialBlob({ provider: "trae", tokens: { foo: 1 } })).toThrow();
    const body = btoa(JSON.stringify({ v: 1, provider: "trae", tokens: { foo: 1 } }))
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");
    expect(() => decodeCredentialBlob(`freeai-cred-v1.${body}`)).toThrow();
  });

  it("rejects an oversized body", () => {
    expect(() => decodeCredentialBlob(oversizedBlob())).toThrow();
  });

  it("body survives shell/URL copy-paste characters", () => {
    const blob = encodeCredentialBlob({ provider: "trae", tokens: TOKENS });
    expect(blob).toMatch(/^[A-Za-z0-9_.-]+$/);
    expect(blob.includes("+")).toBe(false);
    expect(blob.includes("/")).toBe(false);
    expect(blob.includes("=")).toBe(false);
  });
});
