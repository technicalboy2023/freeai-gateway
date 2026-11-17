import { describe, expect, it } from "vitest";
import { getAdapter } from "../src/oauth/engine";
import type { RawTokens } from "../src/oauth/types";

describe("trae adapter", () => {
  const trae = getAdapter("trae");

  it("is registered as a paste adapter", () => {
    expect(trae).not.toBeNull();
    expect(trae?.flowMode).toBe("paste");
    expect(trae?.prefix).toBe("trae");
  });

  it("importToken strips a pasted Bearer prefix and whitespace (header-copy hardening)", async () => {
    const out = await trae!.importToken!({ access_token: "Bearer eyJabc.def.ghi" });
    expect(out).toEqual({ access_token: "eyJabc.def.ghi" });
    const lower = await trae!.importToken!({ access_token: "bearer eyJabc" });
    expect(lower.access_token).toBe("eyJabc");
    const padded = await trae!.importToken!({ access_token: "  eyJabc\n" });
    expect(padded.access_token).toBe("eyJabc");
  });

  it("importToken rejects a token that is empty after normalization", async () => {
    await expect(trae!.importToken!({ access_token: "   " })).rejects.toThrow(/empty/i);
    await expect(trae!.importToken!({ access_token: "Bearer " })).rejects.toThrow(/empty/i);
  });

  it("maps snake_case payload fields; 14-day default expiry; constants pinned", () => {
    if (!trae) return;
    const mapped = trae.mapTokens({ access_token: "jwt", web_id: "w1" } as RawTokens);
    expect(mapped.accessToken).toBe("jwt");
    expect(mapped.refreshToken).toBeNull();
    expect(mapped.expiresIn).toBe(14 * 86400);
    expect(mapped.meta).toMatchObject({
      webId: "w1",
      bizUserId: "",
      userUniqueId: "",
      scope: "marscode-us",
      tenant: "marscode",
      region: "US-East",
      aiRegion: "",
      appLanguage: "en",
      appVersion: "1.0.0.1229",
      userRegion: "US",
      userTimezone: "",
      userIdentity: "Free",
      authMethod: "imported",
    });
  });

  it("camelCase fields + explicit expiresIn win over defaults", () => {
    if (!trae) return;
    const mapped = trae.mapTokens({
      accessToken: "camel-at",
      refreshToken: "rt-1",
      expiresIn: 999,
      webId: "cw",
      bizUserId: "b1",
      userUniqueId: "u1",
      aiRegion: "EU-West",
      appLanguage: "zh",
      appVersion: "9.9.9",
      userRegion: "CN",
      userTimezone: "Asia/Shanghai",
      userIdentity: "Pro",
    } as RawTokens);
    expect(mapped.accessToken).toBe("camel-at");
    expect(mapped.refreshToken).toBe("rt-1");
    expect(mapped.expiresIn).toBe(999);
    expect(mapped.meta).toMatchObject({
      webId: "cw",
      bizUserId: "b1",
      userUniqueId: "u1",
      aiRegion: "EU-West",
      appLanguage: "zh",
      appVersion: "9.9.9",
      userRegion: "CN",
      userTimezone: "Asia/Shanghai",
      userIdentity: "Pro",
    });
  });

  it("aiRegion falls back to snake ai_region then region", () => {
    if (!trae) return;
    expect(trae.mapTokens({ ai_region: "eu1" }).meta!.aiRegion).toBe("eu1");
    expect(trae.mapTokens({ region: "r9" }).meta!.aiRegion).toBe("r9");
  });
});

describe("devin-desktop adapter", () => {
  const devin = getAdapter("devin-desktop");

  it("is registered as a paste adapter", () => {
    expect(devin).not.toBeNull();
    expect(devin?.flowMode).toBe("paste");
    expect(devin?.prefix).toBe("devin-desktop");
  });

  it("bare token (>=16 chars) gets exactly one devin-session-token$ prefix", async () => {
    if (!devin?.importToken) return;
    const out = await devin.importToken({ access_token: "abcd1234abcd1234" });
    expect(out).toEqual({ access_token: "devin-session-token$abcd1234abcd1234" });
  });

  it("already-prefixed token stays single-prefixed", async () => {
    if (!devin?.importToken) return;
    const out = await devin.importToken({
      access_token: "devin-session-token$abcd1234abcd1234",
    });
    expect(out).toEqual({ access_token: "devin-session-token$abcd1234abcd1234" });
  });

  it("token shorter than 16 chars → 'Token is too short'", async () => {
    if (!devin?.importToken) return;
    await expect(devin.importToken({ access_token: "short" })).rejects.toThrow("Token is too short");
  });

  it("empty/missing token → 'Token is empty'", async () => {
    if (!devin?.importToken) return;
    await expect(devin.importToken({ access_token: "   " })).rejects.toThrow("Token is empty");
    await expect(devin.importToken({})).rejects.toThrow("Token is empty");
  });

  it("mapTokens: accessToken passthrough, no refresh, no expiry", () => {
    if (!devin) return;
    const mapped = devin.mapTokens({ access_token: "devin-session-token$x" });
    expect(mapped.accessToken).toBe("devin-session-token$x");
    expect(mapped.refreshToken).toBeNull();
    expect(mapped.expiresIn).toBeNull();
  });
});
